//! Bounded range windows; only a verified contiguous prefix reaches durable storage.
use super::*;
use tokio::task::JoinSet;

pub(super) const RANGE_BYTES: u64 = 256 * 1024;

pub(super) struct Plan {
    pub client: Client,
    pub url: Url,
    pub allow_http: bool,
    pub connections: u8,
    pub checkpoint_bytes: u64,
    pub pacing: TrafficControl,
}

#[derive(Clone)]
struct Fetch {
    client: Client,
    url: Url,
    allow_http: bool,
    total: u64,
    etag: String,
    fingerprint: [u8; 32],
    pacing: TrafficControl,
}

impl Fetch {
    async fn range(
        self,
        start: u64,
        end: u64,
        mut cancel: watch::Receiver<bool>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let mut response = request(
            &self.client,
            self.url,
            Some((start, end, &self.etag)),
            self.allow_http,
            &mut cancel,
        )
        .await?;
        if !matches!(response.status().as_u16(), 200 | 206) {
            if response.headers().contains_key(header::RETRY_AFTER) {
                return Err(Error::ServerBackoff(response.status().as_u16()));
            }
            return Err(Error::HttpStatus(response.status().as_u16()));
        }
        validate_representation(response.headers())?;
        if url_fingerprint(response.url().as_str()) != self.fingerprint {
            return Err(Error::RepresentationChanged);
        }
        if !matches!(field(response.headers(), header::ETAG), Field::Single(v) if v == self.etag.as_bytes())
        {
            return Err(Error::RepresentationChanged);
        }
        if response.status().as_u16() == 200 {
            if length(response.headers())? != self.total
                || response.headers().contains_key(header::CONTENT_RANGE)
            {
                return Err(Error::RepresentationChanged);
            }
            return Ok(None);
        }
        let tag = StrongEtag::parse(self.etag.as_bytes()).map_err(|_| Error::ResumeUnsupported)?;
        let expected =
            ResumeRequest::new(start, end, self.total, tag).map_err(|_| Error::ResumeRejected)?;
        let headers = ResponseHeaders {
            content_range: field(response.headers(), header::CONTENT_RANGE),
            content_length: field(response.headers(), header::CONTENT_LENGTH),
            etag: field(response.headers(), header::ETAG),
            content_encoding: field(response.headers(), header::CONTENT_ENCODING),
        };
        if !matches!(
            resume_policy::evaluate(expected, response.status().as_u16(), headers),
            Decision::ReadRange(_)
        ) {
            return Err(Error::ResumeRejected);
        }
        let mut bytes = Vec::with_capacity((end - start) as usize);
        loop {
            let chunk = tokio::select! {
                biased;
                _ = cancelled(&mut cancel) => return Err(Error::Cancelled),
                result = tokio::time::timeout(Duration::from_secs(30), response.chunk()) =>
                    result.map_err(|_| Error::Network)?.map_err(|_| Error::Network)?,
            };
            let Some(chunk) = chunk else { break };
            if chunk.len() as u64 > end - start - bytes.len() as u64 {
                return Err(Error::BodyLength);
            }
            for slice in chunk.chunks(self.pacing.slice_bytes()) {
                self.pacing.consume(slice.len() as u32, &mut cancel).await?;
                bytes.extend_from_slice(slice);
            }
        }
        if bytes.len() as u64 != end - start {
            return Err(Error::BodyLength);
        }
        Ok(Some(bytes))
    }
}

async fn append(
    mut store: Store,
    bytes: Vec<u8>,
    threshold: u64,
    cancel: &watch::Receiver<bool>,
    callback: &impl Fn(u64),
) -> Result<Store, Error> {
    if is_cancelled(cancel) {
        let committed = disk(move || {
            store.checkpoint()?;
            Ok(store.committed_len())
        })
        .await?;
        callback(committed);
        return Err(Error::Cancelled);
    }
    store = disk(move || {
        store.append(&bytes)?;
        if store.len() - store.committed_len() >= threshold {
            store.checkpoint()?;
        }
        Ok(store)
    })
    .await?;
    if store.len() == store.committed_len() {
        callback(store.committed_len());
    }
    Ok(store)
}

pub(super) async fn transfer(
    plan: Plan,
    mut store: Store,
    initial_response: &mut Option<Response>,
    cancel: &mut watch::Receiver<bool>,
    callback: &impl Fn(u64),
) -> Result<Store, Error> {
    let fetch = Fetch {
        client: plan.client,
        url: plan.url,
        allow_http: plan.allow_http,
        total: store.identity().total,
        etag: store
            .identity()
            .strong_etag
            .clone()
            .ok_or(Error::ResumeUnsupported)?,
        fingerprint: store.identity().final_url_fingerprint,
        pacing: plan.pacing,
    };
    let mut offset = store.len();
    let end = offset + RANGE_BYTES.min(fetch.total - offset);
    // Keep the validated original stream available until real range support is proven.
    // A 200 response is never appended as range data.
    let Some(first) = fetch.clone().range(offset, end, cancel.clone()).await? else {
        return Ok(store);
    };
    drop(initial_response.take());
    store = append(store, first, plan.checkpoint_bytes, cancel, callback).await?;
    offset = end;
    while offset < fetch.total {
        let mut workers = JoinSet::new();
        for index in 0..plan.connections {
            if offset == fetch.total {
                break;
            }
            let end = offset + RANGE_BYTES.min(fetch.total - offset);
            let task = fetch.clone();
            let receiver = cancel.clone();
            let start = offset;
            workers.spawn(async move {
                task.range(start, end, receiver)
                    .await
                    .map(|bytes| (index, bytes))
            });
            offset = end;
        }
        let mut results = Vec::with_capacity(usize::from(plan.connections));
        while let Some(result) = workers.join_next().await {
            match result {
                Ok(Ok((index, Some(bytes)))) => results.push((index, bytes)),
                failure => {
                    let error = match failure {
                        Ok(Err(error)) => error,
                        Ok(Ok(_)) => Error::ResumeRejected,
                        Err(_) => Error::WorkerFailed,
                    };
                    // Workers perform HTTP/buffer operations only, never disk operations.
                    workers.abort_all();
                    while workers.join_next().await.is_some() {}
                    let committed = disk(move || {
                        store.checkpoint()?;
                        Ok(store.committed_len())
                    })
                    .await?;
                    callback(committed);
                    return Err(error);
                }
            }
        }
        results.sort_unstable_by_key(|(index, _)| *index);
        for (_, bytes) in results {
            store = append(store, bytes, plan.checkpoint_bytes, cancel, callback).await?;
        }
    }
    Ok(store)
}
