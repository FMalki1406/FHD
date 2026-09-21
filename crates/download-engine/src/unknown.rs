//! Framed streaming without Content-Length; unfinished streams never resume.
use crate::{cancelled, disk, field, is_cancelled, Error, Options, Outcome, TrafficControl};
use reqwest::{header, Response, Url, Version};
use resume_policy::{Field, StrongEtag};
use std::time::Duration;
use tokio::sync::watch;
use transfer_store::{url_fingerprint, Identity, Store};

fn validate_framing(response: &Response) -> Result<(), Error> {
    if response.headers().contains_key(header::CONTENT_LENGTH) {
        return Err(Error::InvalidHeaders);
    }
    match (
        response.version(),
        field(response.headers(), header::TRANSFER_ENCODING),
    ) {
        (Version::HTTP_11, Field::Single(value)) if value.eq_ignore_ascii_case(b"chunked") => {
            Ok(())
        }
        (Version::HTTP_2, Field::Missing) => Ok(()),
        // Close-delimited HTTP/1.x cannot distinguish success from an interrupted
        // stream. Requiring chunk framing avoids publishing a silent truncation.
        _ => Err(Error::InvalidHeaders),
    }
}

async fn checkpoint(store: Store, on_checkpoint: &impl Fn(u64)) -> Result<(), Error> {
    let committed = disk(move || {
        let mut store = store;
        store.checkpoint()?;
        Ok(store.committed_len())
    })
    .await?;
    on_checkpoint(committed);
    Ok(())
}

pub(super) async fn transfer(
    mut response: Response,
    options: Options,
    original: Url,
    pacing: TrafficControl,
    mut cancel: watch::Receiver<bool>,
    on_checkpoint: impl Fn(u64),
) -> Result<Outcome, Error> {
    validate_framing(&response)?;
    let strong_etag = match field(response.headers(), header::ETAG) {
        Field::Missing => None,
        Field::Repeated => return Err(Error::InvalidHeaders),
        Field::Single(value) => {
            if value.len() > resume_policy::MAX_FIELD_BYTES {
                return Err(Error::InvalidHeaders);
            }
            if StrongEtag::parse(value).is_ok() {
                Some(
                    std::str::from_utf8(value)
                        .map_err(|_| Error::InvalidHeaders)?
                        .to_owned(),
                )
            } else {
                None
            }
        }
    };
    if is_cancelled(&cancel) {
        return Err(Error::Cancelled);
    }
    let identity = Identity {
        original_url_fingerprint: url_fingerprint(original.as_str()),
        final_url_fingerprint: url_fingerprint(response.url().as_str()),
        strong_etag,
        total: options.max_download_bytes,
        expected_sha256: options.expected_sha256,
    };
    let directory = options.job_dir;
    let parent = directory.parent().ok_or(Error::InvalidOptions)?;
    crate::files::before_transfer(
        std::path::absolute(parent).map_err(|e| Error::StorageIo(e.kind()))?,
        0,
    )
    .await?;
    let output = options.output_name;
    let mut store = disk(move || Store::create_unknown(&directory, identity, &output)).await?;
    loop {
        let next = tokio::select! {
            biased;
            _ = cancelled(&mut cancel) => Err(Error::Cancelled),
            next = tokio::time::timeout(Duration::from_secs(30), response.chunk()) =>
                next.map_err(|_| Error::Network).and_then(|result| result.map_err(|_| Error::Network)),
        };
        let chunk = match next {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                checkpoint(store, &on_checkpoint).await?;
                return Err(error);
            }
        };
        if store
            .len()
            .checked_add(chunk.len() as u64)
            .is_none_or(|size| size > options.max_download_bytes)
        {
            checkpoint(store, &on_checkpoint).await?;
            return Err(Error::SizeLimit);
        }
        for bytes in chunk.chunks(pacing.slice_bytes()) {
            if let Some(error) = pacing
                .consume(bytes.len() as u32, &mut cancel)
                .await
                .err()
                .or_else(|| is_cancelled(&cancel).then_some(Error::Cancelled))
            {
                checkpoint(store, &on_checkpoint).await?;
                return Err(error);
            }
            let bytes = bytes.to_vec();
            let threshold = options.checkpoint_bytes;
            store = disk(move || {
                store.append(&bytes)?;
                if store.len() - store.committed_len() >= threshold {
                    store.checkpoint()?;
                }
                Ok(store)
            })
            .await?;
            if store.len() == store.committed_len() {
                on_checkpoint(store.committed_len());
            }
        }
    }
    if is_cancelled(&cancel) {
        checkpoint(store, &on_checkpoint).await?;
        return Err(Error::Cancelled);
    }
    // reqwest has consumed the protocol's clean ending, including HTTP/1 chunk
    // termination. A socket EOF with incomplete framing returns an error above.
    let bytes = store.len();
    let path = disk(move || {
        store.mark_unknown_transfer_complete()?;
        store.finalize()
    })
    .await?;
    on_checkpoint(bytes);
    Ok(Outcome {
        bytes,
        resumed_from: 0,
        path,
    })
}
