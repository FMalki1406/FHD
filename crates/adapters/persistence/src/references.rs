//! What each admitted job points at. A link the caller marked sensitive is never
//! written: the row proves the source existed, and a later run has to be told the
//! link again rather than fetching from a credential left on disk.
use super::{app_error, PersistenceError, Result, SqliteRepository};
use fhd_app::{AppError, CommitError, PortFuture, ReferenceStore, SourceReference};
use fhd_domain::{DestinationRef, SourceRef};
use std::path::PathBuf;

/// A reference is a digest, so it uses the whole u64 range; SQLite integers are
/// signed. The bit pattern is kept exactly and read back the same way, rather than
/// refusing every identifier above i64::MAX.
fn stored_id(value: u64) -> i64 {
    i64::from_ne_bytes(value.to_ne_bytes())
}
fn loaded_id(value: i64) -> u64 {
    u64::from_ne_bytes(value.to_ne_bytes())
}

impl SqliteRepository {
    async fn record_reference(
        &self,
        source: SourceRef,
        reference: SourceReference,
        destination: DestinationRef,
        path: PathBuf,
    ) -> Result<()> {
        self.run(move |inner| {
            let source_id = stored_id(source.get());
            let destination_id = stored_id(destination.get());
            let path = path.to_str().ok_or(PersistenceError::Corrupt)?.to_owned();
            let transaction = inner.db.transaction()?;
            // Recording the same request twice is one row: a rerun is not a change.
            transaction.execute(
                "INSERT INTO sources(source_id,url,allow_http,sensitive) VALUES(?1,?2,?3,?4)
                 ON CONFLICT(source_id) DO UPDATE SET url=excluded.url,
                 allow_http=excluded.allow_http, sensitive=excluded.sensitive",
                rusqlite::params![
                    source_id,
                    reference.url(),
                    i64::from(reference.allow_http()),
                    i64::from(reference.is_sensitive()),
                ],
            )?;
            transaction.execute(
                "INSERT INTO destinations(destination_id,path) VALUES(?1,?2)
                 ON CONFLICT(destination_id) DO UPDATE SET path=excluded.path",
                rusqlite::params![destination_id, path],
            )?;
            transaction.commit()?;
            Ok(())
        })
        .await
    }

    async fn stored_sources(&self) -> Result<Vec<(SourceRef, SourceReference)>> {
        self.run(move |inner| {
            let mut statement = inner
                .db
                .prepare("SELECT source_id,url,allow_http,sensitive FROM sources")?;
            let rows = statement.query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)? != 0,
                    row.get::<_, i64>(3)? != 0,
                ))
            })?;
            let mut sources = Vec::new();
            for row in rows {
                let (id, url, allow_http, sensitive) = row?;
                let source =
                    SourceRef::new(loaded_id(id)).map_err(|_| PersistenceError::Corrupt)?;
                let reference = match (url, sensitive) {
                    (_, true) | (None, _) => SourceReference::sensitive(allow_http),
                    (Some(url), false) => SourceReference::new(url, allow_http)
                        .map_err(|_| PersistenceError::Corrupt)?,
                };
                sources.push((source, reference));
            }
            Ok(sources)
        })
        .await
    }

    async fn stored_destinations(&self) -> Result<Vec<(DestinationRef, PathBuf)>> {
        self.run(move |inner| {
            let mut statement = inner
                .db
                .prepare("SELECT destination_id,path FROM destinations")?;
            let rows = statement.query_map([], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut destinations = Vec::new();
            for row in rows {
                let (id, path) = row?;
                let destination =
                    DestinationRef::new(loaded_id(id)).map_err(|_| PersistenceError::Corrupt)?;
                destinations.push((destination, PathBuf::from(path)));
            }
            Ok(destinations)
        })
        .await
    }
}

impl ReferenceStore for SqliteRepository {
    fn record(
        &self,
        source: SourceRef,
        reference: SourceReference,
        destination: DestinationRef,
        path: PathBuf,
    ) -> PortFuture<'_, std::result::Result<(), CommitError>> {
        Box::pin(async move {
            self.record_reference(source, reference, destination, path)
                .await
                .map_err(|error| match error {
                    PersistenceError::Unavailable => CommitError::Unavailable,
                    PersistenceError::Capacity => CommitError::Capacity,
                    _ => CommitError::Conflict,
                })
        })
    }
    fn sources(
        &self,
    ) -> PortFuture<'_, std::result::Result<Vec<(SourceRef, SourceReference)>, AppError>> {
        Box::pin(async move { self.stored_sources().await.map_err(app_error) })
    }
    fn destinations(
        &self,
    ) -> PortFuture<'_, std::result::Result<Vec<(DestinationRef, PathBuf)>, AppError>> {
        Box::pin(async move { self.stored_destinations().await.map_err(app_error) })
    }
}
