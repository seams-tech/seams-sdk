use std::{cell::RefCell, future::Future, rc::Rc};

use serde::{de::DeserializeOwned, Deserialize};
use worker::{D1DatabaseSession, D1SessionConstraint, D1Type, Env};

use super::{PairYaoSessionRecordV1, YAO_RUNNING_LIFETIME_MS};

const ROLE_PRIVATE_D1_BINDING: &str = "DERIVER_ROLE_PRIVATE_DB";
const LOAD_PAIR_SQL: &str =
    "SELECT record_json, revision FROM yao_pair_sessions WHERE session_hex = ?1";
const INSERT_PAIR_SQL: &str = "INSERT INTO yao_pair_sessions \
    (session_hex, pair_digest_hex, lifecycle, record_json, revision, expires_at_ms, updated_at_ms) \
    VALUES (?1, ?2, ?3, ?4, 1, ?5, ?6) ON CONFLICT(session_hex) DO NOTHING";
const UPDATE_PAIR_SQL: &str = "UPDATE yao_pair_sessions SET pair_digest_hex = ?2, \
    lifecycle = ?3, record_json = ?4, revision = revision + 1, expires_at_ms = ?5, \
    updated_at_ms = ?6 WHERE session_hex = ?1 AND revision = ?7";

#[derive(Deserialize)]
struct PairRowV1 {
    record_json: String,
    revision: i64,
}

#[derive(Clone)]
struct CachedPairV1 {
    record_json: String,
    revision: i64,
}

#[derive(Clone)]
struct PendingPairV1 {
    record_json: String,
    pair_digest_hex: String,
    lifecycle: &'static str,
    expires_at_ms: u64,
    updated_at_ms: u64,
}

/// One request-scoped, primary-anchored view of a role-private Yao session row.
pub(super) struct RolePairD1StorageV1 {
    session: D1DatabaseSession,
    session_hex: String,
    cached: RefCell<Option<Option<CachedPairV1>>>,
}

impl RolePairD1StorageV1 {
    pub(super) fn from_env(env: &Env, session_id: [u8; 32]) -> worker::Result<Self> {
        let database = env.d1(ROLE_PRIVATE_D1_BINDING).map_err(|error| {
            worker::Error::RustError(format!(
                "role-private D1 binding {ROLE_PRIVATE_D1_BINDING} is unavailable: {error}"
            ))
        })?;
        let session = database
            .with_session_constraint(D1SessionConstraint::FirstPrimary)
            .map_err(|error| {
                worker::Error::RustError(format!(
                    "role-private D1 primary session could not be created: {error}"
                ))
            })?;
        Ok(Self {
            session,
            session_hex: encode_hex(session_id),
            cached: RefCell::new(None),
        })
    }

    pub(super) async fn get<T: DeserializeOwned>(&self, _key: &str) -> worker::Result<Option<T>> {
        let row = self.load().await?;
        row.map(|row| {
            serde_json::from_str(&row.record_json).map_err(|error| {
                worker::Error::RustError(format!(
                    "role-private D1 Yao record is malformed: {error}"
                ))
            })
        })
        .transpose()
    }

    pub(super) async fn put(
        &self,
        _key: &str,
        value: PairYaoSessionRecordV1,
    ) -> worker::Result<()> {
        let pending = pending_pair(value)?;
        self.persist(pending).await
    }

    pub(super) async fn transaction<F, Fut>(&self, closure: F) -> worker::Result<()>
    where
        F: FnOnce(RolePairD1TransactionV1) -> Fut,
        Fut: Future<Output = worker::Result<()>>,
    {
        let initial = self.load().await?;
        let pending = Rc::new(RefCell::new(None));
        closure(RolePairD1TransactionV1 {
            initial: initial.clone(),
            pending: Rc::clone(&pending),
        })
        .await?;
        let pending = pending.borrow_mut().take();
        if let Some(pending) = pending {
            self.persist_from(initial, pending).await?;
        }
        Ok(())
    }

    async fn load(&self) -> worker::Result<Option<CachedPairV1>> {
        if let Some(cached) = self.cached.borrow().clone() {
            return Ok(cached);
        }
        let statement = self
            .session
            .prepare(LOAD_PAIR_SQL)
            .bind_refs([D1Type::Text(self.session_hex.as_str())].iter())?;
        let row = statement
            .first::<PairRowV1>(None)
            .await?
            .map(|row| CachedPairV1 {
                record_json: row.record_json,
                revision: row.revision,
            });
        self.cached.replace(Some(row.clone()));
        Ok(row)
    }

    async fn persist(&self, pending: PendingPairV1) -> worker::Result<()> {
        let initial = self.load().await?;
        self.persist_from(initial, pending).await
    }

    async fn persist_from(
        &self,
        initial: Option<CachedPairV1>,
        pending: PendingPairV1,
    ) -> worker::Result<()> {
        let expires_at_ms = pending.expires_at_ms.to_string();
        let updated_at_ms = pending.updated_at_ms.to_string();
        let result = match initial {
            None => {
                self.session
                    .prepare(INSERT_PAIR_SQL)
                    .bind_refs(
                        [
                            D1Type::Text(self.session_hex.as_str()),
                            D1Type::Text(pending.pair_digest_hex.as_str()),
                            D1Type::Text(pending.lifecycle),
                            D1Type::Text(pending.record_json.as_str()),
                            D1Type::Text(expires_at_ms.as_str()),
                            D1Type::Text(updated_at_ms.as_str()),
                        ]
                        .iter(),
                    )?
                    .run()
                    .await?
            }
            Some(ref current) => {
                let revision = current.revision.to_string();
                self.session
                    .prepare(UPDATE_PAIR_SQL)
                    .bind_refs(
                        [
                            D1Type::Text(self.session_hex.as_str()),
                            D1Type::Text(pending.pair_digest_hex.as_str()),
                            D1Type::Text(pending.lifecycle),
                            D1Type::Text(pending.record_json.as_str()),
                            D1Type::Text(expires_at_ms.as_str()),
                            D1Type::Text(updated_at_ms.as_str()),
                            D1Type::Text(revision.as_str()),
                        ]
                        .iter(),
                    )?
                    .run()
                    .await?
            }
        };
        let changes = result
            .meta()?
            .and_then(|meta| meta.changes)
            .unwrap_or_default();
        if changes != 1 {
            return Err(worker::Error::RustError(
                "role-private D1 Yao lifecycle conflict".to_owned(),
            ));
        }
        let next_revision = initial
            .as_ref()
            .map_or(1, |row| row.revision.saturating_add(1));
        self.cached.replace(Some(Some(CachedPairV1 {
            record_json: pending.record_json,
            revision: next_revision,
        })));
        Ok(())
    }
}

pub(super) struct RolePairD1TransactionV1 {
    initial: Option<CachedPairV1>,
    pending: Rc<RefCell<Option<PendingPairV1>>>,
}

impl RolePairD1TransactionV1 {
    pub(super) async fn get<T: DeserializeOwned>(&self, _key: &str) -> worker::Result<T> {
        let row = self
            .initial
            .as_ref()
            .ok_or_else(|| worker::Error::JsError("No such value in storage.".to_owned()))?;
        serde_json::from_str(&row.record_json).map_err(|error| {
            worker::Error::RustError(format!("role-private D1 Yao record is malformed: {error}"))
        })
    }

    pub(super) async fn put(
        &self,
        _key: &str,
        value: PairYaoSessionRecordV1,
    ) -> worker::Result<()> {
        self.pending.replace(Some(pending_pair(value)?));
        Ok(())
    }
}

fn pending_pair(value: PairYaoSessionRecordV1) -> worker::Result<PendingPairV1> {
    let lifecycle = match &value {
        PairYaoSessionRecordV1::Prepared { .. } => "prepared",
        PairYaoSessionRecordV1::Running { .. } => "running",
        PairYaoSessionRecordV1::Completed { .. } => "completed",
        PairYaoSessionRecordV1::Burned { .. } => "burned",
        PairYaoSessionRecordV1::Expired { .. } => "expired",
    };
    let expires_at_ms = match &value {
        PairYaoSessionRecordV1::Prepared { expires_at_ms, .. } => *expires_at_ms,
        PairYaoSessionRecordV1::Running { started_at_ms, .. } => {
            started_at_ms.saturating_add(YAO_RUNNING_LIFETIME_MS)
        }
        PairYaoSessionRecordV1::Completed { .. }
        | PairYaoSessionRecordV1::Burned { .. }
        | PairYaoSessionRecordV1::Expired { .. } => 0,
    };
    let updated_at_ms = super::cloudflare_yao_now_unix_ms()?;
    Ok(PendingPairV1 {
        record_json: serde_json::to_string(&value).map_err(|error| {
            worker::Error::RustError(format!(
                "role-private D1 Yao record encoding failed: {error}"
            ))
        })?,
        pair_digest_hex: encode_hex(value.pair_digest()),
        lifecycle,
        expires_at_ms,
        updated_at_ms,
    })
}

fn encode_hex(value: [u8; 32]) -> String {
    encode_hex_slice(&value)
}

fn encode_hex_slice(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}
