//! Cursor pagination helpers shared by route modules.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use philharmonic_types::{UnixMillis, Uuid};
use serde::{Deserialize, Serialize};

/// Default number of items returned when a request omits `limit`.
pub const DEFAULT_LIMIT: u32 = 50;
/// Maximum number of items returned from one paginated request.
pub const MAX_LIMIT: u32 = 200;

/// Parsed cursor-pagination query parameters.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct PaginationParams {
    /// Opaque cursor returned by the previous page.
    pub cursor: Option<String>,
    /// Maximum items to return, clamped to the route-layer maximum.
    #[serde(default = "default_limit", deserialize_with = "deserialize_limit")]
    pub limit: u32,
}

impl Default for PaginationParams {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: DEFAULT_LIMIT,
        }
    }
}

/// Standard paginated response envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PaginatedResponse<T> {
    /// Items in this page.
    pub items: Vec<T>,
    /// Cursor for the next page, or `null` if this is the last page.
    pub next_cursor: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CursorKey {
    pub(crate) created_at: UnixMillis,
    pub(crate) id: Uuid,
}

impl CursorKey {
    pub(crate) const fn new(created_at: UnixMillis, id: Uuid) -> Self {
        Self { created_at, id }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PaginationError {
    #[error("invalid pagination cursor")]
    InvalidCursor,
    #[error("pagination limit does not fit target platform")]
    LimitConversion,
}

pub(crate) fn decode_cursor(cursor: Option<&str>) -> Result<Option<CursorKey>, PaginationError> {
    let Some(cursor) = cursor else {
        return Ok(None);
    };
    let bytes = URL_SAFE_NO_PAD
        .decode(cursor)
        .map_err(|_| PaginationError::InvalidCursor)?;
    let wire: CursorWire =
        serde_json::from_slice(&bytes).map_err(|_| PaginationError::InvalidCursor)?;
    Ok(Some(CursorKey {
        created_at: UnixMillis(wire.created_at),
        id: wire.id,
    }))
}

pub(crate) fn encode_cursor(key: CursorKey) -> Result<String, PaginationError> {
    let wire = CursorWire {
        created_at: key.created_at.as_i64(),
        id: key.id,
    };
    let bytes = serde_json::to_vec(&wire).map_err(|_| PaginationError::InvalidCursor)?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn page_size(limit: u32) -> Result<usize, PaginationError> {
    usize::try_from(limit).map_err(|_| PaginationError::LimitConversion)
}

fn default_limit() -> u32 {
    DEFAULT_LIMIT
}

fn deserialize_limit<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = Option::<u32>::deserialize(deserializer)?;
    Ok(value.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT))
}

#[derive(Deserialize, Serialize)]
struct CursorWire {
    created_at: i64,
    id: Uuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trips() {
        let key = CursorKey::new(UnixMillis(123), Uuid::new_v4());
        let encoded = encode_cursor(key).expect("cursor encodes");
        let decoded = decode_cursor(Some(&encoded))
            .expect("cursor decodes")
            .expect("cursor present");

        assert_eq!(decoded, key);
    }

    #[test]
    fn limit_defaults_and_clamps() {
        let defaulted: PaginationParams = serde_json::from_str("{}").expect("params");
        assert_eq!(defaulted.limit, DEFAULT_LIMIT);

        let clamped: PaginationParams = serde_json::from_str(r#"{"limit":999}"#).expect("params");
        assert_eq!(clamped.limit, MAX_LIMIT);

        let minimum: PaginationParams = serde_json::from_str(r#"{"limit":0}"#).expect("params");
        assert_eq!(minimum.limit, 1);
    }
}
