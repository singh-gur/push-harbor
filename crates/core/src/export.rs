//! Registration export/import (spec: docs/spec/export.md): JSON Lines, a header line then one
//! registration per line. Shared by every hosting option so their files are interchangeable.
//!
//! Exposed by the adapters as `GET /v1/admin/export` and `POST /v1/admin/import`, enabled only
//! when an admin token is configured ([`authorize_admin`]); native also has CLI subcommands.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::json;

use crate::adapter::Store;
use crate::error::Error;
use crate::model::{EndpointId, KeyId, Platform, Registration};
use crate::registration::{constant_time_eq, parse_public_key, parse_target};

pub const FORMAT: &str = "pushharbor-registrations";
pub const VERSION: u64 = 1;
/// Registrations read per store call while exporting.
const PAGE: u32 = 500;
/// Admin tokens shorter than this are refused at configuration time.
pub const MIN_ADMIN_TOKEN_LEN: usize = 32;

/// Checks `Authorization: Bearer <token>` for the admin API. No configured token: the API does
/// not exist (404). Wrong or missing token: 403.
pub fn authorize_admin(authorization: Option<&str>, token: Option<&str>) -> Result<(), Error> {
    let Some(token) = token else {
        return Err(Error::NotFound);
    };
    let given = authorization
        .and_then(|h| h.trim().strip_prefix("Bearer "))
        .unwrap_or_default()
        .trim();
    if constant_time_eq(given.as_bytes(), token.as_bytes()) {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

/// The whole export file.
// shortcut: built in memory (~200 B per registration); stream it if deployments reach millions.
pub async fn export(store: &impl Store, origin: &str, now: u64) -> Result<String, Error> {
    let mut out =
        json!({"format": FORMAT, "version": VERSION, "origin": origin, "exported_at": now})
            .to_string();
    out.push('\n');
    let mut after: Option<EndpointId> = None;
    loop {
        let page = store.list(after.as_ref(), PAGE).await?;
        for r in &page {
            let platform = match r.platform {
                Platform::Fcm => "fcm",
                Platform::Apns => "apns",
            };
            out.push_str(
                &json!({
                    "id": r.endpoint.as_str(),
                    "platform": platform,
                    "target": r.target,
                    "key_id": r.key_id.as_str(),
                    "sender_key": URL_SAFE_NO_PAD.encode(r.sender_key),
                    "created_at": r.created_at,
                })
                .to_string(),
            );
            out.push('\n');
        }
        match page.last() {
            Some(last) if page.len() == PAGE as usize => after = Some(last.endpoint.clone()),
            _ => return Ok(out),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The file is invalid; nothing was imported. `line` is 1-based.
    Invalid { line: usize, reason: &'static str },
    /// Storage failed part-way; importing the same file again is safe.
    Store(Error),
}

#[derive(Deserialize)]
struct Header {
    format: String,
    version: u64,
    origin: String,
}

#[derive(Deserialize)]
struct Line {
    id: String,
    platform: String,
    target: String,
    key_id: String,
    sender_key: String,
    created_at: u64,
}

/// Validates the whole file, then upserts every registration (same ID: replaced). Returns the
/// number of registrations imported. The file's origin must be this relay's origin.
pub async fn import(store: &impl Store, origin: &str, file: &str) -> Result<usize, ImportError> {
    let invalid = |line, reason| ImportError::Invalid { line, reason };
    let mut lines = file
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.trim()))
        .filter(|(_, l)| !l.is_empty());
    let (n, header) = lines.next().ok_or(invalid(1, "empty file"))?;
    let header: Header =
        serde_json::from_str(header).map_err(|_| invalid(n, "first line must be the header"))?;
    if header.format != FORMAT {
        return Err(invalid(n, "not a pushharbor-registrations file"));
    }
    if header.version != VERSION {
        return Err(invalid(n, "unsupported version"));
    }
    if header.origin.trim_end_matches('/') != origin {
        return Err(invalid(
            n,
            "the file was exported by a relay with another origin; endpoints would not work here",
        ));
    }

    let mut registrations = Vec::new();
    for (n, text) in lines {
        let line: Line =
            serde_json::from_str(text).map_err(|_| invalid(n, "not a registration line"))?;
        registrations.push(Registration {
            endpoint: EndpointId::parse(&line.id).ok_or(invalid(n, "invalid id"))?,
            platform: match line.platform.as_str() {
                "fcm" => Platform::Fcm,
                "apns" => Platform::Apns,
                _ => return Err(invalid(n, "invalid platform")),
            },
            target: parse_target(&line.target)
                .map_err(|_| invalid(n, "invalid target"))?
                .to_owned(),
            key_id: KeyId::parse(&line.key_id).ok_or(invalid(n, "invalid key_id"))?,
            sender_key: parse_public_key(&line.sender_key)
                .map_err(|_| invalid(n, "invalid sender_key"))?,
            created_at: line.created_at,
        });
    }
    for registration in &registrations {
        store.put(registration).await.map_err(ImportError::Store)?;
    }
    Ok(registrations.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fakes::MemoryStore;
    use crate::testkit::{ORIGIN, public, signer};

    fn registration(seed: u8) -> Registration {
        Registration {
            endpoint: EndpointId::from_random([seed; 16]),
            platform: Platform::Fcm,
            target: format!("fid-{seed}"),
            key_id: KeyId::parse("k1").unwrap(),
            sender_key: public(&signer(seed)),
            created_at: 1_700_000_000 + u64::from(seed),
        }
    }

    #[test]
    fn round_trip_through_another_store() {
        let source = MemoryStore::default();
        // More than one page.
        let all: Vec<Registration> = (0..PAGE as u16 + 7)
            .map(|i| {
                let mut r = registration((i % 200 + 1) as u8);
                let mut id = [0; 16];
                id[..2].copy_from_slice(&i.to_be_bytes());
                r.endpoint = EndpointId::from_random(id);
                r
            })
            .collect();
        for r in &all {
            pollster::block_on(source.put(r)).unwrap();
        }
        let file = pollster::block_on(export(&source, ORIGIN, 42)).unwrap();
        assert!(file.starts_with(&format!(
            r#"{{"exported_at":42,"format":"pushharbor-registrations","origin":"{ORIGIN}","version":1}}"#
        )));
        assert_eq!(file.lines().count(), all.len() + 1);

        let target = MemoryStore::default();
        assert_eq!(
            pollster::block_on(import(&target, ORIGIN, &file)),
            Ok(all.len())
        );
        for r in &all {
            assert_eq!(
                pollster::block_on(target.get(&r.endpoint))
                    .unwrap()
                    .as_ref(),
                Some(r)
            );
        }
        // Importing again replaces, it doesn't duplicate or fail.
        assert_eq!(
            pollster::block_on(import(&target, ORIGIN, &file)),
            Ok(all.len())
        );
    }

    #[test]
    fn invalid_files_import_nothing() {
        let good = pollster::block_on(async {
            let store = MemoryStore::default();
            store.put(&registration(1)).await.unwrap();
            export(&store, ORIGIN, 1).await.unwrap()
        });
        let header = good.lines().next().unwrap();
        let line = good.lines().nth(1).unwrap();
        let cases = [
            (String::new(), 1, "empty file"),
            (format!("{line}\n"), 1, "first line must be the header"),
            (
                good.replace("\"version\":1", "\"version\":2"),
                1,
                "unsupported version",
            ),
            (
                good.replace(ORIGIN, "https://other.example"),
                1,
                "the file was exported by a relay with another origin; endpoints would not work here",
            ),
            (
                format!("{header}\n{line}\nnot json\n"),
                3,
                "not a registration line",
            ),
            (
                format!("{header}\n{line}\n{}\n", line.replace("\"fcm\"", "\"gcm\"")),
                3,
                "invalid platform",
            ),
            (
                format!("{header}\n{}\n", line.replace("\"k1\"", "\"bad.key\"")),
                2,
                "invalid key_id",
            ),
        ];
        for (file, n, reason) in cases {
            let store = MemoryStore::default();
            assert_eq!(
                pollster::block_on(import(&store, ORIGIN, &file)),
                Err(ImportError::Invalid { line: n, reason }),
                "{reason}"
            );
            assert_eq!(
                pollster::block_on(store.list(None, 10)).unwrap(),
                vec![],
                "{reason}"
            );
        }
        // Unknown fields and blank lines are fine.
        let extended = good.replace("\"platform\"", "\"future\":true,\"platform\"") + "\n\n";
        assert_eq!(
            pollster::block_on(import(&MemoryStore::default(), ORIGIN, &extended)),
            Ok(1)
        );
    }

    #[test]
    fn admin_token() {
        let token = "t".repeat(MIN_ADMIN_TOKEN_LEN);
        let ok = format!("Bearer {token}");
        assert_eq!(authorize_admin(Some(&ok), Some(&token)), Ok(()));
        assert_eq!(authorize_admin(Some(&ok), None), Err(Error::NotFound));
        for bad in [
            None,
            Some("Bearer wrong"),
            Some(token.as_str()),
            Some("Basic x"),
        ] {
            assert_eq!(authorize_admin(bad, Some(&token)), Err(Error::Forbidden));
        }
    }
}
