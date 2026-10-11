//! Parsing what people type for ids, subjects, name paths, and tags.
//!
//! A SUBJECT is one argument:
//!
//! - `writ1…`: an identity, or `DIR` (an identity directory) for its id
//! - `writ1… alice devices`, `DIR alice`: a name path (SDSI compound name)
//! - `FILE`: a public key file (`writ pubkey` output, or a leaf grant's key),
//!   or an OpenSSH public key file
//! - `ssh-ed25519 AAAA… [comment]`: an OpenSSH public key, as an opaque key
//! - `(key TYPE |BASE64|)`: any opaque application key, in readable form

use crate::error::{Error, Result, err};
use crate::ident;
use libwrit::{Holder, Id, Item, NamePath, OpaqueKey, PublicKey, Subject, Tag};
use std::path::Path;
use writ_sexp::{Sexp, readable};

const SSH_PREFIXES: [&str; 4] = ["ssh-", "ecdsa-sha2-", "sk-ssh-", "sk-ecdsa-"];

/// An id: `writ1…` or an identity directory.
pub fn id(text: &str) -> Result<Id> {
    if let Some(id) = Id::parse(text) {
        return Ok(id);
    }
    if ident::is_identity_dir(Path::new(text)) {
        return Ok(ident::IdentityDir::open(text)?.id());
    }
    if text.starts_with("writ1") {
        return err(format!(
            "{text}: not a valid id (checksum or length is wrong)"
        ));
    }
    err(format!(
        "{text}: not an id (writ1…) or an identity directory"
    ))
}

/// A tag: `(zuko home)`, `zuko home`, or `()`.
pub fn tag(text: &str) -> Result<Tag> {
    Tag::parse(text).ok_or_else(|| {
        Error::Msg(format!(
            "{text:?}: not a tag; write atoms general to specific, e.g. '(ssh nas)', or '()' for everything"
        ))
    })
}

fn words(text: &str) -> Result<Vec<Vec<u8>>> {
    let sexps = readable::parse_many(text).map_err(|e| Error::Msg(format!("{text:?}: {e}")))?;
    sexps
        .into_iter()
        .map(|s| match s {
            Sexp::Atom(a) => Ok(a),
            Sexp::List(_) => err(format!("{text:?}: unexpected parenthesis")),
        })
        .collect()
}

fn utf8(bytes: &[u8]) -> Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| Error::Msg("not UTF-8".into()))
}

/// A subject (see module docs).
pub fn subject(text: &str) -> Result<Subject> {
    let trimmed = text.trim();
    if SSH_PREFIXES.iter().any(|p| trimmed.starts_with(p)) {
        return ssh_key(trimmed).map(Subject::Opaque);
    }
    if trimmed.starts_with('(') {
        let sexp = readable::parse(trimmed).map_err(|e| Error::Msg(format!("{text:?}: {e}")))?;
        return Subject::from_sexp(&sexp).map_err(|e| Error::Msg(format!("{text:?}: {e}")));
    }
    let words = words(trimmed)?;
    let Some((first, names)) = words.split_first() else {
        return err("empty subject");
    };
    let first = utf8(first)?;
    if !names.is_empty() {
        let base = id(first)?;
        return Ok(Subject::Name(NamePath {
            base,
            names: names.to_vec(),
        }));
    }
    if let Some(id) = Id::parse(first) {
        return Ok(Subject::Id(id));
    }
    let path = Path::new(first);
    if ident::is_identity_dir(path) {
        return Ok(Subject::Id(ident::IdentityDir::open(first)?.id()));
    }
    if path.is_file() {
        return key_file(first);
    }
    err(format!(
        "{first}: not an id (writ1…), an identity directory, a key file, or an OpenSSH public key"
    ))
}

/// A concrete subject for a query (not a name path).
pub fn holder(text: &str) -> Result<Holder> {
    match subject(text)? {
        Subject::Id(id) => Ok(Holder::Id(id)),
        Subject::Leaf(k) => Ok(Holder::Leaf(k)),
        Subject::Opaque(k) => Ok(Holder::Opaque(k)),
        Subject::Name(_) => err(format!(
            "{text:?} is a name path; ask who it refers to with `writ resolve`, then check them"
        )),
    }
}

/// A name path; without a leading id or directory, names start at `default`.
pub fn name_path(text: &str, default: Option<Id>) -> Result<NamePath> {
    let words = words(text)?;
    let Some((first, rest)) = words.split_first() else {
        return err("empty name path");
    };
    let first_str = utf8(first).unwrap_or_default();
    if let Some(base) = Id::parse(first_str)
        .or_else(|| ident::is_identity_dir(Path::new(first_str)).then(|| id(first_str).ok())?)
    {
        if rest.is_empty() {
            return err(format!(
                "{text:?}: a name path needs at least one name after the id"
            ));
        }
        return Ok(NamePath {
            base,
            names: rest.to_vec(),
        });
    }
    match default {
        Some(base) => Ok(NamePath { base, names: words }),
        None => err(format!(
            "{text:?}: start the name path with an id or identity directory"
        )),
    }
}

/// One name atom.
pub fn name(text: &str) -> Result<Vec<u8>> {
    match words(text)?.as_slice() {
        [one] if !one.is_empty() => Ok(one.clone()),
        _ => err(format!(
            "{text:?}: a name is a single word (quote it if it has spaces)"
        )),
    }
}

fn key_file(path: &str) -> Result<Subject> {
    let bytes = crate::fs::read_input(path, "a key file")?;
    let text = String::from_utf8_lossy(&bytes);
    if SSH_PREFIXES
        .iter()
        .any(|p| text.trim_start().starts_with(p))
    {
        let line = text.lines().next().unwrap_or_default();
        return ssh_key(line).map(Subject::Opaque);
    }
    if text.contains("WRIT-SECRET-KEY-1") || text.contains("writ-secret-key-1") {
        return err(format!(
            "{path} is a secret key; subjects are public keys (get one with `writ pubkey`)"
        ));
    }
    let items = Item::decode_bundle(&bytes).map_err(|e| Error::Msg(format!("{path}: {e}")))?;
    match items.as_slice() {
        [Item::PublicKey(PublicKey::Leaf(k))] => Ok(Subject::Leaf(k.clone())),
        [Item::PublicKey(PublicKey::Root(_))] => err(format!(
            "{path} is a root key; grant to the identity's id instead"
        )),
        _ => err(format!("{path}: expected one public key")),
    }
}

/// An OpenSSH public key line: `TYPE BASE64 [COMMENT]`.
fn ssh_key(line: &str) -> Result<OpaqueKey> {
    let mut parts = line.split_whitespace();
    let (Some(kind), Some(b64)) = (parts.next(), parts.next()) else {
        return err("expected an OpenSSH public key: TYPE BASE64 [COMMENT]");
    };
    let blob = writ_sexp::base64::decode(b64.as_bytes())
        .ok_or_else(|| Error::Msg(format!("{kind} key: bad base64")))?;
    // The blob starts with the length-prefixed key type.
    let declared = blob
        .get(..4)
        .and_then(|l| l.try_into().ok())
        .map(u32::from_be_bytes)
        .and_then(|n| blob.get(4..4usize.checked_add(usize::try_from(n).ok()?)?));
    if declared != Some(kind.as_bytes()) {
        return err(format!(
            "{kind} key: the key data says it is a different type"
        ));
    }
    Ok(OpaqueKey {
        kind: kind.as_bytes().to_vec(),
        bytes: blob,
    })
}
