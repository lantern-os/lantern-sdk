//! The `lantern.capabilities.toml` model, parser, and validator (RFC-0015 §"Reference-level
//! explanation", §"Validation rules").

use std::fmt;

use crate::registry::{self, Shape};

/// A parsed, **validated** capability manifest. Every field here has passed the RFC-0015
/// checklist: known interfaces, legal `ops`, unique roles, non-empty justifications.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub app: AppInfo,
    /// `[[keystore.key]]` entries, in file order (the order *is* the `open(slot)` index).
    pub keystore: Vec<ResourceDecl>,
    /// `[[filesystem.file]]` entries, in file order.
    pub filesystem: Vec<ResourceDecl>,
    /// `[monotonic-clock]` — `Some` iff the table is present.
    pub monotonic_clock: Option<LinkDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceDecl {
    pub role: String,
    /// The requested operation subset (registry-validated, lower-cased).
    pub ops: Vec<String>,
    pub justification: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkDecl {
    pub justification: String,
}

const MAX_JUSTIFICATION: usize = 280;

/// Parses and validates a `lantern.capabilities.toml` source string.
pub fn parse(src: &str) -> Result<Manifest, ManifestError> {
    let root: toml::Table = src.parse().map_err(ManifestError::Toml)?;

    let app = parse_app(&root)?;

    let mut keystore = Vec::new();
    let mut filesystem = Vec::new();
    let mut monotonic_clock = None;

    for (key, value) in &root {
        if key == "app" {
            continue;
        }
        let iface = registry::lookup(key).ok_or_else(|| ManifestError::UnknownInterface(key.clone()))?;
        match &iface.shape {
            Shape::Resource { resource, ops } => {
                let decls = parse_resource_array(key, resource, ops, value)?;
                match iface.name {
                    "keystore" => keystore = decls,
                    "filesystem" => filesystem = decls,
                    other => {
                        // A new resource-scoped interface was added to the registry but
                        // not wired into this struct — fail loudly rather than silently
                        // drop the grants.
                        return Err(ManifestError::UnwiredInterface(other.to_string()));
                    }
                }
            }
            Shape::Link => {
                let decl = parse_link_table(key, value)?;
                match iface.name {
                    "monotonic-clock" => monotonic_clock = Some(decl),
                    other => return Err(ManifestError::UnwiredInterface(other.to_string())),
                }
            }
        }
    }

    Ok(Manifest { app, keystore, filesystem, monotonic_clock })
}

fn parse_app(root: &toml::Table) -> Result<AppInfo, ManifestError> {
    let table = root
        .get("app")
        .ok_or(ManifestError::MissingApp)?
        .as_table()
        .ok_or(ManifestError::MissingApp)?;

    let name = require_str(table, "app", "name")?;
    if !is_ident(&name) {
        return Err(ManifestError::BadAppField {
            field: "name",
            why: format!("{name:?} is not a valid identifier (^[a-z0-9]([a-z0-9-]*[a-z0-9])?$)"),
        });
    }
    let version = require_str(table, "app", "version")?;
    if !looks_like_semver(&version) {
        return Err(ManifestError::BadAppField {
            field: "version",
            why: format!("{version:?} is not an x.y.z version"),
        });
    }
    Ok(AppInfo { name, version })
}

fn parse_resource_array(
    iface: &str,
    resource: &str,
    legal_ops: &[&str],
    value: &toml::Value,
) -> Result<Vec<ResourceDecl>, ManifestError> {
    let table = value.as_table().ok_or_else(|| ManifestError::ShapeMismatch {
        interface: iface.to_string(),
        expected: "a [[<interface>.<resource>]] array-of-tables",
    })?;
    // The interface table must contain exactly the one registered resource key.
    for k in table.keys() {
        if k != resource {
            return Err(ManifestError::UnknownKey {
                context: format!("[{iface}]"),
                key: k.clone(),
            });
        }
    }
    let array = table
        .get(resource)
        .and_then(|v| v.as_array())
        .ok_or_else(|| ManifestError::ShapeMismatch {
            interface: iface.to_string(),
            expected: "a [[<interface>.<resource>]] array-of-tables",
        })?;

    let mut decls: Vec<ResourceDecl> = Vec::new();
    for (index, entry) in array.iter().enumerate() {
        let et = entry.as_table().ok_or_else(|| ManifestError::BadResourceEntry {
            interface: iface.to_string(),
            index,
            why: "not a table".to_string(),
        })?;
        for k in et.keys() {
            if !matches!(k.as_str(), "role" | "ops" | "justification") {
                return Err(ManifestError::UnknownKey {
                    context: format!("[[{iface}.{resource}]] #{index}"),
                    key: k.clone(),
                });
            }
        }

        let role = require_str(et, &format!("[[{iface}.{resource}]] #{index}"), "role")?;
        if !is_ident(&role) {
            return Err(ManifestError::BadResourceEntry {
                interface: iface.to_string(),
                index,
                why: format!("role {role:?} is not a valid identifier"),
            });
        }
        if decls.iter().any(|d| d.role == role) {
            return Err(ManifestError::DuplicateRole { interface: iface.to_string(), role });
        }

        let ops_val = et.get("ops").and_then(|v| v.as_array()).ok_or_else(|| {
            ManifestError::BadResourceEntry {
                interface: iface.to_string(),
                index,
                why: "`ops` must be an array of strings".to_string(),
            }
        })?;
        if ops_val.is_empty() {
            return Err(ManifestError::BadResourceEntry {
                interface: iface.to_string(),
                index,
                why: "`ops` is empty — a handle you can do nothing with is a bug".to_string(),
            });
        }
        let mut ops = Vec::new();
        for o in ops_val {
            let o = o.as_str().ok_or_else(|| ManifestError::BadResourceEntry {
                interface: iface.to_string(),
                index,
                why: "`ops` values must be strings".to_string(),
            })?;
            if !legal_ops.contains(&o) {
                return Err(ManifestError::UnknownOp {
                    interface: iface.to_string(),
                    role: role.clone(),
                    op: o.to_string(),
                });
            }
            if ops.iter().any(|x| x == o) {
                return Err(ManifestError::BadResourceEntry {
                    interface: iface.to_string(),
                    index,
                    why: format!("`ops` lists {o:?} twice"),
                });
            }
            ops.push(o.to_string());
        }

        let justification =
            require_justification(et, &format!("[[{iface}.{resource}]] #{index}"))?;

        decls.push(ResourceDecl { role, ops, justification });
    }
    Ok(decls)
}

fn parse_link_table(iface: &str, value: &toml::Value) -> Result<LinkDecl, ManifestError> {
    let table = value.as_table().ok_or_else(|| ManifestError::ShapeMismatch {
        interface: iface.to_string(),
        expected: "a [<interface>] table with a `justification`",
    })?;
    for k in table.keys() {
        if k != "justification" {
            return Err(ManifestError::UnknownKey {
                context: format!("[{iface}]"),
                key: k.clone(),
            });
        }
    }
    Ok(LinkDecl { justification: require_justification(table, &format!("[{iface}]"))? })
}

fn require_str(table: &toml::Table, context: &str, field: &str) -> Result<String, ManifestError> {
    table
        .get(field)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .ok_or_else(|| ManifestError::MissingField {
            context: context.to_string(),
            field: field.to_string(),
        })
}

fn require_justification(table: &toml::Table, context: &str) -> Result<String, ManifestError> {
    let raw = require_str(table, context, "justification")?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ManifestError::BadJustification {
            context: context.to_string(),
            why: "empty".to_string(),
        });
    }
    if trimmed.chars().count() > MAX_JUSTIFICATION {
        return Err(ManifestError::BadJustification {
            context: context.to_string(),
            why: format!("longer than {MAX_JUSTIFICATION} characters"),
        });
    }
    Ok(trimmed.to_string())
}

/// `^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`
fn is_ident(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.is_empty() {
        return false;
    }
    let ok = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    if !ok(bytes[0]) || !ok(bytes[bytes.len() - 1]) {
        return false;
    }
    bytes.iter().all(|&b| ok(b) || b == b'-')
}

/// Lenient — `version` is advisory only in Phase 2 (RFC-0015). Requires a leading digit
/// and at least two dots.
fn looks_like_semver(s: &str) -> bool {
    s.split('.').count() >= 3 && s.starts_with(|c: char| c.is_ascii_digit())
}

/// Every way a manifest can fail validation. Each carries enough to point a developer at
/// the offending declaration.
#[derive(Debug)]
pub enum ManifestError {
    Toml(toml::de::Error),
    MissingApp,
    MissingField { context: String, field: String },
    BadAppField { field: &'static str, why: String },
    BadJustification { context: String, why: String },
    UnknownInterface(String),
    UnwiredInterface(String),
    ShapeMismatch { interface: String, expected: &'static str },
    UnknownKey { context: String, key: String },
    BadResourceEntry { interface: String, index: usize, why: String },
    DuplicateRole { interface: String, role: String },
    UnknownOp { interface: String, role: String, op: String },
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Toml(e) => write!(f, "not valid TOML: {e}"),
            Self::MissingApp => write!(f, "missing or malformed [app] table (needs `name` and `version`)"),
            Self::MissingField { context, field } => write!(f, "{context}: missing required field `{field}`"),
            Self::BadAppField { field, why } => write!(f, "[app].{field}: {why}"),
            Self::BadJustification { context, why } => write!(f, "{context}: `justification` is {why}"),
            Self::UnknownInterface(n) => write!(f, "`{n}` is not a host interface this runtime provides (see the SDK's interface registry)"),
            Self::UnwiredInterface(n) => write!(f, "internal: registry interface `{n}` is not wired into the manifest model"),
            Self::ShapeMismatch { interface, expected } => write!(f, "`{interface}` must be {expected}"),
            Self::UnknownKey { context, key } => write!(f, "{context}: unexpected key `{key}`"),
            Self::BadResourceEntry { interface, index, why } => write!(f, "[[{interface}.*]] entry #{index}: {why}"),
            Self::DuplicateRole { interface, role } => write!(f, "`{interface}`: role `{role}` declared twice"),
            Self::UnknownOp { interface, role, op } => write!(f, "`{interface}` role `{role}`: `{op}` is not a legal operation for this resource"),
        }
    }
}

impl std::error::Error for ManifestError {}
