//! Cœur cryptographique de Securio.
//!
//! - Chiffrement : format **v3** ([`v3`]) — Argon2id + AES-256-GCM par segments,
//!   traité en flux (taille de fichier illimitée en pratique).
//! - Déchiffrement : **v3**, **v2** (Securio 1.3) et **v1** (Securio 1.0 → 1.2.1).
//!
//! La rétro-compatibilité est vérifiée par les fichiers témoins de
//! `test/fixtures/` (générés par les anciennes versions), voir `tests/`.

pub mod archive;
mod error;
pub mod names;
pub mod passphrase;
pub mod repair;
pub mod v1;
pub mod v2;
pub mod v3;
pub mod wipe;

pub use error::{Error, Result};
pub use names::{name_from_encrypted_name, name_warnings, risky_extension, sanitize_file_name};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

pub const MAGIC: &[u8; 7] = b"SECURIO";
pub const ENCRYPTED_EXTENSION: &str = ".encrypted";
/// Nombre d'octets à lire en début de fichier pour [`inspect`].
pub const PROBE_LEN: usize = 128;

/// Métadonnées chiffrées avec le fichier (formats v2 et v3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Metadata {
    pub name: String,
    #[serde(rename = "type", default = "default_mime")]
    pub mime: String,
    #[serde(default)]
    pub size: u64,
}

fn default_mime() -> String {
    "application/octet-stream".into()
}

/// Résultat de l'identification d'un fichier.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "format")]
pub enum Inspection {
    #[serde(rename = "v1")]
    V1(v1::V1Info),
    #[serde(rename = "v2")]
    V2(v2::V2Info),
    #[serde(rename = "v3")]
    V3(v3::V3Header),
    /// Fichier Securio d'un format plus récent que cette version.
    #[serde(rename = "future")]
    Future { version: u8 },
}

/// Identifie un fichier Securio à partir de ses premiers octets (au moins
/// [`PROBE_LEN`] si le fichier est assez grand) et de sa taille totale.
pub fn inspect(probe: &[u8], total_len: u64) -> Option<Inspection> {
    if probe.len() >= 8 && &probe[..7] == MAGIC {
        return match probe[7] {
            v2::VERSION => v2::inspect(probe).map(Inspection::V2),
            v3::VERSION => v3::V3Header::parse(probe).map(Inspection::V3),
            0 | 1 => None,
            v => Some(Inspection::Future { version: v }),
        };
    }
    v1::inspect(probe, total_len).map(Inspection::V1)
}

/// Une version du contenu déchiffré, proposée à l'enregistrement.
pub struct Variant {
    pub label: String,
    pub name: String,
    pub mime: String,
    pub content: Zeroizing<Vec<u8>>,
}

/// Fichier v1 ou v2 déchiffré en mémoire.
pub struct Decrypted {
    pub format: &'static str,
    pub algorithm: &'static str,
    pub warnings: Vec<String>,
    /// `variants[0]` est la version recommandée.
    pub variants: Vec<Variant>,
}

/// Options de déchiffrement des anciens formats.
#[derive(Debug, Default, Clone)]
pub struct LegacyOptions {
    /// v1 : algorithme imposé (`aes-256-cbc`…) ; `None` = détection automatique.
    pub algorithm: Option<String>,
    /// Nom du fichier `.encrypted` (sert à retrouver un nom v1 tronqué).
    pub outer_name: Option<String>,
}

/// Déchiffre en mémoire un fichier v1 ou v2.
pub fn decrypt_legacy(bytes: &[u8], password: &str, opts: &LegacyOptions) -> Result<Decrypted> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let probe = &bytes[..bytes.len().min(PROBE_LEN)];
    match inspect(probe, bytes.len() as u64) {
        Some(Inspection::V2(info)) => {
            let (meta, content) = v2::decrypt(bytes, &info, password)?;
            Ok(Decrypted {
                format: "v2",
                algorithm: "aes-256-gcm",
                warnings: name_warnings(&meta.name),
                variants: vec![Variant {
                    label: "Fichier déchiffré".into(),
                    name: sanitize_file_name(&meta.name),
                    mime: meta.mime,
                    content,
                }],
            })
        }
        Some(Inspection::V1(info)) => decrypt_v1(bytes, &info, password, opts),
        Some(Inspection::Future { version }) => Err(Error::FutureVersion(version)),
        Some(Inspection::V3(_)) => Err(Error::Invalid("format v3 : utiliser v3::open".into())),
        None => Err(Error::NotSecurio),
    }
}

fn decrypt_v1(
    bytes: &[u8],
    info: &v1::V1Info,
    password: &str,
    opts: &LegacyOptions,
) -> Result<Decrypted> {
    let (plaintext, algorithm) = v1::decrypt(bytes, info, password, opts.algorithm.as_deref())?;
    let mut warnings = Vec::new();

    let outer = opts
        .outer_name
        .as_deref()
        .and_then(name_from_encrypted_name);
    let mut name = info.header_name.clone();
    if info.possibly_truncated {
        match &outer {
            Some(o) if !name.is_empty() && o.starts_with(&name) => name = o.clone(),
            _ => warnings.push(format!(
                "Le nom d'origine a pu être tronqué à 32 octets par l'ancienne version (« {name} »). Vérifiez l'extension avant d'ouvrir le fichier."
            )),
        }
    }
    if name.is_empty() {
        name = outer.unwrap_or_default();
    }
    warnings.extend(name_warnings(&name));
    let name = sanitize_file_name(&name);
    let octet = "application/octet-stream".to_string();
    let raw_label = "Contenu brut (tel que stocké)".to_string();

    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    let mut variants = Vec::new();

    if let Some((image, mime)) = repair::repair_data_url_image(&plaintext) {
        warnings.push(
            "Image chiffrée par une ancienne version (stockée en texte « data: ») : elle a été reconvertie automatiquement en image."
                .into(),
        );
        variants.push(Variant {
            label: "Image restaurée".into(),
            name: name.clone(),
            mime,
            content: Zeroizing::new(image),
        });
        variants.push(Variant {
            label: raw_label,
            name,
            mime: octet,
            content: plaintext,
        });
    } else if repair::TEXT_EXTENSIONS.contains(&ext.as_str()) {
        let certain = ext == "txt";
        match repair::repair_latin1_text(&plaintext, certain) {
            Some(fixed) => {
                warnings.push(format!(
                    "Fichier texte chiffré par une ancienne version : les caractères accentués avaient été stockés en Latin-1. {}Les caractères hors Latin-1 (€, emojis…) ont pu être altérés définitivement à l'époque ; € apparaît souvent comme ¬.",
                    if certain { "Ils ont été reconvertis en UTF-8. " } else { "Une version réparée est proposée. " }
                ));
                let fixed = Variant {
                    label: "Version texte réparée (UTF-8)".into(),
                    name: name.clone(),
                    mime: "text/plain".into(),
                    content: Zeroizing::new(fixed),
                };
                let raw = Variant {
                    label: raw_label,
                    name,
                    mime: octet,
                    content: plaintext,
                };
                if certain {
                    variants.push(fixed);
                    variants.push(raw);
                } else {
                    variants.push(raw);
                    variants.push(fixed);
                }
            }
            None => variants.push(Variant {
                label: "Fichier déchiffré".into(),
                name,
                mime: octet,
                content: plaintext,
            }),
        }
    } else {
        variants.push(Variant {
            label: "Fichier déchiffré".into(),
            name,
            mime: octet,
            content: plaintext,
        });
    }

    Ok(Decrypted {
        format: "v1",
        algorithm,
        warnings,
        variants,
    })
}
