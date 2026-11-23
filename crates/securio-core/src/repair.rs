//! Réparation des fichiers v1 abîmés par l'interface de Securio ≤ 1.2.1.
//!
//! - Les images étaient lues en data-URL : le fichier chiffré contient le TEXTE
//!   `data:image/...;base64,....` au lieu de l'image.
//! - Les `.txt` / `text/*` étaient lus en texte puis chaque caractère tronqué à
//!   8 bits : accents en Latin-1, caractères au-delà de U+00FF abîmés.

use base64::Engine;
use regex::bytes::Regex;
use std::sync::OnceLock;

pub const TEXT_EXTENSIONS: &[&str] = &[
    "txt", "text", "csv", "tsv", "md", "markdown", "log", "html", "htm", "css", "js", "mjs", "xml",
    "ics", "vcf",
];

fn data_url_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"^data:(image/[A-Za-z0-9.+-]+)(?:;[^,;]*)*;base64,([A-Za-z0-9+/]*={0,2})$")
            .expect("regex valide")
    })
}

/// Image stockée sous forme de data-URL → (octets de l'image, type MIME).
pub fn repair_data_url_image(plaintext: &[u8]) -> Option<(Vec<u8>, String)> {
    if plaintext.len() < 16 || !plaintext.starts_with(b"data:image/") {
        return None;
    }
    let caps = data_url_re().captures(plaintext)?;
    let mime = String::from_utf8(caps.get(1)?.as_bytes().to_vec()).ok()?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(caps.get(2)?.as_bytes())
        .ok()?;
    Some((data, mime))
}

/// Ponctuation typographique devenue caractère de contrôle (U+20xx & 0xFF).
fn truncated_punctuation(b: u8) -> Option<char> {
    match b {
        0x13 => Some('\u{2013}'), // –
        0x14 => Some('\u{2014}'), // —
        0x18 => Some('\u{2018}'), // ‘
        0x19 => Some('\u{2019}'), // ’
        0x1c => Some('\u{201C}'), // “
        0x1d => Some('\u{201D}'), // ”
        _ => None,
    }
}

/// Texte stocké en Latin-1 tronqué → UTF-8.
/// `certain` : le fichier a forcément été lu en texte (extension .txt) ; sinon on
/// ne répare que si le contenu n'est pas de l'UTF-8 valide.
pub fn repair_latin1_text(plaintext: &[u8], certain: bool) -> Option<Vec<u8>> {
    let has_high = plaintext.iter().any(|&b| b >= 0x80);
    let has_punct = plaintext
        .iter()
        .any(|&b| truncated_punctuation(b).is_some());
    if !has_high && !has_punct {
        return None;
    }
    if !certain && !has_punct && std::str::from_utf8(plaintext).is_ok() {
        return None;
    }
    let text: String = plaintext
        .iter()
        .map(|&b| truncated_punctuation(b).unwrap_or(b as char))
        .collect();
    Some(text.into_bytes())
}
