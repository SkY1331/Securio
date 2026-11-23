//! Lecture des fichiers au format v1 (Securio 1.0 → 1.2.1).
//!
//! ⚠️ Rétro-compatibilité : ce module reproduit À L'OCTET PRÈS le code d'origine
//! (`test/legacy/cryptoUtils.v1.original.js`). Ne pas modifier la dérivation de
//! clé ni le découpage.
//!
//! ```text
//! [0..64)   en-tête : version u32 LE (=1) | type u32 LE | nom UTF-8 sur 32 octets
//!           (complété par des 0) | taille des données chiffrées u32 LE | 20 réservés
//! [64..80)  sel PBKDF2
//! [80..96)  IV AES-CBC
//! [96..)    AES-CBC + PKCS#7, sans authentification
//! ```
//! Clé : PBKDF2-HMAC-SHA256, 100 000 itérations, mot de passe encodé « un octet
//! par unité UTF-16 » (`charCodeAt & 0xFF`), 128/192/256 bits selon l'algorithme
//! choisi à l'époque — qui n'est PAS enregistré dans le fichier.

use crate::{Error, Result};
use cbc::cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
use serde::Serialize;
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_SIZE: usize = 64;
pub const PREFIX_SIZE: usize = HEADER_SIZE + 16 + 16;
pub const ITERATIONS: u32 = 100_000;
pub const ALGORITHMS: [&str; 3] = ["aes-256-cbc", "aes-192-cbc", "aes-128-cbc"];

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V1Info {
    pub data_size: u32,
    pub header_name: String,
    pub possibly_truncated: bool,
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 octets"))
}

/// Encodage historique du mot de passe : chaque unité UTF-16 tronquée à 8 bits.
pub fn password_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.encode_utf16().map(|u| u as u8).collect())
}

/// `probe` : au moins les 64 premiers octets ; `total_len` : taille du fichier.
pub fn inspect(probe: &[u8], total_len: u64) -> Option<V1Info> {
    if probe.len() < HEADER_SIZE || total_len < (PREFIX_SIZE + 16) as u64 {
        return None;
    }
    if u32le(probe, 0) != 1 {
        return None;
    }
    let data_size = u32le(probe, 40);
    if data_size == 0
        || !data_size.is_multiple_of(16)
        || data_size as u64 > total_len - PREFIX_SIZE as u64
    {
        return None;
    }

    let field = &probe[8..40];
    let zero = field.iter().position(|&b| b == 0);
    let name_bytes = &field[..zero.unwrap_or(field.len())];
    let decoded = String::from_utf8_lossy(name_bytes);
    let cut_mid_char = decoded.ends_with('\u{FFFD}');
    let name = decoded
        .trim_end_matches('\u{FFFD}')
        .trim_end_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    let possibly_truncated = zero.is_none() || cut_mid_char || name_bytes.len() >= 29;

    Some(V1Info {
        data_size,
        header_name: name,
        possibly_truncated,
    })
}

fn cbc_decrypt(key: &[u8], iv: &[u8], ct: &[u8]) -> Option<Vec<u8>> {
    match key.len() {
        32 => cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok(),
        24 => cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok(),
        16 => cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .ok()?
            .decrypt_padded_vec_mut::<Pkcs7>(ct)
            .ok(),
        _ => None,
    }
}

/// Déchiffre un fichier v1 complet.
///
/// `algorithm` = `Some("aes-256-cbc" | "aes-192-cbc" | "aes-128-cbc")` : seul cet
/// algorithme est essayé (comportement historique). Sinon : détection automatique
/// (256, puis 192, puis 128).
///
/// AES-CBC n'étant pas authentifié, une mauvaise clé peut exceptionnellement
/// (~0,4 % par algorithme essayé) passer le contrôle de remplissage : c'est une
/// limite du format v1.
pub fn decrypt(
    bytes: &[u8],
    info: &V1Info,
    password: &str,
    algorithm: Option<&str>,
) -> Result<(Zeroizing<Vec<u8>>, &'static str)> {
    let salt = &bytes[HEADER_SIZE..HEADER_SIZE + 16];
    let iv = &bytes[HEADER_SIZE + 16..PREFIX_SIZE];
    let ct = &bytes[PREFIX_SIZE..PREFIX_SIZE + info.data_size as usize];

    let forced = algorithm
        .and_then(|a| ALGORITHMS.iter().find(|&&x| x == a))
        .copied();
    let order: Vec<&'static str> = match forced {
        Some(a) => vec![a],
        None => ALGORITHMS.to_vec(),
    };

    // PBKDF2 : les clés 128/192 bits sont les préfixes de la clé 256 bits.
    let mut derived = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        &password_bytes(password),
        salt,
        ITERATIONS,
        derived.as_mut(),
    );

    for algo in &order {
        let len = match *algo {
            "aes-256-cbc" => 32,
            "aes-192-cbc" => 24,
            _ => 16,
        };
        if let Some(mut pt) = cbc_decrypt(&derived[..len], iv, ct) {
            let out = Zeroizing::new(std::mem::take(&mut pt));
            pt.zeroize();
            return Ok((out, algo));
        }
    }
    Err(Error::WrongPassword(if order.len() == 1 {
        "Clé incorrecte (ou mauvais algorithme : essayez « Détection automatique »).".into()
    } else {
        "Clé incorrecte (aucun des algorithmes AES-128/192/256-CBC ne fonctionne).".into()
    }))
}
