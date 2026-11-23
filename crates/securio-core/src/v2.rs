//! Lecture des fichiers au format v2 (Securio 1.3).
//!
//! ```text
//! 0   7  "SECURIO"          13  1  longueur du sel (16)
//! 7   1  version (2)        14  1  chiffrement (1 = AES-256-GCM)
//! 8   1  KDF (1 = PBKDF2)   15  1  longueur de l'IV (12)
//! 9   4  itérations u32 LE  16  …  sel, IV, puis AES-GCM (tag de 16 octets)
//! ```
//! En-tête = données associées (AAD). Clair = `[u32 LE L][JSON L octets][fichier]`.
//! Mot de passe : UTF-8 après normalisation NFC.

use crate::{Error, Metadata, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

pub const VERSION: u8 = 2;
pub const KDF_PBKDF2_SHA256: u8 = 1;
pub const CIPHER_AES_256_GCM: u8 = 1;
const MAX_ITERATIONS: u32 = 10_000_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V2Info {
    pub kdf: u8,
    pub iterations: u32,
    pub salt_length: u8,
    pub cipher: u8,
    pub iv_length: u8,
    pub header_length: usize,
}

/// Mot de passe des formats v2 et v3 : UTF-8 après normalisation NFC.
pub fn password_bytes(password: &str) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(password.nfc().collect::<String>().into_bytes())
}

/// `probe` doit commencer par "SECURIO" + version 2.
pub fn inspect(probe: &[u8]) -> Option<V2Info> {
    if probe.len() < 16 || &probe[..7] != crate::MAGIC || probe[7] != VERSION {
        return None;
    }
    Some(V2Info {
        kdf: probe[8],
        iterations: u32::from_le_bytes(probe[9..13].try_into().ok()?),
        salt_length: probe[13],
        cipher: probe[14],
        iv_length: probe[15],
        header_length: 16 + probe[13] as usize + probe[15] as usize,
    })
}

/// Déchiffre un fichier v2 complet → (métadonnées, contenu).
pub fn decrypt(
    bytes: &[u8],
    info: &V2Info,
    password: &str,
) -> Result<(Metadata, Zeroizing<Vec<u8>>)> {
    if info.kdf != KDF_PBKDF2_SHA256 || info.cipher != CIPHER_AES_256_GCM {
        return Err(Error::UnknownAlgorithm);
    }
    if info.iterations < 1
        || info.iterations > MAX_ITERATIONS
        || info.salt_length < 8
        || info.iv_length != 12
    {
        return Err(Error::Invalid("en-tête v2 incorrect".into()));
    }
    if bytes.len() < info.header_length + 16 + 4 {
        return Err(Error::Invalid("fichier tronqué".into()));
    }
    let header = &bytes[..info.header_length];
    let salt = &header[16..16 + info.salt_length as usize];
    let iv = &header[16 + info.salt_length as usize..];

    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        &password_bytes(password),
        salt,
        info.iterations,
        key.as_mut(),
    );
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("clé de 32 octets");
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(iv),
                Payload {
                    msg: &bytes[info.header_length..],
                    aad: header,
                },
            )
            .map_err(|_| {
                Error::WrongPassword("Clé incorrecte ou fichier modifié/corrompu.".into())
            })?,
    );

    let meta_len = u32::from_le_bytes(plain[..4].try_into().expect("4 octets")) as usize;
    if 4 + meta_len > plain.len() {
        return Err(Error::Invalid("métadonnées incorrectes".into()));
    }
    let meta: Metadata = serde_json::from_slice(&plain[4..4 + meta_len])
        .map_err(|_| Error::Invalid("métadonnées incorrectes".into()))?;
    Ok((meta, Zeroizing::new(plain[4 + meta_len..].to_vec())))
}
