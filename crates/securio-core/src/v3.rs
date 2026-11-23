//! Format v3 (Securio ≥ 2.0) : Argon2id + AES-256-GCM par segments (STREAM).
//!
//! ```text
//! Offset Taille Champ
//! 0      7      "SECURIO"
//! 7      1      version (3)
//! 8      1      KDF : 2 = Argon2id (v0x13)
//! 9      4      Argon2 m_cost en Kio (u32 LE)
//! 13     4      Argon2 t_cost (u32 LE)
//! 17     1      Argon2 parallélisme
//! 18     1      longueur du sel (16)
//! 19     1      chiffrement : 2 = AES-256-GCM STREAM (nonce = préfixe ‖ compteur u32 BE ‖ drapeau « dernier »)
//! 20     1      longueur du préfixe de nonce (7)
//! 21     4      taille d'un segment en clair (u32 LE)
//! 25     4      taille du segment de métadonnées chiffré (u32 LE)
//! 29     16     sel
//! 45     7      préfixe de nonce
//! 52     …      segments
//! ```
//!
//! Segments (chacun = chiffré AES-256-GCM avec tag de 16 octets, AAD = en-tête complet) :
//! - n° 0 : métadonnées JSON `{name, type, size}` complétées par des espaces à un
//!   multiple de 256 octets (la longueur du nom ne fuit pas) ;
//! - n° 1… : le fichier, découpé en segments de `chunk_size` octets ; le dernier
//!   (éventuellement vide) porte le drapeau « dernier ».
//!
//! Le compteur interdit la réorganisation des segments, le drapeau « dernier »
//! interdit la troncature, l'AAD lie chaque segment à l'en-tête. Le fichier est
//! traité en flux : la mémoire utilisée ne dépend pas de sa taille.

use crate::{Error, Metadata, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use serde::Serialize;
use std::io::{BufRead, BufReader, Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub const VERSION: u8 = 3;
pub const KDF_ARGON2ID: u8 = 2;
pub const CIPHER_AES_256_GCM_STREAM: u8 = 2;
pub const HEADER_LEN: usize = 52;
const SALT_LEN: usize = 16;
const NONCE_PREFIX_LEN: usize = 7;
const TAG_LEN: usize = 16;
const META_PAD: usize = 256;

// Garde-fous contre un fichier forgé (déni de service)
const MAX_M_COST_KIB: u32 = 4 * 1024 * 1024; // 4 Gio
const MAX_T_COST: u32 = 64;
const MAX_P_COST: u8 = 16;
const MIN_CHUNK: u32 = 1024;
const MAX_CHUNK: u32 = 64 * 1024 * 1024;
const MAX_META_CT: u32 = 64 * 1024;

/// Paramètres de chiffrement v3.
#[derive(Debug, Clone, Copy)]
pub struct Params {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u8,
    pub chunk_size: u32,
}

impl Default for Params {
    /// RFC 9106, deuxième recommandation : Argon2id, 64 Mio, t = 3, p = 4.
    /// Segments de 1 Mio.
    fn default() -> Self {
        Params {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            chunk_size: 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct V3Header {
    pub kdf: u8,
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u8,
    pub cipher: u8,
    pub chunk_size: u32,
    pub meta_ct_len: u32,
    #[serde(skip)]
    salt: [u8; SALT_LEN],
    #[serde(skip)]
    nonce_prefix: [u8; NONCE_PREFIX_LEN],
    #[serde(skip)]
    raw: [u8; HEADER_LEN],
}

fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 octets"))
}

impl V3Header {
    /// Lit l'en-tête (sans le valider) si `probe` commence par "SECURIO" v3.
    pub fn parse(probe: &[u8]) -> Option<Self> {
        if probe.len() < HEADER_LEN || &probe[..7] != crate::MAGIC || probe[7] != VERSION {
            return None;
        }
        let mut raw = [0u8; HEADER_LEN];
        raw.copy_from_slice(&probe[..HEADER_LEN]);
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&raw[29..45]);
        let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
        nonce_prefix.copy_from_slice(&raw[45..52]);
        Some(V3Header {
            kdf: raw[8],
            m_cost_kib: u32le(&raw, 9),
            t_cost: u32le(&raw, 13),
            p_cost: raw[17],
            cipher: raw[19],
            chunk_size: u32le(&raw, 21),
            meta_ct_len: u32le(&raw, 25),
            salt,
            nonce_prefix,
            raw,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.kdf != KDF_ARGON2ID || self.cipher != CIPHER_AES_256_GCM_STREAM {
            return Err(Error::UnknownAlgorithm);
        }
        let bad = |what: &str| Err(Error::Invalid(format!("en-tête v3 incorrect ({what})")));
        if self.raw[18] as usize != SALT_LEN || self.raw[20] as usize != NONCE_PREFIX_LEN {
            return bad("longueurs");
        }
        if self.m_cost_kib < 8 * self.p_cost as u32 || self.m_cost_kib > MAX_M_COST_KIB {
            return bad("mémoire Argon2");
        }
        if self.t_cost == 0
            || self.t_cost > MAX_T_COST
            || self.p_cost == 0
            || self.p_cost > MAX_P_COST
        {
            return bad("paramètres Argon2");
        }
        if !(MIN_CHUNK..=MAX_CHUNK).contains(&self.chunk_size) {
            return bad("taille de segment");
        }
        if (self.meta_ct_len as usize) < META_PAD + TAG_LEN || self.meta_ct_len > MAX_META_CT {
            return bad("métadonnées");
        }
        Ok(())
    }

    /// Position du premier segment de données dans le fichier.
    pub fn data_offset(&self) -> u64 {
        HEADER_LEN as u64 + self.meta_ct_len as u64
    }
}

fn validate_params(p: &Params) -> Result<()> {
    if p.p_cost == 0
        || p.p_cost > MAX_P_COST
        || p.t_cost == 0
        || p.t_cost > MAX_T_COST
        || p.m_cost_kib < 8 * p.p_cost as u32
        || p.m_cost_kib > MAX_M_COST_KIB
        || !(MIN_CHUNK..=MAX_CHUNK).contains(&p.chunk_size)
    {
        return Err(Error::Invalid(
            "paramètres de chiffrement hors limites".into(),
        ));
    }
    Ok(())
}

fn derive_key(password: &str, salt: &[u8], m: u32, t: u32, p: u8) -> Result<Zeroizing<[u8; 32]>> {
    let params = argon2::Params::new(m, t, p as u32, Some(32))
        .map_err(|e| Error::Invalid(format!("paramètres Argon2 : {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(&crate::v2::password_bytes(password), salt, key.as_mut())
        .map_err(|e| Error::Invalid(format!("Argon2 : {e}")))?;
    Ok(key)
}

fn nonce(prefix: &[u8; NONCE_PREFIX_LEN], counter: u32, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..7].copy_from_slice(prefix);
    n[7..11].copy_from_slice(&counter.to_be_bytes());
    n[11] = last as u8;
    n
}

/// Lit jusqu'à remplir `buf` ou atteindre la fin ; renvoie le nombre d'octets lus.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    Ok(b)
}

/// Chiffre `input` vers `output` au format v3.
/// `meta.size` doit être la taille exacte de `input` ; `progress` reçoit le nombre
/// d'octets en clair traités.
pub fn encrypt<R: Read, W: Write>(
    input: R,
    mut output: W,
    password: &str,
    meta: &Metadata,
    params: &Params,
    mut progress: impl FnMut(u64),
) -> Result<()> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    validate_params(params)?;

    // Métadonnées complétées par des espaces (JSON reste valide)
    let mut meta_plain = Zeroizing::new(serde_json::to_vec(meta).expect("sérialisation"));
    let padded = meta_plain.len().div_ceil(META_PAD).max(1) * META_PAD;
    meta_plain.resize(padded, b' ');
    let meta_ct_len = (padded + TAG_LEN) as u32;
    if meta_ct_len > MAX_META_CT {
        return Err(Error::Invalid("nom de fichier trop long".into()));
    }

    let salt: [u8; SALT_LEN] = random()?;
    let prefix: [u8; NONCE_PREFIX_LEN] = random()?;
    let mut header = [0u8; HEADER_LEN];
    header[..7].copy_from_slice(crate::MAGIC);
    header[7] = VERSION;
    header[8] = KDF_ARGON2ID;
    header[9..13].copy_from_slice(&params.m_cost_kib.to_le_bytes());
    header[13..17].copy_from_slice(&params.t_cost.to_le_bytes());
    header[17] = params.p_cost;
    header[18] = SALT_LEN as u8;
    header[19] = CIPHER_AES_256_GCM_STREAM;
    header[20] = NONCE_PREFIX_LEN as u8;
    header[21..25].copy_from_slice(&params.chunk_size.to_le_bytes());
    header[25..29].copy_from_slice(&meta_ct_len.to_le_bytes());
    header[29..45].copy_from_slice(&salt);
    header[45..52].copy_from_slice(&prefix);

    let key = derive_key(
        password,
        &salt,
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
    )?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("clé de 32 octets");
    let seal = |counter: u32, last: bool, msg: &[u8]| -> Result<Vec<u8>> {
        cipher
            .encrypt(
                Nonce::from_slice(&nonce(&prefix, counter, last)),
                Payload { msg, aad: &header },
            )
            .map_err(|_| Error::Invalid("échec du chiffrement".into()))
    };

    output.write_all(&header)?;
    output.write_all(&seal(0, false, &meta_plain)?)?;

    let chunk = params.chunk_size as usize;
    let mut reader = BufReader::with_capacity(chunk.clamp(64 * 1024, 1 << 20), input);
    let mut buf = Zeroizing::new(vec![0u8; chunk]);
    let mut counter: u32 = 1;
    let mut done: u64 = 0;
    loop {
        let n = read_full(&mut reader, &mut buf)?;
        let last = n < chunk || reader.fill_buf()?.is_empty();
        output.write_all(&seal(counter, last, &buf[..n])?)?;
        done += n as u64;
        progress(done);
        if last {
            break;
        }
        counter = counter
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("fichier trop volumineux".into()))?;
    }
    if done != meta.size {
        return Err(Error::Invalid(
            "le fichier a été modifié pendant le chiffrement".into(),
        ));
    }
    output.flush()?;
    Ok(())
}

/// Fichier v3 ouvert : clé dérivée et métadonnées déchiffrées.
/// La clé est effacée de la mémoire à la destruction.
pub struct Opened {
    pub header: V3Header,
    pub meta: Metadata,
    key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("header", &self.header)
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// Lit l'en-tête et les métadonnées, vérifie la clé. `input` doit être placé au
/// début du fichier ; il est laissé au début des données.
pub fn open<R: Read>(input: &mut R, password: &str) -> Result<Opened> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    let mut raw = [0u8; HEADER_LEN];
    if read_full(input, &mut raw)? < HEADER_LEN {
        return Err(Error::Invalid("fichier tronqué".into()));
    }
    let header = V3Header::parse(&raw).ok_or(Error::NotSecurio)?;
    header.validate()?;

    let mut meta_ct = vec![0u8; header.meta_ct_len as usize];
    if read_full(input, &mut meta_ct)? < meta_ct.len() {
        return Err(Error::Invalid("fichier tronqué".into()));
    }
    let key = derive_key(
        password,
        &header.salt,
        header.m_cost_kib,
        header.t_cost,
        header.p_cost,
    )?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).expect("clé de 32 octets");
    let meta_plain = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(&nonce(&header.nonce_prefix, 0, false)),
                Payload {
                    msg: &meta_ct,
                    aad: &header.raw,
                },
            )
            .map_err(|_| {
                Error::WrongPassword("Clé incorrecte ou fichier modifié/corrompu.".into())
            })?,
    );
    let meta: Metadata = serde_json::from_slice(&meta_plain)
        .map_err(|_| Error::Invalid("métadonnées incorrectes".into()))?;
    Ok(Opened { header, meta, key })
}

impl Opened {
    /// Déchiffre les données. `input` doit être placé à `header.data_offset()`.
    /// Renvoie le nombre d'octets écrits. En cas d'erreur, `output` peut contenir
    /// un début de fichier : l'appelant doit écrire dans un fichier temporaire et
    /// ne le renommer qu'en cas de succès.
    pub fn decrypt_to<R: Read, W: Write>(
        &self,
        input: R,
        mut output: W,
        mut progress: impl FnMut(u64),
    ) -> Result<u64> {
        let cipher = Aes256Gcm::new_from_slice(self.key.as_ref()).expect("clé de 32 octets");
        let seg_ct = self.header.chunk_size as usize + TAG_LEN;
        let mut reader = BufReader::with_capacity(seg_ct.clamp(64 * 1024, 1 << 20), input);
        let mut buf = vec![0u8; seg_ct];
        let mut counter: u32 = 1;
        let mut written: u64 = 0;
        loop {
            let n = read_full(&mut reader, &mut buf)?;
            if n < TAG_LEN {
                return Err(Error::Corrupted("fichier tronqué".into()));
            }
            let last = n < seg_ct || reader.fill_buf()?.is_empty();
            let mut plain = cipher
                .decrypt(
                    Nonce::from_slice(&nonce(&self.header.nonce_prefix, counter, last)),
                    Payload {
                        msg: &buf[..n],
                        aad: &self.header.raw,
                    },
                )
                .map_err(|_| {
                    Error::Corrupted(format!(
                        "segment n° {counter} invalide (fichier altéré ou tronqué)"
                    ))
                })?;
            written += plain.len() as u64;
            if written > self.meta.size {
                plain.zeroize();
                return Err(Error::Corrupted("taille incohérente".into()));
            }
            output.write_all(&plain)?;
            plain.zeroize();
            progress(written);
            if last {
                break;
            }
            counter = counter
                .checked_add(1)
                .ok_or_else(|| Error::Corrupted("trop de segments".into()))?;
        }
        if written != self.meta.size {
            return Err(Error::Corrupted("taille incohérente".into()));
        }
        output.flush()?;
        Ok(written)
    }
}
