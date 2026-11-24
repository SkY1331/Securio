//! Format v3 : aller-retour, intégrité, troncature, réorganisation.

use securio_core::v3::{self, Params};
use securio_core::{Error, Metadata};
use std::io::Cursor;

const FAST: Params = Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
    chunk_size: 1024,
};

fn meta(name: &str, size: usize) -> Metadata {
    Metadata {
        name: name.into(),
        mime: "application/pdf".into(),
        size: size as u64,
    }
}

fn enc(data: &[u8], pw: &str, params: &Params) -> Vec<u8> {
    let mut out = Vec::new();
    v3::encrypt(
        Cursor::new(data),
        &mut out,
        pw,
        &meta("doc.pdf", data.len()),
        params,
        |_| {},
    )
    .unwrap();
    out
}

fn dec(file: &[u8], pw: &str) -> Result<(Metadata, Vec<u8>), Error> {
    let mut cur = Cursor::new(file);
    let opened = v3::open(&mut cur, pw)?;
    let mut out = Vec::new();
    opened.decrypt_to(&mut cur, &mut out, |_| {})?;
    Ok((opened.meta.clone(), out))
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

#[test]
fn round_trip_sizes() {
    // vide, < 1 segment, exactement 1, 1 + 1 octet, plusieurs
    for n in [0, 1, 1023, 1024, 1025, 2048, 5000] {
        let d = data(n);
        let f = enc(&d, "clé", &FAST);
        let (m, out) = dec(&f, "clé").unwrap();
        assert_eq!(out, d, "taille {n}");
        assert_eq!(m.size, n as u64);
        assert_eq!(m.name, "doc.pdf");
    }
}

#[test]
fn default_params() {
    let d = data(3000);
    let f = enc(&d, "x", &Params::default());
    let h = v3::V3Header::parse(&f).unwrap();
    assert_eq!(
        (h.m_cost_kib, h.t_cost, h.p_cost, h.chunk_size),
        (262144, 3, 4, 1 << 20)
    );
    assert_eq!(dec(&f, "x").unwrap().1, d);
}

#[test]
fn name_is_hidden_and_length_padded() {
    let d = data(10);
    let mut a = Vec::new();
    let mut b = Vec::new();
    v3::encrypt(Cursor::new(&d), &mut a, "k", &meta("a", 10), &FAST, |_| {}).unwrap();
    v3::encrypt(
        Cursor::new(&d),
        &mut b,
        "k",
        &meta("Résumé confidentiel de l’équipe.pdf", 10),
        &FAST,
        |_| {},
    )
    .unwrap();
    assert_eq!(a.len(), b.len(), "la longueur du nom ne doit pas fuir");
    assert!(!b.windows(12).any(|w| w == b"confidentiel"));
}

#[test]
fn wrong_password() {
    let f = enc(&data(100), "bonne", &FAST);
    assert!(matches!(dec(&f, "mauvaise"), Err(Error::WrongPassword(_))));
}

#[test]
fn unicode_password_nfc_nfd() {
    use unicode_normalization::UnicodeNormalization;
    let nfc: String = "clé€🔑".nfc().collect();
    let nfd: String = "clé€🔑".nfd().collect();
    assert_ne!(nfc, nfd);
    let f = enc(&data(10), &nfc, &FAST);
    assert_eq!(dec(&f, &nfd).unwrap().1, data(10));
}

#[test]
fn any_bit_flip_is_detected() {
    let f = enc(&data(3000), "k", &FAST);
    for pos in (0..f.len()).step_by(37).chain([f.len() - 1]) {
        let mut t = f.clone();
        t[pos] ^= 0x01;
        assert!(
            dec(&t, "k").is_err(),
            "altération non détectée à l'octet {pos}"
        );
    }
}

#[test]
fn truncation_is_detected() {
    let f = enc(&data(5000), "k", &FAST);
    let data_off = v3::V3Header::parse(&f).unwrap().data_offset() as usize;
    let seg = 1024 + 16;
    // coupe à chaque frontière de segment et au milieu
    for cut in [
        data_off + seg,
        data_off + 2 * seg,
        data_off + 4 * seg,
        f.len() - 1,
        f.len() - 16,
    ] {
        assert!(
            dec(&f[..cut], "k").is_err(),
            "troncature non détectée à {cut}"
        );
    }
}

#[test]
fn extension_is_detected() {
    let mut f = enc(&data(2048), "k", &FAST); // 2 segments pleins, le 2e est le dernier
    f.extend_from_slice(&[0u8; 16]);
    assert!(dec(&f, "k").is_err());
}

#[test]
fn reordering_is_detected() {
    let f = enc(&data(4096), "k", &FAST);
    let off = v3::V3Header::parse(&f).unwrap().data_offset() as usize;
    let seg = 1024 + 16;
    let mut t = f.clone();
    let (a, b) = (off, off + seg);
    let s1 = f[a..a + seg].to_vec();
    let s2 = f[b..b + seg].to_vec();
    t[a..a + seg].copy_from_slice(&s2);
    t[b..b + seg].copy_from_slice(&s1);
    assert!(dec(&t, "k").is_err());
}

#[test]
fn file_changed_during_encryption() {
    let d = data(100);
    let mut out = Vec::new();
    let r = v3::encrypt(
        Cursor::new(&d),
        &mut out,
        "k",
        &meta("a", 99),
        &FAST,
        |_| {},
    );
    assert!(r.is_err());
}

#[test]
fn hostile_header_is_rejected_cheaply() {
    let base = enc(&data(10), "k", &FAST);
    // mémoire Argon2 > 1 Gio
    let mut f = base.clone();
    f[9..13].copy_from_slice(&(1024 * 1024 + 1u32).to_le_bytes());
    assert!(matches!(dec(&f, "k"), Err(Error::Invalid(_))));
    // passes Argon2 > 10
    let mut f = base.clone();
    f[13..17].copy_from_slice(&11u32.to_le_bytes());
    assert!(matches!(dec(&f, "k"), Err(Error::Invalid(_))));
    // parallélisme nul
    let mut f = base.clone();
    f[17] = 0;
    assert!(matches!(dec(&f, "k"), Err(Error::Invalid(_))));
    // segments démesurés
    let mut f = base;
    f[21..25].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(dec(&f, "k"), Err(Error::Invalid(_))));
}

#[test]
fn params_of_published_versions_stay_accepted() {
    // 2.0 (64 Mio) et 2.1 (256 Mio) : les bornes ne doivent jamais les exclure
    for m in [64 * 1024, 256 * 1024] {
        let p = Params {
            m_cost_kib: m,
            t_cost: 3,
            p_cost: 4,
            chunk_size: 1 << 20,
        };
        let f = enc(&data(10), "k", &p);
        assert_eq!(dec(&f, "k").unwrap().1, data(10));
    }
}

#[test]
fn progress_is_reported() {
    let d = data(5000);
    let mut out = Vec::new();
    let mut seen = Vec::new();
    v3::encrypt(
        Cursor::new(&d),
        &mut out,
        "k",
        &meta("a", 5000),
        &FAST,
        |n| seen.push(n),
    )
    .unwrap();
    assert_eq!(seen.last(), Some(&5000));
    assert!(seen.len() >= 5);
}
