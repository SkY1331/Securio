//! Rétro-compatibilité : fichiers témoins créés par Securio 1.2.1 (v1) et 1.3 (v2),
//! et par la 2.0 (v3). Ces fichiers ne doivent JAMAIS être régénérés.

use base64::Engine;
use securio_core::*;
use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::path::PathBuf;

fn fixtures(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test/fixtures")
        .join(sub)
}

fn sha(b: &[u8]) -> String {
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn manifest(sub: &str) -> Vec<serde_json::Value> {
    serde_json::from_slice(&std::fs::read(fixtures(sub).join("manifest.json")).unwrap()).unwrap()
}

fn s<'a>(v: &'a serde_json::Value, k: &str) -> &'a str {
    v[k].as_str().unwrap()
}

/// Ce que l'ancienne interface donnait réellement à chiffrer.
fn legacy_input(original: &[u8], read_mode: &str, mime: &str) -> Vec<u8> {
    match read_mode {
        // readAsText puis charCodeAt & 0xFF
        "text" => String::from_utf8(original.to_vec())
            .unwrap()
            .encode_utf16()
            .map(|u| u as u8)
            .collect(),
        "dataurl" => format!(
            "data:{mime};base64,{}",
            base64::engine::general_purpose::STANDARD.encode(original)
        )
        .into_bytes(),
        _ => original.to_vec(),
    }
}

#[test]
fn v1_fixtures() {
    for fx in manifest("v1") {
        let file = s(&fx, "file");
        let bytes = std::fs::read(fixtures("v1").join(file)).unwrap();
        let original = base64::engine::general_purpose::STANDARD
            .decode(s(&fx, "originalBase64"))
            .unwrap();
        let name = s(&fx, "originalName");

        assert!(
            matches!(
                inspect(&bytes[..PROBE_LEN.min(bytes.len())], bytes.len() as u64),
                Some(Inspection::V1(_))
            ),
            "{file}"
        );

        let d = decrypt_legacy(
            &bytes,
            s(&fx, "password"),
            &LegacyOptions {
                algorithm: None,
                outer_name: Some(format!("{name}.encrypted")),
            },
        )
        .unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(d.format, "v1");
        assert_eq!(d.algorithm, s(&fx, "algorithm"), "{file}");
        assert_eq!(d.variants[0].name, sanitize_file_name(name), "{file}");

        // Le contenu brut est exactement ce que l'ancienne version restituait
        let mime = if file.starts_with("image") {
            "image/png"
        } else {
            ""
        };
        let raw = d
            .variants
            .iter()
            .find(|v| v.label.starts_with("Contenu brut"))
            .unwrap_or(&d.variants[0]);
        assert_eq!(
            *raw.content,
            legacy_input(&original, s(&fx, "readMode"), mime),
            "{file}"
        );

        if s(&fx, "readMode") == "arraybuffer" {
            assert_eq!(
                sha(&d.variants[0].content),
                s(&fx, "originalSha256"),
                "{file}"
            );
        }
    }
}

fn v1(file: &str) -> Vec<u8> {
    std::fs::read(fixtures("v1").join(file)).unwrap()
}

fn original_sha(file: &str) -> String {
    manifest("v1")
        .into_iter()
        .find(|m| s(m, "file") == file)
        .map(|m| s(&m, "originalSha256").to_string())
        .unwrap()
}

#[test]
fn v1_image_restored_exactly() {
    let d = decrypt_legacy(
        &v1("image.png.encrypted"),
        "motdepasse",
        &LegacyOptions::default(),
    )
    .unwrap();
    assert_eq!(
        sha(&d.variants[0].content),
        original_sha("image.png.encrypted")
    );
    assert_eq!(d.variants[0].mime, "image/png");
    assert!(!d.warnings.is_empty());
}

#[test]
fn v1_latin1_text_restored_exactly() {
    let d = decrypt_legacy(
        &v1("texte-latin1.txt.encrypted"),
        "motdepasse",
        &LegacyOptions::default(),
    )
    .unwrap();
    assert_eq!(
        sha(&d.variants[0].content),
        original_sha("texte-latin1.txt.encrypted")
    );
}

#[test]
fn v1_lossy_text_best_effort() {
    let d = decrypt_legacy(
        &v1("texte-avec-pertes.txt.encrypted"),
        "motdepasse",
        &LegacyOptions::default(),
    )
    .unwrap();
    let text = String::from_utf8(d.variants[0].content.to_vec()).unwrap();
    assert!(text.contains("l’apostrophe"));
    assert!(text.contains('—'));
    assert!(text.contains("10 ¬"));
}

#[test]
fn v1_truncated_name() {
    let bytes = v1("nom-long.pdf.encrypted");
    let d = decrypt_legacy(
        &bytes,
        "motdepasse",
        &LegacyOptions {
            outer_name: Some("autre.encrypted".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert!(d.variants[0].name.len() <= 32);
    assert!(d.warnings.iter().any(|w| w.contains("tronqué")));

    let d = decrypt_legacy(
        &bytes,
        "motdepasse",
        &LegacyOptions {
            outer_name: Some(
                "C:\\Users\\x\\Rapport annuel confidentiel 2024 version finale.pdf (1).encrypted"
                    .into(),
            ),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        d.variants[0].name,
        "Rapport annuel confidentiel 2024 version finale.pdf"
    );
}

#[test]
fn v1_accented_password() {
    let d = decrypt_legacy(
        &v1("mdp-accentue.bin.encrypted"),
        "clé€secrète",
        &LegacyOptions::default(),
    )
    .unwrap();
    assert_eq!(
        sha(&d.variants[0].content),
        original_sha("mdp-accentue.bin.encrypted")
    );
}

#[test]
fn v1_forced_algorithm() {
    let bytes = v1("binaire-aes128.bin.encrypted");
    let ok = decrypt_legacy(
        &bytes,
        "motdepasse",
        &LegacyOptions {
            algorithm: Some("aes-128-cbc".into()),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        sha(&ok.variants[0].content),
        original_sha("binaire-aes128.bin.encrypted")
    );
    let err = decrypt_legacy(
        &bytes,
        "motdepasse",
        &LegacyOptions {
            algorithm: Some("aes-256-cbc".into()),
            ..Default::default()
        },
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("Détection automatique"));
}

#[test]
fn v1_wrong_password() {
    let err = decrypt_legacy(
        &v1("binaire-aes256.bin.encrypted"),
        "mauvaise",
        &LegacyOptions::default(),
    )
    .err()
    .unwrap();
    assert!(err.to_string().contains("Clé incorrecte"));
}

#[test]
fn v2_fixtures() {
    for fx in manifest("v2") {
        let bytes = std::fs::read(fixtures("v2").join(s(&fx, "file"))).unwrap();
        assert!(matches!(
            inspect(&bytes[..PROBE_LEN], bytes.len() as u64),
            Some(Inspection::V2(_))
        ));
        let d = decrypt_legacy(&bytes, s(&fx, "password"), &LegacyOptions::default()).unwrap();
        assert_eq!(d.format, "v2");
        assert_eq!(sha(&d.variants[0].content), s(&fx, "originalSha256"));
        assert_eq!(d.variants[0].name, s(&fx, "name"));
        assert_eq!(d.variants[0].mime, s(&fx, "type"));
    }
}

#[test]
fn v2_wrong_password_and_tamper() {
    let fx = &manifest("v2")[0];
    let bytes = std::fs::read(fixtures("v2").join(s(fx, "file"))).unwrap();
    assert!(decrypt_legacy(&bytes, "mauvaise", &LegacyOptions::default()).is_err());
    for pos in [18, 40, bytes.len() - 1] {
        let mut t = bytes.clone();
        t[pos] ^= 1;
        assert!(
            decrypt_legacy(&t, s(fx, "password"), &LegacyOptions::default()).is_err(),
            "pos {pos}"
        );
    }
}

#[test]
fn v3_fixtures() {
    for fx in manifest("v3") {
        let bytes = std::fs::read(fixtures("v3").join(s(&fx, "file"))).unwrap();
        assert!(matches!(
            inspect(&bytes[..PROBE_LEN], bytes.len() as u64),
            Some(Inspection::V3(_))
        ));
        let mut cur = Cursor::new(&bytes);
        let opened = v3::open(&mut cur, s(&fx, "password")).unwrap();
        assert_eq!(opened.meta.name, s(&fx, "name"));
        assert_eq!(opened.meta.mime, s(&fx, "type"));
        let mut out = Vec::new();
        opened.decrypt_to(&mut cur, &mut out, |_| {}).unwrap();
        assert_eq!(sha(&out), s(&fx, "originalSha256"));
    }
}

#[test]
fn not_securio() {
    let text = b"bonjour, ceci est un texte ordinaire !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
    assert!(inspect(text, text.len() as u64).is_none());
    assert!(inspect(&[0u8; 10], 10).is_none());
    let mut future = b"SECURIO\x09".to_vec();
    future.resize(64, 0);
    assert!(matches!(
        inspect(&future, 64),
        Some(Inspection::Future { version: 9 })
    ));
}
