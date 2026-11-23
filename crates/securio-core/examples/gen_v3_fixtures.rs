//! Génère les fichiers témoins v3 (une seule fois ; ne jamais régénérer une fois commités).
//! cargo run --release -p securio-core --example gen_v3_fixtures

use securio_core::{v3, Metadata};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/v3");
    std::fs::create_dir_all(&dir).unwrap();
    let small: Vec<u8> = (0..3000u32).map(|i| (i * 13 + 5) as u8).collect();
    let multi: Vec<u8> = (0..10_000u32).map(|i| (i * 7 + 3) as u8).collect();

    let cases = [
        // paramètres par défaut (Argon2id 64 Mio, segments de 1 Mio)
        (
            "defaut.v3.encrypted",
            "motdepasse",
            "Résumé très long de l’équipe — 2026 (final).pdf",
            "application/pdf",
            &small,
            v3::Params::default(),
        ),
        // plusieurs segments + mot de passe Unicode
        (
            "multi-segments.v3.encrypted",
            "clé€🔑 secrète",
            "données.bin",
            "application/octet-stream",
            &multi,
            v3::Params {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
                chunk_size: 1024,
            },
        ),
        // fichier vide
        (
            "vide.v3.encrypted",
            "motdepasse",
            "vide.txt",
            "text/plain",
            &Vec::new(),
            v3::Params {
                m_cost_kib: 1024,
                t_cost: 1,
                p_cost: 1,
                chunk_size: 4096,
            },
        ),
    ];

    let mut manifest = Vec::new();
    for (file, pw, name, mime, data, params) in cases {
        let meta = Metadata {
            name: name.into(),
            mime: mime.into(),
            size: data.len() as u64,
        };
        let mut out = Vec::new();
        v3::encrypt(&data[..], &mut out, pw, &meta, &params, |_| {}).unwrap();
        std::fs::write(dir.join(file), out).unwrap();
        let sha: String = Sha256::digest(data)
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        manifest.push(serde_json::json!({ "file": file, "password": pw, "name": name, "type": mime, "originalSha256": sha }));
        println!("écrit {file}");
    }
    std::fs::write(
        dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).unwrap() + "\n",
    )
    .unwrap();
}
