//! Application Tauri de Securio.
//!
//! Toute la cryptographie est faite en Rust (crate `securio-core`). Voir
//! `commands.rs` pour les commandes appelées par l'interface.

mod commands;
mod files;

use files::TempJournal;
use securio_core as core;
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter, Manager};

/// Durée d'inactivité après laquelle le contenu déchiffré (v1/v2) ou la clé (v3)
/// sont effacés de la mémoire.
const SESSION_TTL: Duration = Duration::from_secs(5 * 60);

/// Fichier déchiffré en attente d'enregistrement. Les secrets (clé v3, contenu
/// v1/v2) sont effacés de la mémoire quand la session est détruite.
pub(crate) enum Session {
    InMemory(core::Decrypted),
    V3 {
        path: PathBuf,
        opened: core::v3::Opened,
    },
}

pub(crate) struct SessionSlot {
    pub id: u64,
    pub session: Arc<Session>,
    pub last_used: Instant,
}

/// Demande d'ouverture venue du système : lancement, double-clic, « Ouvrir avec »,
/// ou clic droit « Chiffrer avec Securio » (`--encrypt`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OpenRequest {
    pub action: &'static str, // "open" | "encrypt"
    pub path: String,
}

#[derive(Default)]
pub(crate) struct AppState {
    pub pending: Mutex<Vec<OpenRequest>>,
    /// Une seule session à la fois : ouvrir un autre fichier efface la précédente.
    pub session: Mutex<Option<SessionSlot>>,
    pub next_id: AtomicU64,
    pub journal: TempJournal,
}

/// Interprète les arguments de la ligne de commande.
/// `--encrypt CHEMIN` force le chiffrement ; tout autre chemin existant est ouvert
/// (le mode est ensuite choisi selon le contenu).
fn parse_requests(args: impl IntoIterator<Item = String>, cwd: &Path) -> Vec<OpenRequest> {
    let resolve = |a: &str| {
        let p = PathBuf::from(a);
        let p = if p.is_absolute() { p } else { cwd.join(p) };
        (p.is_file() || p.is_dir()).then(|| p.to_string_lossy().into_owned())
    };
    let mut out = Vec::new();
    let mut encrypt_next = false;
    for a in args {
        if a == "--encrypt" {
            encrypt_next = true;
        } else if a.starts_with('-') {
            encrypt_next = false;
        } else if let Some(path) = resolve(&a) {
            out.push(OpenRequest {
                action: if encrypt_next { "encrypt" } else { "open" },
                path,
            });
            encrypt_next = false;
        }
    }
    out
}

fn queue_requests(app: &AppHandle, requests: Vec<OpenRequest>) {
    if requests.is_empty() {
        return;
    }
    if let Ok(mut pending) = app.state::<AppState>().pending.lock() {
        pending.extend(requests);
    }
    // L'interface vient alors chercher la file (évite toute perte si elle n'est pas prête)
    let _ = app.emit("open-requests", ());
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let cwd = std::env::current_dir().unwrap_or_default();
    let state = AppState::default();
    *state.pending.lock().expect("verrou") = parse_requests(std::env::args().skip(1), &cwd);

    let app = tauri::Builder::default()
        // Doit être le premier plugin : une seule instance ; les fichiers ouverts
        // ensuite (double-clic, clic droit) sont transmis à la fenêtre existante.
        .plugin(tauri_plugin_single_instance::init(|app, argv, cwd| {
            queue_requests(app, parse_requests(argv.into_iter().skip(1), Path::new(&cwd)));
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(|app| {
            // Nettoyage des temporaires d'une exécution interrompue
            if let Ok(dir) = app.path().app_local_data_dir() {
                let removed = app
                    .state::<AppState>()
                    .journal
                    .init(dir.join("temp-files.txt"));
                if removed > 0 {
                    eprintln!("Securio : {removed} temporaire(s) d'une exécution interrompue supprimé(s).");
                }
            }
            // Expiration des sessions inactives
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(15));
                let state = handle.state::<AppState>();
                let expired = match state.session.lock() {
                    Ok(mut slot)
                        if slot
                            .as_ref()
                            .is_some_and(|s| s.last_used.elapsed() > SESSION_TTL) =>
                    {
                        slot.take();
                        true
                    }
                    _ => false,
                };
                if expired {
                    let _ = handle.emit("session-expired", ());
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::inspect_file,
            commands::encrypt_file,
            commands::encrypt_separately,
            commands::encrypt_archive,
            commands::open_encrypted,
            commands::save_decrypted,
            commands::extract_archive,
            commands::preview,
            commands::convert_to_v3,
            commands::close_session,
            commands::decrypt_many,
            commands::generate_passphrase,
            commands::take_pending_requests,
        ])
        .build(tauri::generate_context!())
        .expect("erreur au démarrage de Securio");

    app.run(|_app, _event| {
        // macOS : ouverture d'un fichier depuis le Finder
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Opened { urls } = &_event {
            let requests = urls
                .iter()
                .filter_map(|u| u.to_file_path().ok())
                .map(|p| OpenRequest {
                    action: "open",
                    path: p.to_string_lossy().into_owned(),
                })
                .collect();
            queue_requests(_app, requests);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn command_line_requests() {
        let dir = std::env::temp_dir().join(format!("securio-args-{}", std::process::id()));
        fs::create_dir_all(dir.join("dossier")).unwrap();
        let enc = dir.join("a.pdf.encrypted");
        let doc = dir.join("b.docx");
        fs::write(&enc, b"x").unwrap();
        fs::write(&doc, b"x").unwrap();
        let s = |p: &Path| p.to_string_lossy().into_owned();
        let args = vec![
            "--flag".to_string(),
            s(&enc),
            "--encrypt".into(),
            s(&doc),
            "--encrypt".into(),
            "dossier".into(), // relatif au dossier courant
            "absent.encrypted".into(),
            "--encrypt".into(),
            "--autre".into(),
            s(&doc),
        ];
        assert_eq!(
            parse_requests(args, &dir),
            vec![
                OpenRequest {
                    action: "open",
                    path: s(&enc)
                },
                OpenRequest {
                    action: "encrypt",
                    path: s(&doc)
                },
                OpenRequest {
                    action: "encrypt",
                    path: s(&dir.join("dossier"))
                },
                OpenRequest {
                    action: "open",
                    path: s(&doc)
                },
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
