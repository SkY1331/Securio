//! Application Tauri de Securio.
//!
//! Toute la cryptographie est faite ici, en Rust (crate `securio-core`). L'interface
//! web ne manipule que des chemins de fichiers et des mots de passe : le contenu
//! des fichiers ne transite jamais par le WebView.

use securio_core::{self as core, v3, Inspection, LegacyOptions};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tauri::ipc::Channel;
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

/// Durée d'inactivité après laquelle le contenu déchiffré (v1/v2) ou la clé (v3)
/// sont effacés de la mémoire.
const SESSION_TTL: Duration = Duration::from_secs(5 * 60);
const TEMP_SUFFIX: &str = ".securio-tmp";

/// Taille maximale d'un fichier v1/v2 (déchiffrés en mémoire).
const MAX_LEGACY_SIZE: u64 = 2 * 1024 * 1024 * 1024;

type CmdResult<T> = Result<T, String>;

fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

// ---------------------------------------------------------------------------
// État
// ---------------------------------------------------------------------------

/// Fichier déchiffré en attente d'enregistrement. Les secrets (clé v3, contenu
/// v1/v2) sont effacés de la mémoire quand la session est détruite.
enum Session {
    InMemory(core::Decrypted),
    V3 { path: PathBuf, opened: v3::Opened },
}

struct SessionSlot {
    id: u64,
    session: Arc<Session>,
    last_used: Instant,
}

#[derive(Default)]
struct AppState {
    launch_files: Mutex<Vec<String>>,
    /// Une seule session à la fois : ouvrir un autre fichier efface la précédente.
    session: Mutex<Option<SessionSlot>>,
    next_id: AtomicU64,
    journal: TempJournal,
}

/// Journal des fichiers temporaires en cours d'écriture. Si l'application est
/// interrompue (coupure, plantage), ceux qui restent — qui peuvent contenir un
/// début de fichier déchiffré — sont supprimés au démarrage suivant.
#[derive(Default)]
struct TempJournal {
    path: Mutex<Option<PathBuf>>,
}

impl TempJournal {
    fn entries(path: &Path) -> Vec<PathBuf> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(PathBuf::from)
            .collect()
    }

    fn save(path: &Path, entries: &[PathBuf]) {
        let text: String = entries
            .iter()
            .map(|p| format!("{}\n", p.display()))
            .collect();
        let _ = fs::write(path, text);
    }

    fn add(&self, tmp: &Path) {
        if let Ok(guard) = self.path.lock() {
            if let Some(j) = guard.as_ref() {
                let mut e = Self::entries(j);
                e.push(tmp.to_path_buf());
                Self::save(j, &e);
            }
        }
    }

    fn remove(&self, tmp: &Path) {
        if let Ok(guard) = self.path.lock() {
            if let Some(j) = guard.as_ref() {
                let e: Vec<PathBuf> = Self::entries(j).into_iter().filter(|p| p != tmp).collect();
                Self::save(j, &e);
            }
        }
    }

    /// Active le journal et supprime les temporaires laissés par une exécution interrompue.
    /// Renvoie le nombre de fichiers supprimés.
    fn init(&self, journal: PathBuf) -> usize {
        let mut removed = 0;
        for p in Self::entries(&journal) {
            let ours = p
                .file_name()
                .map(|n| n.to_string_lossy().ends_with(TEMP_SUFFIX))
                .unwrap_or(false);
            if ours && p.is_file() && fs::remove_file(&p).is_ok() {
                removed += 1;
            }
        }
        if let Some(dir) = journal.parent() {
            let _ = fs::create_dir_all(dir);
        }
        Self::save(&journal, &[]);
        if let Ok(mut g) = self.path.lock() {
            *g = Some(journal);
        }
        removed
    }
}

// ---------------------------------------------------------------------------
// Utilitaires
// ---------------------------------------------------------------------------

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// Écrit dans un fichier temporaire du même dossier, puis le renomme : en cas
/// d'erreur (clé incorrecte, fichier altéré, disque plein…), aucun fichier
/// partiel n'est laissé à la place de la cible.
fn write_atomically(
    journal: &TempJournal,
    target: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> core::Result<()>,
) -> CmdResult<()> {
    let dir = target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut rnd = [0u8; 6];
    getrandom::getrandom(&mut rnd).map_err(err)?;
    let suffix: String = rnd.iter().map(|b| format!("{b:02x}")).collect();
    let tmp = dir.join(format!(".{}.{suffix}{TEMP_SUFFIX}", file_name(target)));

    journal.add(&tmp);
    let result = write_to_temp(&tmp, target, write);
    journal.remove(&tmp);
    result
}

fn write_to_temp(
    tmp: &Path,
    target: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> core::Result<()>,
) -> CmdResult<()> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp)
        .map_err(err)?;
    let mut writer = BufWriter::with_capacity(1 << 20, file);
    let result = write(&mut writer)
        .and_then(|_| writer.flush().map_err(core::Error::from))
        .and_then(|_| writer.get_ref().sync_all().map_err(core::Error::from));
    drop(writer);
    match result {
        Ok(()) => fs::rename(tmp, target).map_err(|e| {
            let _ = fs::remove_file(tmp);
            err(e)
        }),
        Err(e) => {
            let _ = fs::remove_file(tmp);
            Err(err(e))
        }
    }
}

/// Envoie la progression au plus toutes les 100 ms.
fn throttled(channel: Channel<u64>) -> impl FnMut(u64) {
    let mut last = Instant::now() - Duration::from_secs(1);
    move |n| {
        if last.elapsed() >= Duration::from_millis(100) {
            last = Instant::now();
            let _ = channel.send(n);
        }
    }
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(err)?
}

// ---------------------------------------------------------------------------
// Commandes
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FileSummary {
    path: String,
    name: String,
    size: u64,
    inspection: Option<Inspection>,
}

/// Identifie un fichier (Securio v1/v2/v3 ou fichier ordinaire).
#[tauri::command]
async fn inspect_file(path: String) -> CmdResult<FileSummary> {
    blocking(move || {
        let p = PathBuf::from(&path);
        let meta = fs::metadata(&p).map_err(err)?;
        if !meta.is_file() {
            return Err("Ce n'est pas un fichier.".into());
        }
        let mut probe = vec![0u8; core::PROBE_LEN];
        let n = File::open(&p)
            .and_then(|mut f| f.read(&mut probe))
            .map_err(err)?;
        Ok(FileSummary {
            name: file_name(&p),
            size: meta.len(),
            inspection: core::inspect(&probe[..n], meta.len()),
            path,
        })
    })
    .await
}

/// Chiffre `input` vers `output` au format v3.
#[tauri::command]
async fn encrypt_file(
    app: AppHandle,
    input: String,
    output: String,
    password: String,
    on_progress: Channel<u64>,
) -> CmdResult<String> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let (inp, out) = (PathBuf::from(&input), PathBuf::from(&output));
        if same_file(&inp, &out) {
            return Err("Le fichier chiffré ne peut pas remplacer le fichier d'origine.".into());
        }
        let file = File::open(&inp).map_err(err)?;
        let size = file.metadata().map_err(err)?.len();
        let meta = core::Metadata {
            name: file_name(&inp),
            mime: mime_from_name(&file_name(&inp)),
            size,
        };
        let mut progress = throttled(on_progress.clone());
        write_atomically(journal, &out, |w| {
            v3::encrypt(
                file,
                w,
                &password,
                &meta,
                &v3::Params::default(),
                &mut progress,
            )
        })?;
        let _ = on_progress.send(size);
        Ok(output)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VariantSummary {
    label: String,
    name: String,
    mime: String,
    size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OpenedSummary {
    session: u64,
    format: &'static str,
    algorithm: &'static str,
    warnings: Vec<String>,
    variants: Vec<VariantSummary>,
}

/// Vérifie la clé et prépare le déchiffrement. Pour v1/v2 le fichier est
/// déchiffré en mémoire ; pour v3 seules les métadonnées le sont (le contenu est
/// déchiffré en flux lors de l'enregistrement).
#[tauri::command]
async fn open_encrypted(
    state: State<'_, AppState>,
    path: String,
    password: String,
    algorithm: Option<String>,
) -> CmdResult<OpenedSummary> {
    let password = Zeroizing::new(password);
    // Efface la session précédente avant d'en ouvrir une autre
    state.session.lock().map_err(err)?.take();

    let (session, summary) = blocking(move || {
        let p = PathBuf::from(&path);
        let mut file = File::open(&p).map_err(err)?;
        let size = file.metadata().map_err(err)?.len();
        let mut probe = vec![0u8; core::PROBE_LEN];
        let n = file.read(&mut probe).map_err(err)?;
        file.seek(SeekFrom::Start(0)).map_err(err)?;

        match core::inspect(&probe[..n], size) {
            Some(Inspection::V3(_)) => {
                let opened = v3::open(&mut file, &password).map_err(err)?;
                let summary = OpenedSummary {
                    session: 0,
                    format: "v3",
                    algorithm: "argon2id + aes-256-gcm",
                    warnings: core::name_warnings(&opened.meta.name),
                    variants: vec![VariantSummary {
                        label: "Fichier déchiffré".into(),
                        name: core::sanitize_file_name(&opened.meta.name),
                        mime: opened.meta.mime.clone(),
                        size: opened.meta.size,
                    }],
                };
                Ok((Session::V3 { path: p, opened }, summary))
            }
            Some(_) => {
                if size > MAX_LEGACY_SIZE {
                    return Err("Fichier ancien format trop volumineux (2 Go maximum).".into());
                }
                let mut bytes = Vec::with_capacity(size as usize);
                file.read_to_end(&mut bytes).map_err(err)?;
                let opts = LegacyOptions {
                    algorithm: algorithm.filter(|a| a != "auto"),
                    outer_name: Some(file_name(&p)),
                };
                let d = core::decrypt_legacy(&bytes, &password, &opts).map_err(err)?;
                let summary = OpenedSummary {
                    session: 0,
                    format: d.format,
                    algorithm: d.algorithm,
                    warnings: d.warnings.clone(),
                    variants: d
                        .variants
                        .iter()
                        .map(|v| VariantSummary {
                            label: v.label.clone(),
                            name: v.name.clone(),
                            mime: v.mime.clone(),
                            size: v.content.len() as u64,
                        })
                        .collect(),
                };
                Ok((Session::InMemory(d), summary))
            }
            None => Err(core::Error::NotSecurio.to_string()),
        }
    })
    .await?;

    let id = state.next_id.fetch_add(1, Ordering::Relaxed) + 1;
    *state.session.lock().map_err(err)? = Some(SessionSlot {
        id,
        session: Arc::new(session),
        last_used: Instant::now(),
    });
    Ok(OpenedSummary {
        session: id,
        ..summary
    })
}

/// Enregistre une version déchiffrée de la session courante.
#[tauri::command]
async fn save_decrypted(
    app: AppHandle,
    state: State<'_, AppState>,
    session: u64,
    variant: usize,
    output: String,
    on_progress: Channel<u64>,
) -> CmdResult<String> {
    let current = match &mut *state.session.lock().map_err(err)? {
        Some(slot) if slot.id == session => {
            slot.last_used = Instant::now();
            slot.session.clone()
        }
        _ => {
            return Err(
                "Session expirée : saisissez à nouveau la clé et déchiffrez le fichier.".into(),
            )
        }
    };
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let out = PathBuf::from(&output);
        match &*current {
            Session::InMemory(d) => {
                let v = d.variants.get(variant).ok_or("Version inconnue.")?;
                write_atomically(journal, &out, |w| {
                    w.write_all(&v.content).map_err(core::Error::from)
                })?;
            }
            Session::V3 { path, opened } => {
                if same_file(path, &out) {
                    return Err(
                        "Le fichier déchiffré ne peut pas remplacer le fichier chiffré.".into(),
                    );
                }
                let mut file = File::open(path).map_err(err)?;
                file.seek(SeekFrom::Start(opened.header.data_offset()))
                    .map_err(err)?;
                let mut progress = throttled(on_progress.clone());
                write_atomically(journal, &out, |w| {
                    opened.decrypt_to(file, w, &mut progress).map(|_| ())
                })?;
                let _ = on_progress.send(opened.meta.size);
            }
        }
        Ok(output)
    })
    .await
}

/// Efface la session (et donc les secrets en mémoire).
#[tauri::command]
fn close_session(state: State<'_, AppState>) -> CmdResult<()> {
    state.session.lock().map_err(err)?.take();
    Ok(())
}

/// Fichiers .encrypted passés au lancement (double-clic, « Ouvrir avec »).
#[tauri::command]
fn launch_files(state: State<'_, AppState>) -> CmdResult<Vec<String>> {
    Ok(state.launch_files.lock().map_err(err)?.clone())
}

// ---------------------------------------------------------------------------

fn mime_from_name(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "txt" => "text/plain",
        "csv" => "text/csv",
        "json" => "application/json",
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
    .into()
}

fn encrypted_paths(args: impl IntoIterator<Item = String>, cwd: &Path) -> Vec<String> {
    args.into_iter()
        .filter(|a| !a.starts_with('-') && a.to_lowercase().ends_with(core::ENCRYPTED_EXTENSION))
        .map(|a| {
            let p = PathBuf::from(&a);
            if p.is_absolute() {
                p
            } else {
                cwd.join(p)
            }
        })
        .filter(|p| p.is_file())
        .map(|p| p.to_string_lossy().into_owned())
        .collect()
}

fn focus_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let cwd = std::env::current_dir().unwrap_or_default();
    let state = AppState::default();
    *state.launch_files.lock().expect("verrou") = encrypted_paths(std::env::args().skip(1), &cwd);

    let app = tauri::Builder::default()
        // Doit être le premier plugin : une seule instance, les fichiers ouverts
        // ensuite (double-clic) sont transmis à la fenêtre existante.
        .plugin(tauri_plugin_single_instance::init(|app, argv, cwd| {
            for p in encrypted_paths(argv.into_iter().skip(1), Path::new(&cwd)) {
                let _ = app.emit("open-file", p);
            }
            focus_main(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .manage(state)
        .setup(|app| {
            // Nettoyage des temporaires d'une exécution interrompue
            if let Ok(dir) = app.path().app_local_data_dir() {
                let removed = app.state::<AppState>().journal.init(dir.join("temp-files.txt"));
                if removed > 0 {
                    eprintln!("Securio : {removed} fichier(s) temporaire(s) d'une exécution interrompue supprimé(s).");
                }
            }
            // Expiration des sessions inactives
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(15));
                let state = handle.state::<AppState>();
                let expired = match state.session.lock() {
                    Ok(mut slot) if slot.as_ref().is_some_and(|s| s.last_used.elapsed() > SESSION_TTL) => {
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
            inspect_file,
            encrypt_file,
            open_encrypted,
            save_decrypted,
            close_session,
            launch_files
        ])
        .build(tauri::generate_context!())
        .expect("erreur au démarrage de Securio");

    app.run(|_app, _event| {
        // macOS : ouverture d'un fichier depuis le Finder
        #[cfg(target_os = "macos")]
        if let tauri::RunEvent::Opened { urls } = &_event {
            for url in urls {
                if let Ok(p) = url.to_file_path() {
                    let _ = _app.emit("open-file", p.to_string_lossy().into_owned());
                }
            }
            focus_main(_app);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_leaves_nothing_on_error() {
        let dir = std::env::temp_dir().join(format!("securio-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("out.bin");
        let journal = TempJournal::default();
        let r = write_atomically(&journal, &target, |w| {
            w.write_all(b"partiel").unwrap();
            Err(core::Error::Corrupted("test".into()))
        });
        assert!(r.is_err());
        assert!(!target.exists());
        assert_eq!(
            fs::read_dir(&dir).unwrap().count(),
            0,
            "aucun fichier temporaire ne doit rester"
        );

        write_atomically(&journal, &target, |w| {
            w.write_all(b"ok").map_err(core::Error::from)
        })
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ok");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn interrupted_temp_files_are_removed_at_startup() {
        let dir = std::env::temp_dir().join(format!("securio-journal-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let leftover = dir.join(format!(".secret.pdf.abcdef{TEMP_SUFFIX}"));
        let foreign = dir.join("document-utilisateur.pdf");
        fs::write(&leftover, b"debut du fichier dechiffre").unwrap();
        fs::write(&foreign, b"a garder").unwrap();
        let journal_file = dir.join("temp-files.txt");
        TempJournal::save(&journal_file, &[leftover.clone(), foreign.clone()]);

        let journal = TempJournal::default();
        assert_eq!(journal.init(journal_file.clone()), 1);
        assert!(
            !leftover.exists(),
            "le temporaire orphelin doit être supprimé"
        );
        assert!(
            foreign.exists(),
            "un fichier qui n'est pas un temporaire Securio ne doit jamais être supprimé"
        );
        assert!(TempJournal::entries(&journal_file).is_empty());

        // pendant une écriture, le temporaire est journalisé, puis retiré
        let target = dir.join("out.bin");
        write_atomically(&journal, &target, |_| {
            assert_eq!(TempJournal::entries(&journal_file).len(), 1);
            Ok(())
        })
        .unwrap();
        assert!(TempJournal::entries(&journal_file).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn launch_args() {
        let dir = std::env::temp_dir();
        let f = dir.join(format!("securio-launch-{}.encrypted", std::process::id()));
        fs::write(&f, b"x").unwrap();
        let args = vec![
            "--flag".to_string(),
            f.to_string_lossy().into_owned(),
            "autre.txt".into(),
            "absent.encrypted".into(),
        ];
        assert_eq!(
            encrypted_paths(args, &dir),
            vec![f.to_string_lossy().into_owned()]
        );
        fs::remove_file(&f).unwrap();
    }
}
