//! Commandes appelées par l'interface. Toute la cryptographie est faite ici, en
//! Rust : l'interface ne manipule que des chemins et des mots de passe, sauf pour
//! l'aperçu, qui lui transmet le contenu déchiffré en mémoire (jamais sur disque).

use crate::files::{
    err, file_name, fill_dir_atomically, mime_from_name, same_file, unique_path, write_atomically,
    CmdResult, TempJournal,
};
use crate::{AppState, OpenRequest, Session, SessionSlot};
use securio_core::{self as core, archive, v3, Inspection, LegacyOptions};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::ipc::{Channel, Response};
use tauri::{AppHandle, Manager, State};
use zeroize::Zeroizing;

/// Taille maximale d'un fichier v1/v2 (déchiffrés en mémoire).
const MAX_LEGACY_SIZE: u64 = 2 * 1024 * 1024 * 1024;
/// Taille maximale d'un aperçu (le contenu est transmis à l'interface en mémoire).
const MAX_PREVIEW_SIZE: u64 = 64 * 1024 * 1024;

async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> CmdResult<T> + Send + 'static,
) -> CmdResult<T> {
    tauri::async_runtime::spawn_blocking(f).await.map_err(err)?
}

/// Limite la fréquence des messages de progression (100 ms).
struct Throttle(Instant);
impl Throttle {
    fn new() -> Self {
        Throttle(Instant::now() - Duration::from_secs(1))
    }
    fn ready(&mut self) -> bool {
        let ok = self.0.elapsed() >= Duration::from_millis(100);
        if ok {
            self.0 = Instant::now();
        }
        ok
    }
}

fn throttled(channel: Channel<u64>) -> impl FnMut(u64) {
    let mut t = Throttle::new();
    move |n| {
        if t.ready() {
            let _ = channel.send(n);
        }
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BatchProgress {
    index: usize,
    count: usize,
    name: String,
    done: u64,
    total: u64,
}

fn read_probe(file: &mut File) -> io::Result<Vec<u8>> {
    let mut probe = vec![0u8; core::PROBE_LEN];
    let n = file.read(&mut probe)?;
    probe.truncate(n);
    file.seek(SeekFrom::Start(0))?;
    Ok(probe)
}

fn encrypt_one(
    journal: &TempJournal,
    input: &Path,
    output: &Path,
    password: &str,
    progress: impl FnMut(u64),
) -> CmdResult<u64> {
    if same_file(input, output) {
        return Err("Le fichier chiffré ne peut pas remplacer le fichier d'origine.".into());
    }
    let file = File::open(input).map_err(err)?;
    let size = file.metadata().map_err(err)?.len();
    let name = file_name(input);
    let meta = core::Metadata {
        mime: mime_from_name(&name),
        name,
        size,
    };
    let mut progress = progress;
    write_atomically(journal, output, |w| {
        v3::encrypt(
            file,
            w,
            password,
            &meta,
            &v3::Params::default(),
            &mut progress,
        )
    })?;
    Ok(size)
}

/// Relit entièrement un fichier v3 (clé + intégrité de chaque segment).
fn verify_v3(path: &Path, password: &str) -> CmdResult<()> {
    let mut f = File::open(path).map_err(err)?;
    let opened = v3::open(&mut f, password).map_err(err)?;
    opened.decrypt_to(f, io::sink(), |_| {}).map_err(err)?;
    Ok(())
}

/// Vérifie le fichier chiffré, puis écrase et supprime l'original.
fn verify_then_wipe(encrypted: &Path, password: &str, original: &Path) -> CmdResult<()> {
    verify_v3(encrypted, password).map_err(|e| {
        format!("Vérification du fichier chiffré impossible ({e}) : l'original a été conservé.")
    })?;
    core::wipe::wipe_and_remove(original)
        .map_err(|e| format!("Suppression de l'original impossible : {e}"))
}

// ---------------------------------------------------------------------------
// Identification
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FileSummary {
    path: String,
    name: String,
    size: u64,
    is_dir: bool,
    file_count: u64,
    inspection: Option<Inspection>,
}

/// Identifie un fichier (Securio v1/v2/v3 ou ordinaire) ou un dossier.
#[tauri::command]
pub async fn inspect_file(path: String) -> CmdResult<FileSummary> {
    blocking(move || {
        let p = PathBuf::from(&path);
        let meta = fs::symlink_metadata(&p).map_err(err)?;
        if meta.is_dir() {
            let (_, summary) = archive::collect(std::slice::from_ref(&p)).map_err(err)?;
            return Ok(FileSummary {
                name: file_name(&p),
                size: summary.bytes,
                is_dir: true,
                file_count: summary.files,
                inspection: None,
                path,
            });
        }
        if !meta.is_file() {
            return Err("Ni un fichier ni un dossier (lien ou fichier spécial).".into());
        }
        let mut f = File::open(&p).map_err(err)?;
        let probe = read_probe(&mut f).map_err(err)?;
        Ok(FileSummary {
            name: file_name(&p),
            size: meta.len(),
            is_dir: false,
            file_count: 1,
            inspection: core::inspect(&probe, meta.len()),
            path,
        })
    })
    .await
}

// ---------------------------------------------------------------------------
// Chiffrement
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptResult {
    output: String,
    original_deleted: bool,
}

/// Chiffre un fichier au format v3 ; supprime ensuite l'original si demandé
/// (après relecture complète du fichier chiffré).
#[tauri::command]
pub async fn encrypt_file(
    app: AppHandle,
    input: String,
    output: String,
    password: String,
    delete_original: bool,
    on_progress: Channel<u64>,
) -> CmdResult<EncryptResult> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let (inp, out) = (PathBuf::from(&input), PathBuf::from(&output));
        let size = encrypt_one(
            journal,
            &inp,
            &out,
            &password,
            throttled(on_progress.clone()),
        )?;
        let _ = on_progress.send(size);
        if delete_original {
            verify_then_wipe(&out, &password, &inp)?;
        }
        Ok(EncryptResult {
            output,
            original_deleted: delete_original,
        })
    })
    .await
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ItemResult {
    input: String,
    output: Option<String>,
    error: Option<String>,
    original_deleted: bool,
    warnings: Vec<String>,
}

/// Chiffre plusieurs fichiers, chacun à côté de son original (`nom.encrypted`).
#[tauri::command]
pub async fn encrypt_separately(
    app: AppHandle,
    inputs: Vec<String>,
    password: String,
    delete_originals: bool,
    on_progress: Channel<BatchProgress>,
) -> CmdResult<Vec<ItemResult>> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let sizes: Vec<u64> = inputs
            .iter()
            .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .collect();
        let total: u64 = sizes.iter().sum();
        let count = inputs.len();
        let mut before = 0u64;
        let mut results = Vec::with_capacity(count);
        for (index, input) in inputs.into_iter().enumerate() {
            let inp = PathBuf::from(&input);
            let name = file_name(&inp);
            let mut item = ItemResult { input: input.clone(), ..Default::default() };
            let outcome = (|| -> CmdResult<PathBuf> {
                if !inp.is_file() {
                    return Err("Seuls les fichiers peuvent être chiffrés séparément (utilisez une archive pour les dossiers).".into());
                }
                let dir = inp.parent().unwrap_or(Path::new("."));
                let out = unique_path(dir, &format!("{name}{}", core::ENCRYPTED_EXTENSION));
                let mut t = Throttle::new();
                let ch = on_progress.clone();
                let nm = name.clone();
                encrypt_one(journal, &inp, &out, &password, move |n| {
                    if t.ready() {
                        let _ = ch.send(BatchProgress { index, count, name: nm.clone(), done: before + n, total });
                    }
                })?;
                Ok(out)
            })();
            match outcome {
                Ok(out) => {
                    item.output = Some(out.to_string_lossy().into_owned());
                    if delete_originals {
                        match verify_then_wipe(&out, &password, &inp) {
                            Ok(()) => item.original_deleted = true,
                            Err(e) => item.warnings.push(e),
                        }
                    }
                }
                Err(e) => item.error = Some(e),
            }
            before += sizes[index];
            let _ = on_progress.send(BatchProgress { index, count, name, done: before, total });
            results.push(item);
        }
        Ok(results)
    })
    .await
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ArchiveResult {
    output: String,
    summary: archive::Summary,
    originals_deleted: u64,
    warnings: Vec<String>,
}

/// Regroupe fichiers et dossiers dans une seule archive chiffrée (tar dans un v3).
#[tauri::command]
pub async fn encrypt_archive(
    app: AppHandle,
    inputs: Vec<String>,
    output: String,
    password: String,
    delete_originals: bool,
    on_progress: Channel<u64>,
) -> CmdResult<ArchiveResult> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let paths: Vec<PathBuf> = inputs.iter().map(PathBuf::from).collect();
        let out = PathBuf::from(&output);
        if paths.iter().any(|p| same_file(p, &out)) {
            return Err("L'archive ne peut pas remplacer un des éléments à chiffrer.".into());
        }
        let (entries, summary) = archive::collect(&paths).map_err(err)?;
        let size = archive::archive_size(&entries).map_err(err)?;
        let inner_name = file_name(&out)
            .strip_suffix(core::ENCRYPTED_EXTENSION)
            .map(str::to_string)
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| archive::default_name(&paths));
        let meta = core::Metadata {
            name: inner_name,
            mime: archive::MIME.into(),
            size,
        };

        // L'archive est produite à la volée dans un tube et chiffrée au fil de l'eau :
        // aucune copie en clair n'est écrite sur le disque.
        let (reader, writer) = io::pipe().map_err(err)?;
        let producer = std::thread::spawn(move || archive::write_archive(&entries, writer));
        let mut progress = throttled(on_progress.clone());
        let encrypted = write_atomically(journal, &out, |w| {
            v3::encrypt(
                reader,
                w,
                &password,
                &meta,
                &v3::Params::default(),
                &mut progress,
            )
        });
        let produced = producer
            .join()
            .map_err(|_| "Erreur interne lors de l'archivage.".to_string())?;
        produced.map_err(|e| format!("Archivage impossible : {e}"))?;
        encrypted?;
        let _ = on_progress.send(size);

        let mut warnings = Vec::new();
        let mut originals_deleted = 0;
        if summary.skipped > 0 {
            warnings.push(format!(
                "{} lien(s) symbolique(s) ou fichier(s) spécial(aux) ignoré(s).",
                summary.skipped
            ));
        }
        if delete_originals {
            if paths.iter().any(|p| p.is_dir()) {
                warnings.push(
                    "Les dossiers d'origine ne sont jamais supprimés automatiquement.".into(),
                );
            } else if let Err(e) = verify_v3(&out, &password) {
                warnings.push(format!(
                    "Vérification impossible ({e}) : originaux conservés."
                ));
            } else {
                for p in &paths {
                    match core::wipe::wipe_and_remove(p) {
                        Ok(()) => originals_deleted += 1,
                        Err(e) => warnings
                            .push(format!("{} : suppression impossible ({e}).", file_name(p))),
                    }
                }
            }
        }
        Ok(ArchiveResult {
            output,
            summary,
            originals_deleted,
            warnings,
        })
    })
    .await
}

// ---------------------------------------------------------------------------
// Déchiffrement d'un fichier (session)
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VariantSummary {
    label: String,
    name: String,
    mime: String,
    size: u64,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenedSummary {
    session: u64,
    format: &'static str,
    algorithm: &'static str,
    warnings: Vec<String>,
    variants: Vec<VariantSummary>,
    is_archive: bool,
}

fn open_session(
    path: &Path,
    password: &str,
    algorithm: Option<String>,
) -> CmdResult<(Session, OpenedSummary)> {
    let mut file = File::open(path).map_err(err)?;
    let size = file.metadata().map_err(err)?.len();
    let probe = read_probe(&mut file).map_err(err)?;
    match core::inspect(&probe, size) {
        Some(Inspection::V3(_)) => {
            let opened = v3::open(&mut file, password).map_err(err)?;
            let is_archive = opened.meta.mime == archive::MIME;
            let summary = OpenedSummary {
                session: 0,
                format: "v3",
                algorithm: "argon2id + aes-256-gcm",
                warnings: core::name_warnings(&opened.meta.name),
                variants: vec![VariantSummary {
                    label: if is_archive {
                        "Archive (.tar)".into()
                    } else {
                        "Fichier déchiffré".into()
                    },
                    name: core::sanitize_file_name(&opened.meta.name),
                    mime: opened.meta.mime.clone(),
                    size: opened.meta.size,
                }],
                is_archive,
            };
            Ok((
                Session::V3 {
                    path: path.to_path_buf(),
                    opened,
                },
                summary,
            ))
        }
        Some(Inspection::Future { version }) => {
            Err(core::Error::FutureVersion(version).to_string())
        }
        Some(_) => {
            if size > MAX_LEGACY_SIZE {
                return Err("Fichier ancien format trop volumineux (2 Go maximum).".into());
            }
            let mut bytes = Zeroizing::new(Vec::with_capacity(size as usize));
            file.read_to_end(&mut bytes).map_err(err)?;
            let opts = LegacyOptions {
                algorithm: algorithm.filter(|a| a != "auto"),
                outer_name: Some(file_name(path)),
            };
            let d = core::decrypt_legacy(&bytes, password, &opts).map_err(err)?;
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
                is_archive: false,
            };
            Ok((Session::InMemory(d), summary))
        }
        None => Err(core::Error::NotSecurio.to_string()),
    }
}

/// Vérifie la clé et prépare le déchiffrement. v1/v2 : déchiffré en mémoire ;
/// v3 : seules les métadonnées le sont (le contenu l'est en flux à l'enregistrement).
#[tauri::command]
pub async fn open_encrypted(
    state: State<'_, AppState>,
    path: String,
    password: String,
    algorithm: Option<String>,
) -> CmdResult<OpenedSummary> {
    let password = Zeroizing::new(password);
    state.session.lock().map_err(err)?.take();
    let (session, summary) =
        blocking(move || open_session(Path::new(&path), &password, algorithm)).await?;
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

fn current_session(state: &AppState, session: u64) -> CmdResult<Arc<Session>> {
    match &mut *state.session.lock().map_err(err)? {
        Some(slot) if slot.id == session => {
            slot.last_used = Instant::now();
            Ok(slot.session.clone())
        }
        _ => Err("Session expirée : saisissez à nouveau la clé et déchiffrez le fichier.".into()),
    }
}

/// Enregistre une version déchiffrée de la session courante.
#[tauri::command]
pub async fn save_decrypted(
    app: AppHandle,
    state: State<'_, AppState>,
    session: u64,
    variant: usize,
    output: String,
    on_progress: Channel<u64>,
) -> CmdResult<String> {
    let current = current_session(&state, session)?;
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

fn extract_v3_archive(
    journal: &TempJournal,
    path: &Path,
    opened: &v3::Opened,
    parent: &Path,
    progress: impl FnMut(u64) + Send,
) -> CmdResult<(PathBuf, archive::Summary)> {
    let name = opened
        .meta
        .name
        .strip_suffix(archive::EXTENSION)
        .unwrap_or(&opened.meta.name)
        .to_string();
    let name = core::sanitize_file_name(&name);
    let mut summary = archive::Summary::default();
    let dir = fill_dir_atomically(journal, parent, &name, |tmp| {
        let mut file = File::open(path).map_err(err)?;
        file.seek(SeekFrom::Start(opened.header.data_offset()))
            .map_err(err)?;
        let (reader, writer) = io::pipe().map_err(err)?;
        // Déchiffrement et extraction en parallèle, sans archive en clair sur le disque
        std::thread::scope(|scope| {
            let producer = scope.spawn(move || opened.decrypt_to(file, writer, progress));
            let extracted = archive::extract(reader, tmp);
            let decrypted = producer
                .join()
                .map_err(|_| "Erreur interne lors du déchiffrement.".to_string())?;
            decrypted.map_err(err)?;
            summary = extracted.map_err(|e| format!("Extraction impossible : {e}"))?;
            Ok(())
        })
    })?;
    Ok((dir, summary))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtractResult {
    output: String,
    summary: archive::Summary,
}

/// Extrait l'archive chiffrée de la session courante dans `parent/nom`.
#[tauri::command]
pub async fn extract_archive(
    app: AppHandle,
    state: State<'_, AppState>,
    session: u64,
    parent: String,
    on_progress: Channel<u64>,
) -> CmdResult<ExtractResult> {
    let current = current_session(&state, session)?;
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        match &*current {
            Session::V3 { path, opened } if opened.meta.mime == archive::MIME => {
                let (dir, summary) = extract_v3_archive(
                    journal,
                    path,
                    opened,
                    Path::new(&parent),
                    throttled(on_progress.clone()),
                )?;
                let _ = on_progress.send(opened.meta.size);
                Ok(ExtractResult {
                    output: dir.to_string_lossy().into_owned(),
                    summary,
                })
            }
            _ => Err("Ce fichier n'est pas une archive Securio.".into()),
        }
    })
    .await
}

/// Contenu déchiffré, en mémoire, pour l'aperçu (jamais écrit sur le disque).
#[tauri::command]
pub async fn preview(
    state: State<'_, AppState>,
    session: u64,
    variant: usize,
) -> CmdResult<Response> {
    let current = current_session(&state, session)?;
    blocking(move || {
        let bytes = match &*current {
            Session::InMemory(d) => {
                let v = d.variants.get(variant).ok_or("Version inconnue.")?;
                if v.content.len() as u64 > MAX_PREVIEW_SIZE {
                    return Err("Fichier trop volumineux pour l'aperçu (64 Mo maximum).".into());
                }
                v.content.to_vec()
            }
            Session::V3 { path, opened } => {
                if opened.meta.size > MAX_PREVIEW_SIZE {
                    return Err("Fichier trop volumineux pour l'aperçu (64 Mo maximum).".into());
                }
                let mut file = File::open(path).map_err(err)?;
                file.seek(SeekFrom::Start(opened.header.data_offset()))
                    .map_err(err)?;
                let mut out = Vec::with_capacity(opened.meta.size as usize);
                opened.decrypt_to(file, &mut out, |_| {}).map_err(err)?;
                out
            }
        };
        Ok(Response::new(bytes))
    })
    .await
}

/// Convertit un fichier v1/v2 ouvert au format v3 (avec une clé éventuellement nouvelle).
#[tauri::command]
pub async fn convert_to_v3(
    app: AppHandle,
    state: State<'_, AppState>,
    session: u64,
    variant: usize,
    output: String,
    password: String,
) -> CmdResult<String> {
    let password = Zeroizing::new(password);
    let current = current_session(&state, session)?;
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let Session::InMemory(d) = &*current else {
            return Err("Ce fichier est déjà au format v3.".into());
        };
        let v = d.variants.get(variant).ok_or("Version inconnue.")?;
        let meta = core::Metadata {
            name: v.name.clone(),
            mime: v.mime.clone(),
            size: v.content.len() as u64,
        };
        let out = PathBuf::from(&output);
        // Si `out` est l'ancien fichier, il n'est remplacé qu'une fois le nouveau entièrement écrit
        write_atomically(journal, &out, |w| {
            v3::encrypt(
                &v.content[..],
                w,
                &password,
                &meta,
                &v3::Params::default(),
                |_| {},
            )
        })?;
        verify_v3(&out, &password)?;
        Ok(output)
    })
    .await
}

/// Efface la session (et donc les secrets en mémoire).
#[tauri::command]
pub fn close_session(state: State<'_, AppState>) -> CmdResult<()> {
    state.session.lock().map_err(err)?.take();
    Ok(())
}

// ---------------------------------------------------------------------------
// Déchiffrement par lot
// ---------------------------------------------------------------------------

/// Déchiffre plusieurs fichiers dans `output_dir` (archives extraites en dossiers).
#[tauri::command]
pub async fn decrypt_many(
    app: AppHandle,
    inputs: Vec<String>,
    password: String,
    algorithm: Option<String>,
    output_dir: String,
    on_progress: Channel<BatchProgress>,
) -> CmdResult<Vec<ItemResult>> {
    let password = Zeroizing::new(password);
    blocking(move || {
        let journal = &app.state::<AppState>().journal;
        let dest = PathBuf::from(&output_dir);
        let count = inputs.len();
        let total: u64 = inputs
            .iter()
            .map(|p| fs::metadata(p).map(|m| m.len()).unwrap_or(0))
            .sum();
        let mut before = 0u64;
        let mut results = Vec::with_capacity(count);
        for (index, input) in inputs.into_iter().enumerate() {
            let inp = PathBuf::from(&input);
            let in_size = fs::metadata(&inp).map(|m| m.len()).unwrap_or(0);
            let name = file_name(&inp);
            let mut item = ItemResult {
                input: input.clone(),
                ..Default::default()
            };
            let outcome = (|| -> CmdResult<PathBuf> {
                let (session, summary) = open_session(&inp, &password, algorithm.clone())?;
                item.warnings = summary.warnings;
                let mut t = Throttle::new();
                let ch = on_progress.clone();
                let nm = name.clone();
                let plain_total = summary.variants.first().map(|v| v.size).unwrap_or(1).max(1);
                let progress = move |n: u64| {
                    if t.ready() {
                        let done = before + in_size * n / plain_total;
                        let _ = ch.send(BatchProgress {
                            index,
                            count,
                            name: nm.clone(),
                            done,
                            total,
                        });
                    }
                };
                match &session {
                    Session::V3 { path, opened } if summary.is_archive => {
                        Ok(extract_v3_archive(journal, path, opened, &dest, progress)?.0)
                    }
                    Session::V3 { path, opened } => {
                        let out = unique_path(&dest, &core::sanitize_file_name(&opened.meta.name));
                        let mut file = File::open(path).map_err(err)?;
                        file.seek(SeekFrom::Start(opened.header.data_offset()))
                            .map_err(err)?;
                        let mut progress = progress;
                        write_atomically(journal, &out, |w| {
                            opened.decrypt_to(file, w, &mut progress).map(|_| ())
                        })?;
                        Ok(out)
                    }
                    Session::InMemory(d) => {
                        let v = &d.variants[0];
                        let out = unique_path(&dest, &v.name);
                        write_atomically(journal, &out, |w| {
                            w.write_all(&v.content).map_err(core::Error::from)
                        })?;
                        Ok(out)
                    }
                }
            })();
            match outcome {
                Ok(out) => item.output = Some(out.to_string_lossy().into_owned()),
                Err(e) => item.error = Some(e),
            }
            before += in_size;
            let _ = on_progress.send(BatchProgress {
                index,
                count,
                name,
                done: before,
                total,
            });
            results.push(item);
        }
        Ok(results)
    })
    .await
}

// ---------------------------------------------------------------------------
// Divers
// ---------------------------------------------------------------------------

/// Phrase de passe aléatoire (mots français, 12 bits par mot).
#[tauri::command]
pub fn generate_passphrase(words: usize) -> CmdResult<String> {
    core::passphrase::generate(words)
        .map(|p| p.to_string())
        .map_err(err)
}

/// Fichiers à ouvrir reçus du système (lancement, double-clic, clic droit).
#[tauri::command]
pub fn take_pending_requests(state: State<'_, AppState>) -> CmdResult<Vec<OpenRequest>> {
    Ok(std::mem::take(&mut *state.pending.lock().map_err(err)?))
}
