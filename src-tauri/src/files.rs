//! Écriture sûre sur le disque : fichiers et dossiers temporaires journalisés,
//! renommés seulement en cas de succès.

use securio_core as core;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const TEMP_SUFFIX: &str = ".securio-tmp";

pub type CmdResult<T> = Result<T, String>;

pub fn err<E: std::fmt::Display>(e: E) -> String {
    e.to_string()
}

pub fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

pub fn same_file(a: &Path, b: &Path) -> bool {
    match (fs::canonicalize(a), fs::canonicalize(b)) {
        (Ok(x), Ok(y)) => x == y,
        _ => false,
    }
}

/// `dir/name`, ou `dir/nom (2).ext`, `dir/nom (3).ext`… si le nom est déjà pris.
pub fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let first = dir.join(name);
    if !first.exists() {
        return first;
    }
    // « rapport.pdf.encrypted » → « rapport (2).pdf.encrypted »
    let (stem, ext) = match name.find('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    (2..)
        .map(|n| dir.join(format!("{stem} ({n}){ext}")))
        .find(|p| !p.exists())
        .expect("nom disponible")
}

fn random_suffix() -> CmdResult<String> {
    let mut rnd = [0u8; 6];
    getrandom::fill(&mut rnd).map_err(err)?;
    Ok(rnd.iter().map(|b| format!("{b:02x}")).collect())
}

fn parent_dir(target: &Path) -> &Path {
    target
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Journal des temporaires en cours d'écriture. Si l'application est interrompue
/// (coupure, plantage), ceux qui restent — qui peuvent contenir un début de
/// contenu déchiffré — sont supprimés au démarrage suivant.
#[derive(Default)]
pub struct TempJournal {
    path: Mutex<Option<PathBuf>>,
}

impl TempJournal {
    pub fn entries(path: &Path) -> Vec<PathBuf> {
        fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(PathBuf::from)
            .collect()
    }

    pub fn save(path: &Path, entries: &[PathBuf]) {
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

    /// Active le journal et supprime les temporaires (fichiers ou dossiers)
    /// laissés par une exécution interrompue. Renvoie le nombre supprimé.
    pub fn init(&self, journal: PathBuf) -> usize {
        let mut removed = 0;
        for p in Self::entries(&journal) {
            let ours = p
                .file_name()
                .map(|n| n.to_string_lossy().ends_with(TEMP_SUFFIX))
                .unwrap_or(false);
            if !ours {
                continue;
            }
            let meta = match fs::symlink_metadata(&p) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let ok = if meta.is_dir() {
                fs::remove_dir_all(&p).is_ok()
            } else if meta.is_file() {
                fs::remove_file(&p).is_ok()
            } else {
                false
            };
            removed += ok as usize;
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

/// Écrit dans un fichier temporaire du même dossier, puis le renomme : en cas
/// d'erreur (clé incorrecte, fichier altéré, disque plein…), aucun fichier
/// partiel n'est laissé à la place de la cible.
pub fn write_atomically(
    journal: &TempJournal,
    target: &Path,
    write: impl FnOnce(&mut BufWriter<File>) -> core::Result<()>,
) -> CmdResult<()> {
    let tmp = parent_dir(target).join(format!(
        ".{}.{}{TEMP_SUFFIX}",
        file_name(target),
        random_suffix()?
    ));
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

/// Remplit un dossier temporaire, puis le place dans `parent` (nom rendu unique) :
/// s'il ne contient qu'un seul dossier, c'est ce dossier qui est placé (pas de
/// niveau intermédiaire « Dossier/Dossier ») ; sinon le temporaire devient `parent/nom`.
pub fn fill_dir_atomically(
    journal: &TempJournal,
    parent: &Path,
    name: &str,
    fill: impl FnOnce(&Path) -> CmdResult<()>,
) -> CmdResult<PathBuf> {
    let tmp = parent.join(format!(".{name}.{}{TEMP_SUFFIX}", random_suffix()?));
    fs::create_dir(&tmp).map_err(err)?;
    journal.add(&tmp);
    let result = fill(&tmp).and_then(|_| {
        let children: Vec<PathBuf> = fs::read_dir(&tmp)
            .map_err(err)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        match children.as_slice() {
            [only] if only.is_dir() => {
                let target = unique_path(parent, &file_name(only));
                fs::rename(only, &target).map_err(err)?;
                fs::remove_dir(&tmp).map_err(err)?;
                Ok(target)
            }
            _ => {
                let target = unique_path(parent, name);
                fs::rename(&tmp, &target).map_err(err)?;
                Ok(target)
            }
        }
    });
    if result.is_err() {
        let _ = fs::remove_dir_all(&tmp);
    }
    journal.remove(&tmp);
    result
}

pub fn mime_from_name(name: &str) -> String {
    let ext = name.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "pdf" => "application/pdf",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "bmp" => "image/bmp",
        "txt" => "text/plain",
        "md" => "text/markdown",
        "csv" => "text/csv",
        "json" => "application/json",
        "tar" => core::archive::MIME,
        "zip" => "application/zip",
        "docx" => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "xlsx" => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "pptx" => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        _ => "application/octet-stream",
    }
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("securio-files-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_leaves_nothing_on_error() {
        let dir = tmpdir("atomic");
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
            "aucun temporaire ne doit rester"
        );

        write_atomically(&journal, &target, |w| {
            w.write_all(b"ok").map_err(core::Error::from)
        })
        .unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"ok");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn interrupted_temp_files_and_dirs_are_removed_at_startup() {
        let dir = tmpdir("journal");
        let leftover = dir.join(format!(".secret.pdf.abcdef{TEMP_SUFFIX}"));
        let leftover_dir = dir.join(format!(".Dossier.123456{TEMP_SUFFIX}"));
        let foreign = dir.join("document-utilisateur.pdf");
        fs::write(&leftover, b"debut du fichier dechiffre").unwrap();
        fs::create_dir_all(leftover_dir.join("sous")).unwrap();
        fs::write(leftover_dir.join("sous/x.txt"), b"x").unwrap();
        fs::write(&foreign, b"a garder").unwrap();
        let journal_file = dir.join("temp-files.txt");
        TempJournal::save(
            &journal_file,
            &[leftover.clone(), leftover_dir.clone(), foreign.clone()],
        );

        let journal = TempJournal::default();
        assert_eq!(journal.init(journal_file.clone()), 2);
        assert!(!leftover.exists());
        assert!(!leftover_dir.exists());
        assert!(
            foreign.exists(),
            "un fichier qui n'est pas un temporaire Securio ne doit jamais être supprimé"
        );
        assert!(TempJournal::entries(&journal_file).is_empty());

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
    fn atomic_dir() {
        let dir = tmpdir("dir");
        let journal = TempJournal::default();
        // plusieurs éléments : dossier « nom »
        let ok = fill_dir_atomically(&journal, &dir, "Archive", |p| {
            fs::write(p.join("a.txt"), b"a").map_err(err)?;
            fs::write(p.join("b.txt"), b"b").map_err(err)
        })
        .unwrap();
        assert_eq!(ok, dir.join("Archive"));
        assert!(dir.join("Archive/a.txt").is_file());
        // un seul dossier : placé directement (pas de « Projet/Projet »), nom rendu unique
        fs::create_dir(dir.join("Projet")).unwrap();
        let single = fill_dir_atomically(&journal, &dir, "Projet", |p| {
            fs::create_dir(p.join("Projet")).map_err(err)?;
            fs::write(p.join("Projet/x.txt"), b"x").map_err(err)
        })
        .unwrap();
        assert_eq!(single, dir.join("Projet (2)"));
        assert!(dir.join("Projet (2)/x.txt").is_file());
        let failed = fill_dir_atomically(&journal, &dir, "Echec", |p| {
            fs::write(p.join("partiel"), b"x").unwrap();
            Err("erreur".into())
        });
        assert!(failed.is_err());
        let names: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| file_name(&e.unwrap().path()))
            .collect();
        assert_eq!(
            names.len(),
            3,
            "aucun dossier temporaire ne doit rester : {names:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn unique_names() {
        let dir = tmpdir("uniq");
        assert_eq!(
            unique_path(&dir, "a.pdf.encrypted"),
            dir.join("a.pdf.encrypted")
        );
        fs::write(dir.join("a.pdf.encrypted"), b"").unwrap();
        assert_eq!(
            unique_path(&dir, "a.pdf.encrypted"),
            dir.join("a (2).pdf.encrypted")
        );
        fs::write(dir.join("a (2).pdf.encrypted"), b"").unwrap();
        assert_eq!(
            unique_path(&dir, "a.pdf.encrypted"),
            dir.join("a (3).pdf.encrypted")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
