//! Archives de dossiers (format tar non compressé), chiffrées comme un fichier v3.
//!
//! Le format tar est lisible partout (Windows 10+ intègre `tar.exe`) : une archive
//! déchiffrée et enregistrée telle quelle reste exploitable sans Securio.
//!
//! - Les liens symboliques et fichiers spéciaux ne sont jamais archivés.
//! - À l'extraction, seuls les fichiers et dossiers ordinaires sont créés, avec des
//!   chemins relatifs vérifiés (pas de `..`, pas de chemin absolu) et des noms
//!   nettoyés ; liens, périphériques, etc. sont ignorés.
//! - La taille exacte de l'archive est calculée à l'avance (passe « à blanc ») :
//!   le format v3 l'enregistre dans ses métadonnées chiffrées.

use crate::{sanitize_file_name, Result};
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::UNIX_EPOCH;

pub const MIME: &str = "application/x-tar";
pub const EXTENSION: &str = ".tar";

#[derive(Debug, Clone)]
pub struct Entry {
    /// Chemin sur le disque.
    pub source: PathBuf,
    /// Chemin dans l'archive (séparateurs `/`).
    pub archive_path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// Liens symboliques et fichiers spéciaux ignorés.
    pub skipped: u64,
}

fn mtime(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn walk(dir: &Path, prefix: &str, out: &mut Vec<Entry>, summary: &mut Summary) -> Result<()> {
    let mut children: Vec<_> = fs::read_dir(dir)?.collect::<io::Result<_>>()?;
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let meta = fs::symlink_metadata(child.path())?;
        let name = child.file_name().to_string_lossy().into_owned();
        let path = format!("{prefix}/{name}");
        if meta.file_type().is_symlink() {
            summary.skipped += 1;
        } else if meta.is_dir() {
            out.push(Entry {
                source: child.path(),
                archive_path: path.clone(),
                is_dir: true,
                size: 0,
                mtime: mtime(&meta),
            });
            summary.dirs += 1;
            walk(&child.path(), &path, out, summary)?;
        } else if meta.is_file() {
            out.push(Entry {
                source: child.path(),
                archive_path: path,
                is_dir: false,
                size: meta.len(),
                mtime: mtime(&meta),
            });
            summary.files += 1;
            summary.bytes += meta.len();
        } else {
            summary.skipped += 1;
        }
    }
    Ok(())
}

/// Liste le contenu à archiver (fichiers et dossiers, récursivement).
/// Deux éléments de même nom au premier niveau sont renommés « nom (2) ».
pub fn collect(inputs: &[PathBuf]) -> Result<(Vec<Entry>, Summary)> {
    let mut out = Vec::new();
    let mut summary = Summary::default();
    let mut top_names: Vec<String> = Vec::new();
    for input in inputs {
        let meta = fs::symlink_metadata(input)?;
        let base = input
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "dossier".into());
        let mut name = base.clone();
        let mut n = 2;
        while top_names.contains(&name) {
            name = match base.rsplit_once('.') {
                Some((stem, ext)) if !meta.is_dir() && !stem.is_empty() => {
                    format!("{stem} ({n}).{ext}")
                }
                _ => format!("{base} ({n})"),
            };
            n += 1;
        }
        top_names.push(name.clone());
        if meta.file_type().is_symlink() {
            summary.skipped += 1;
        } else if meta.is_dir() {
            out.push(Entry {
                source: input.clone(),
                archive_path: name.clone(),
                is_dir: true,
                size: 0,
                mtime: mtime(&meta),
            });
            summary.dirs += 1;
            walk(input, &name, &mut out, &mut summary)?;
        } else if meta.is_file() {
            out.push(Entry {
                source: input.clone(),
                archive_path: name,
                is_dir: false,
                size: meta.len(),
                mtime: mtime(&meta),
            });
            summary.files += 1;
            summary.bytes += meta.len();
        } else {
            summary.skipped += 1;
        }
    }
    Ok((out, summary))
}

/// Lecteur qui exige exactement `remaining` octets (fichier modifié pendant
/// l'archivage → erreur plutôt qu'archive corrompue).
struct Exact<R> {
    inner: R,
    remaining: u64,
}

impl<R: Read> Read for Exact<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Ok(0);
        }
        let max = buf
            .len()
            .min(self.remaining.min(usize::MAX as u64) as usize);
        let n = self.inner.read(&mut buf[..max])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "fichier modifié pendant l'archivage",
            ));
        }
        self.remaining -= n as u64;
        Ok(n)
    }
}

fn build<W: Write>(entries: &[Entry], w: W, dry_run: bool) -> Result<W> {
    let mut builder = tar::Builder::new(w);
    for e in entries {
        let mut header = tar::Header::new_gnu();
        header.set_mtime(e.mtime);
        if e.is_dir {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_size(0);
            builder.append_data(&mut header, format!("{}/", e.archive_path), io::empty())?;
        } else {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_size(e.size);
            if dry_run {
                builder.append_data(&mut header, &e.archive_path, io::repeat(0).take(e.size))?;
            } else {
                let reader = Exact {
                    inner: File::open(&e.source)?,
                    remaining: e.size,
                };
                builder.append_data(&mut header, &e.archive_path, reader)?;
            }
        }
    }
    Ok(builder.into_inner()?)
}

struct Counter(u64);
impl Write for Counter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Taille exacte de l'archive, sans lire les fichiers.
pub fn archive_size(entries: &[Entry]) -> Result<u64> {
    Ok(build(entries, Counter(0), true)?.0)
}

/// Écrit l'archive (lit réellement les fichiers).
pub fn write_archive<W: Write>(entries: &[Entry], w: W) -> Result<()> {
    build(entries, w, false)?.flush()?;
    Ok(())
}

/// Chemin relatif sûr à partir d'un chemin d'archive, ou `None` s'il est refusé.
fn safe_relative(path: &Path) -> Option<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(part) => {
                let raw = part.to_string_lossy();
                let clean = sanitize_file_name(&raw);
                out.push(clean);
            }
            Component::CurDir => {}
            // `..`, racine, préfixe de lecteur Windows : refusés
            _ => return None,
        }
    }
    (!out.as_os_str().is_empty()).then_some(out)
}

/// Extrait une archive dans `dest` (qui doit exister et être vide de préférence).
pub fn extract<R: Read>(r: R, dest: &Path) -> Result<Summary> {
    let mut archive = tar::Archive::new(r);
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive.set_overwrite(true);
    let mut summary = Summary::default();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let kind = entry.header().entry_type();
        let rel = match safe_relative(&entry.path()?) {
            Some(p) => p,
            None => {
                summary.skipped += 1;
                continue;
            }
        };
        let target = dest.join(&rel);
        match kind {
            tar::EntryType::Directory => {
                fs::create_dir_all(&target)?;
                summary.dirs += 1;
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }
                let mut out = File::create(&target)?;
                let n = io::copy(&mut entry, &mut out)?;
                out.sync_all()?;
                summary.files += 1;
                summary.bytes += n;
            }
            // liens, périphériques, etc. : jamais créés
            _ => summary.skipped += 1,
        }
    }
    Ok(summary)
}

/// Nom d'archive proposé pour une sélection (« Dossier.tar », « 3 éléments.tar »).
pub fn default_name(inputs: &[PathBuf]) -> String {
    match inputs {
        [one] => {
            let base = one
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            format!("{}{EXTENSION}", sanitize_file_name(&base))
        }
        many => format!("{} éléments{EXTENSION}", many.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("securio-archive-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn round_trip_with_exact_size() {
        let root = tmp("rt");
        let src = root.join("Mon dossier");
        fs::create_dir_all(src.join("sous-dossier/vide")).unwrap();
        fs::write(src.join("a.txt"), b"bonjour").unwrap();
        fs::write(src.join("sous-dossier/b.bin"), vec![7u8; 100_000]).unwrap();
        let long = "x".repeat(150) + ".txt"; // nom > 100 octets : extension GNU
        fs::write(src.join(&long), b"long").unwrap();
        let extra = root.join("seul.pdf");
        fs::write(&extra, b"%PDF").unwrap();

        let (entries, summary) = collect(&[src.clone(), extra]).unwrap();
        assert_eq!(summary.files, 4);
        assert_eq!(summary.dirs, 3);
        let size = archive_size(&entries).unwrap();
        let mut buf = Vec::new();
        write_archive(&entries, &mut buf).unwrap();
        assert_eq!(
            buf.len() as u64,
            size,
            "la passe à blanc doit donner la taille exacte"
        );

        let dest = root.join("sortie");
        fs::create_dir_all(&dest).unwrap();
        let s = extract(&buf[..], &dest).unwrap();
        assert_eq!((s.files, s.dirs, s.skipped), (4, 3, 0));
        assert_eq!(
            fs::read(dest.join("Mon dossier/sous-dossier/b.bin")).unwrap(),
            vec![7u8; 100_000]
        );
        assert_eq!(
            fs::read(dest.join("Mon dossier").join(&long)).unwrap(),
            b"long"
        );
        assert!(dest.join("Mon dossier/sous-dossier/vide").is_dir());
        assert_eq!(fs::read(dest.join("seul.pdf")).unwrap(), b"%PDF");
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn duplicate_top_level_names() {
        let root = tmp("dup");
        fs::create_dir_all(root.join("a")).unwrap();
        fs::create_dir_all(root.join("b")).unwrap();
        fs::write(root.join("a/doc.txt"), b"1").unwrap();
        fs::write(root.join("b/doc.txt"), b"2").unwrap();
        let (entries, _) = collect(&[root.join("a/doc.txt"), root.join("b/doc.txt")]).unwrap();
        let names: Vec<_> = entries.iter().map(|e| e.archive_path.as_str()).collect();
        assert_eq!(names, vec!["doc.txt", "doc (2).txt"]);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn file_changed_during_archiving_is_an_error() {
        let root = tmp("chg");
        let f = root.join("f.txt");
        fs::write(&f, b"12345").unwrap();
        let (entries, _) = collect(std::slice::from_ref(&f)).unwrap();
        fs::write(&f, b"12").unwrap(); // raccourci entre-temps
        assert!(write_archive(&entries, io::sink()).is_err());
        fs::remove_dir_all(&root).unwrap();
    }

    /// Archive forgée : remontée de dossier, chemin absolu, lien symbolique.
    #[test]
    fn hostile_archive_cannot_escape() {
        let root = tmp("evil");
        let dest = root.join("dest");
        fs::create_dir_all(&dest).unwrap();

        let mut b = tar::Builder::new(Vec::new());
        let mut add = |path: &[u8], kind: tar::EntryType, data: &[u8], link: Option<&str>| {
            let mut h = tar::Header::new_gnu();
            // écrit le chemin brut, sans les vérifications de la crate tar
            h.as_old_mut().name[..path.len()].copy_from_slice(path);
            h.set_entry_type(kind);
            h.set_size(data.len() as u64);
            h.set_mode(0o644);
            if let Some(l) = link {
                h.set_link_name(l).unwrap();
            }
            h.set_cksum();
            b.append(&h, data).unwrap();
        };
        add(b"../evade.txt", tar::EntryType::Regular, b"x", None);
        add(b"/etc/evade.txt", tar::EntryType::Regular, b"x", None);
        add(b"lien", tar::EntryType::Symlink, b"", Some("/etc/passwd"));
        add(b"ok/fichier.txt", tar::EntryType::Regular, b"ok", None);
        let data = b.into_inner().unwrap();

        let s = extract(&data[..], &dest).unwrap();
        assert_eq!(s.files, 1);
        assert_eq!(s.skipped, 3);
        assert!(!root.join("evade.txt").exists());
        assert!(!dest.join("lien").exists());
        assert_eq!(fs::read(dest.join("ok/fichier.txt")).unwrap(), b"ok");
        fs::remove_dir_all(&root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_are_not_archived() {
        let root = tmp("sym");
        let src = root.join("d");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("vrai.txt"), b"1").unwrap();
        std::os::unix::fs::symlink("/etc/passwd", src.join("lien")).unwrap();
        let (entries, summary) = collect(&[src]).unwrap();
        assert_eq!(summary.skipped, 1);
        assert!(entries.iter().all(|e| !e.archive_path.ends_with("lien")));
        fs::remove_dir_all(&root).unwrap();
    }
}
