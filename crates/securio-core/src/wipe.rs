//! Suppression du fichier d'origine après chiffrement.
//!
//! Le contenu est d'abord écrasé (zéros), puis le fichier est supprimé
//! définitivement (pas de corbeille). Limite importante : sur un SSD, une clé USB
//! ou un disque à instantanés/sauvegardes, l'écrasement n'atteint pas forcément
//! les cellules physiques d'origine ; seul un disque entièrement chiffré
//! (BitLocker…) garantit qu'aucune copie lisible ne subsiste.

use crate::{Error, Result};
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

pub fn wipe_and_remove(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_file() {
        return Err(Error::Invalid(
            "seuls les fichiers ordinaires peuvent être supprimés".into(),
        ));
    }
    let len = meta.len();
    {
        let mut f = OpenOptions::new().write(true).open(path)?;
        f.seek(SeekFrom::Start(0))?;
        let zeros = vec![0u8; 1 << 20];
        let mut left = len;
        while left > 0 {
            let n = left.min(zeros.len() as u64) as usize;
            f.write_all(&zeros[..n])?;
            left -= n as u64;
        }
        f.sync_all()?;
    }
    fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipes_then_removes() {
        let p = std::env::temp_dir().join(format!("securio-wipe-{}", std::process::id()));
        fs::write(&p, vec![0xAB; 3_000_000]).unwrap();
        wipe_and_remove(&p).unwrap();
        assert!(!p.exists());
        let d = std::env::temp_dir();
        assert!(
            wipe_and_remove(&d).is_err(),
            "un dossier ne doit jamais être supprimé"
        );
    }
}
