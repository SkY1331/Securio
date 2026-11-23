//! Noms de fichiers.

use crate::ENCRYPTED_EXTENSION;

/// Rend un nom de fichier sûr pour l'enregistrement (Windows/macOS/Linux).
pub fn sanitize_file_name(name: &str) -> String {
    let replaced: String = name
        .chars()
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if (c as u32) < 0x20 => '_',
            c => c,
        })
        .collect();
    let trimmed = replaced.trim_matches(|c: char| c.is_whitespace() || c == '.');
    let clean: String = trimmed.chars().take(200).collect();
    if clean.is_empty() {
        "fichier".to_string()
    } else {
        clean
    }
}

/// Nom d'origine déduit du nom du fichier chiffré
/// (`a.pdf.encrypted` → `a.pdf`, `a.pdf (1).encrypted` → `a.pdf`).
pub fn name_from_encrypted_name(outer: &str) -> Option<String> {
    let base = outer.rsplit(['/', '\\']).next().unwrap_or(outer);
    let lower = base.to_lowercase();
    if !lower.ends_with(ENCRYPTED_EXTENSION) || base.len() < ENCRYPTED_EXTENSION.len() {
        return None;
    }
    let mut stem = &base[..base.len() - ENCRYPTED_EXTENSION.len()];
    // Suffixe " (n)" ajouté par les navigateurs / l'explorateur
    if let Some(pos) = stem.rfind(" (") {
        let tail = &stem[pos + 2..];
        if tail.len() > 1
            && tail.ends_with(')')
            && tail[..tail.len() - 1].bytes().all(|b| b.is_ascii_digit())
        {
            stem = &stem[..pos];
        }
    }
    if stem.is_empty() {
        None
    } else {
        Some(stem.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize() {
        assert_eq!(
            sanitize_file_name("..\\..\\evil:name?.txt"),
            "_.._evil_name_.txt"
        );
        assert_eq!(sanitize_file_name(""), "fichier");
        assert_eq!(sanitize_file_name(" .. "), "fichier");
    }

    #[test]
    fn from_outer() {
        assert_eq!(
            name_from_encrypted_name("/home/u/doc.pdf.encrypted").as_deref(),
            Some("doc.pdf")
        );
        assert_eq!(
            name_from_encrypted_name("C:\\x\\doc.pdf (2).encrypted").as_deref(),
            Some("doc.pdf")
        );
        assert_eq!(
            name_from_encrypted_name("doc.pdf.ENCRYPTED").as_deref(),
            Some("doc.pdf")
        );
        assert_eq!(name_from_encrypted_name("doc.pdf"), None);
        assert_eq!(
            name_from_encrypted_name("a (b).encrypted").as_deref(),
            Some("a (b)")
        );
    }
}
