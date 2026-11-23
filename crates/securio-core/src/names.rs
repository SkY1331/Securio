//! Noms de fichiers.
//!
//! Le nom d'origine stocké dans un fichier chiffré est contrôlé par la personne
//! qui a créé ce fichier : il doit être traité comme une donnée hostile.

use crate::ENCRYPTED_EXTENSION;

/// Caractères invisibles ou de mise en forme pouvant servir à déguiser un nom
/// (ex. U+202E, qui inverse le sens d'affichage : « facture[U+202E]fdp.exe »
/// apparaît comme « factureexe.pdf »).
fn is_hidden_format_char(c: char) -> bool {
    matches!(c,
        '\u{00AD}'                  // trait d'union conditionnel
        | '\u{061C}'                // marque de lettre arabe
        | '\u{115F}' | '\u{1160}'   // remplissages hangûl
        | '\u{180E}'                // séparateur de voyelles mongol
        | '\u{200B}'..='\u{200F}'   // espaces de largeur nulle, marques LTR/RTL
        | '\u{202A}'..='\u{202E}'   // incorporations / forçages bidirectionnels
        | '\u{2060}'..='\u{206F}'   // gluon, isolats bidirectionnels, etc.
        | '\u{3164}'                // remplissage hangûl
        | '\u{FE00}'..='\u{FE0F}'   // sélecteurs de variante
        | '\u{FEFF}'                // indicateur d'ordre des octets
        | '\u{FFA0}'                // remplissage hangûl demi-chasse
        | '\u{FFF9}'..='\u{FFFB}'   // annotations interlinéaires
        | '\u{E0000}'..='\u{E007F}' // étiquettes
    )
}

/// Noms interdits par Windows, avec ou sans extension (`CON`, `nul.txt`…).
fn is_windows_reserved(name: &str) -> bool {
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end()
        .to_ascii_uppercase();
    matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || ((stem.starts_with("COM") || stem.starts_with("LPT"))
        && stem.len() == 4
        && stem.as_bytes()[3].is_ascii_digit())
}

/// Nom de fichier nettoyé, et indication que des caractères invisibles ont été retirés.
pub fn sanitize_file_name_report(name: &str) -> (String, bool) {
    let mut hidden = false;
    let replaced: String = name
        .chars()
        .filter(|&c| {
            let h = is_hidden_format_char(c);
            hidden |= h;
            !h
        })
        .map(|c| match c {
            '\\' | '/' | ':' | '*' | '?' | '"' | '<' | '>' | '|' => '_',
            c if c.is_control() => '_', // C0, DEL et C1
            c => c,
        })
        .collect();
    let trimmed = replaced.trim_matches(|c: char| c.is_whitespace() || c == '.');
    let mut clean: String = trimmed.chars().take(200).collect();
    if clean.is_empty() {
        clean = "fichier".to_string();
    }
    if is_windows_reserved(&clean) {
        clean.insert(0, '_');
    }
    (clean, hidden)
}

/// Rend un nom de fichier sûr pour l'enregistrement (Windows/macOS/Linux).
pub fn sanitize_file_name(name: &str) -> String {
    sanitize_file_name_report(name).0
}

/// Extensions de fichiers capables d'exécuter du code à l'ouverture.
const RISKY_EXTENSIONS: &[&str] = &[
    "exe",
    "com",
    "scr",
    "pif",
    "bat",
    "cmd",
    "msi",
    "msp",
    "msix",
    "appx",
    "appxbundle",
    "ps1",
    "psm1",
    "psd1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "lnk",
    "url",
    "jar",
    "reg",
    "cpl",
    "dll",
    "sys",
    "inf",
    "gadget",
    "application",
    "iso",
    "img",
    "vhd",
    "vhdx",
    "docm",
    "dotm",
    "xlsm",
    "xltm",
    "xlam",
    "pptm",
    "potm",
    "ppam",
    "sh",
    "command",
    "app",
    "pkg",
    "dmg",
    "deb",
    "rpm",
    "apk",
];

/// Extension (en minuscules) si elle correspond à un fichier exécutable ou à macros.
pub fn risky_extension(name: &str) -> Option<String> {
    let (_, ext) = name.rsplit_once('.')?;
    let ext = ext.to_ascii_lowercase();
    RISKY_EXTENSIONS.contains(&ext.as_str()).then_some(ext)
}

/// Avertissements à afficher pour un nom d'origine (déjà ou non nettoyé).
pub fn name_warnings(original: &str) -> Vec<String> {
    let (clean, hidden) = sanitize_file_name_report(original);
    let mut w = Vec::new();
    if hidden {
        w.push(
            "Le nom d'origine contenait des caractères invisibles ou d'inversion du sens de lecture, souvent utilisés pour déguiser un programme en document : ils ont été retirés."
                .to_string(),
        );
    }
    if let Some(ext) = risky_extension(&clean) {
        w.push(format!(
            "Attention : ce fichier est de type « .{ext} » (programme, script ou document à macros). Ne l'ouvrez que si vous connaissez et faites confiance à son origine."
        ));
    }
    w
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
        assert_eq!(sanitize_file_name("a\u{0085}b\u{007F}c.txt"), "a_b_c.txt");
    }

    #[test]
    fn bidi_spoofing_is_neutralised() {
        // Affiché « facture[U+202E]fdp.exe » → « factureexe.pdf » dans l'explorateur
        let evil = "facture\u{202E}fdp.exe";
        let (clean, hidden) = sanitize_file_name_report(evil);
        assert_eq!(clean, "facturefdp.exe");
        assert!(hidden);
        let w = name_warnings(evil);
        assert!(w.iter().any(|m| m.contains("invisibles")));
        assert!(w.iter().any(|m| m.contains(".exe")));
        assert_eq!(
            sanitize_file_name("re\u{200B}port\u{2067}.pdf\u{FEFF}"),
            "report.pdf"
        );
    }

    #[test]
    fn windows_reserved_names() {
        assert_eq!(sanitize_file_name("CON"), "_CON");
        assert_eq!(sanitize_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_file_name("com1.tar.gz"), "_com1.tar.gz");
        assert_eq!(sanitize_file_name("LPT9"), "_LPT9");
        assert_eq!(sanitize_file_name("console.txt"), "console.txt");
        assert_eq!(sanitize_file_name("COM10.txt"), "COM10.txt");
    }

    #[test]
    fn risky() {
        assert_eq!(risky_extension("setup.EXE").as_deref(), Some("exe"));
        assert_eq!(risky_extension("budget.xlsm").as_deref(), Some("xlsm"));
        assert_eq!(risky_extension("photo.png"), None);
        assert_eq!(risky_extension("sans_extension"), None);
        assert!(name_warnings("rapport.pdf").is_empty());
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
