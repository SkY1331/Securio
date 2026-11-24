//! Générateur de phrases de passe (méthode Diceware).
//!
//! 4 096 mots français courants (12 bits d'entropie par mot), tirés avec le
//! générateur aléatoire du système. 6 mots = 72 bits : combinés à Argon2id, hors
//! de portée d'une attaque par force brute.
//!
//! Liste construite par `tools/build-wordlist.mjs` à partir de la liste de
//! fréquences de zxcvbn-ts (licence MIT) : mots de 4 à 8 lettres sans accent,
//! sans noms propres, anglicismes ni grossièretés.

use crate::{Error, Result};
use std::sync::OnceLock;
use zeroize::Zeroizing;

const WORDLIST: &str = include_str!("wordlist_fr.txt");
pub const WORD_COUNT: usize = 4096;
pub const BITS_PER_WORD: u32 = 12;
pub const DEFAULT_WORDS: usize = 6;
pub const MIN_WORDS: usize = 4;
pub const MAX_WORDS: usize = 12;

fn words() -> &'static [&'static str] {
    static W: OnceLock<Vec<&'static str>> = OnceLock::new();
    W.get_or_init(|| WORDLIST.lines().filter(|l| !l.is_empty()).collect())
}

/// Phrase de passe de `n` mots séparés par des tirets.
pub fn generate(n: usize) -> Result<Zeroizing<String>> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&n) {
        return Err(Error::Invalid(format!(
            "nombre de mots entre {MIN_WORDS} et {MAX_WORDS}"
        )));
    }
    let list = words();
    debug_assert_eq!(list.len(), WORD_COUNT);
    let mut random = Zeroizing::new(vec![0u8; 2 * n]);
    getrandom::fill(&mut random).map_err(|e| Error::Io(std::io::Error::other(e.to_string())))?;
    let mut out = Zeroizing::new(String::new());
    for i in 0..n {
        // 4 096 = 2^12 : le masque donne un tirage parfaitement uniforme
        let index = (u16::from_le_bytes([random[2 * i], random[2 * i + 1]]) & 0x0FFF) as usize;
        if i > 0 {
            out.push('-');
        }
        out.push_str(list[index]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn wordlist_is_well_formed() {
        let w = words();
        assert_eq!(w.len(), WORD_COUNT);
        assert_eq!(
            w.iter().collect::<HashSet<_>>().len(),
            WORD_COUNT,
            "mots en double"
        );
        assert!(w
            .iter()
            .all(|x| (4..=8).contains(&x.len()) && x.bytes().all(|b| b.is_ascii_lowercase())));
    }

    #[test]
    fn generates_requested_number_of_words() {
        for n in [MIN_WORDS, DEFAULT_WORDS, MAX_WORDS] {
            let p = generate(n).unwrap();
            let parts: Vec<&str> = p.split('-').collect();
            assert_eq!(parts.len(), n);
            assert!(parts.iter().all(|x| words().contains(x)));
        }
        assert!(generate(3).is_err());
        assert!(generate(13).is_err());
    }

    #[test]
    fn draws_are_spread_out() {
        let mut seen = HashSet::new();
        for _ in 0..500 {
            for w in generate(MAX_WORDS).unwrap().split('-') {
                seen.insert(w.to_string());
            }
        }
        // 6 000 tirages parmi 4 096 mots : ~3 100 mots distincts attendus
        assert!(seen.len() > 2_500, "tirage peu dispersé : {}", seen.len());
    }
}
