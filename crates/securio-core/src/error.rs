//! Erreurs, avec des messages destinés à l'utilisateur (en français).

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Ce fichier n'est pas un fichier chiffré par Securio.")]
    NotSecurio,
    #[error("La clé secrète ne peut pas être vide.")]
    EmptyPassword,
    #[error("{0}")]
    WrongPassword(String),
    #[error("Ce fichier utilise le format v{0}, créé par une version plus récente de Securio. Mettez l'application à jour.")]
    FutureVersion(u8),
    #[error("Algorithme inconnu : ce fichier a été créé par une version plus récente de Securio.")]
    UnknownAlgorithm,
    #[error("Fichier invalide : {0}.")]
    Invalid(String),
    #[error("Fichier modifié ou corrompu : {0}.")]
    Corrupted(String),
    #[error("Erreur d'accès au fichier : {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
