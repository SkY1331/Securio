# Code d'origine (Securio 1.2.1)

`cryptoUtils.v1.original.js` est une copie conforme du chiffrement de Securio 1.2.1.
`generate-v1-fixtures.mjs` l'a utilisé pour créer `test/fixtures/v1/` en reproduisant la façon
dont l'ancienne interface lisait les fichiers (texte, data-URL, binaire).

Ces fichiers servent de référence aux tests de rétro-compatibilité du cœur Rust
(`crates/securio-core/tests/compat.rs`). **Ne pas les modifier ni régénérer les témoins.**

Les témoins v2 (`test/fixtures/v2/`) ont été produits par Securio 1.3 (JavaScript, commit
`0ee481e`), les témoins v3 par `cargo run -p securio-core --example gen_v3_fixtures`.
