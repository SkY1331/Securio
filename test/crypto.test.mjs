// Tests de non-régression : node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

import {
  encryptFile,
  decryptFile,
  inspectFile,
  sanitizeFileName,
  nameFromEncryptedName,
} from '../src/utils/cryptoUtils.js';

globalThis.window = globalThis; // pour le code d'origine
const original = await import('./legacy/cryptoUtils.v1.original.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const fixturesDir = path.join(here, 'fixtures', 'v1');
const manifest = JSON.parse(readFileSync(path.join(fixturesDir, 'manifest.json'), 'utf8'));
const load = (f) => new Uint8Array(readFileSync(path.join(fixturesDir, f)));
const sha256 = (b) => createHash('sha256').update(Buffer.from(b)).digest('hex');
const FAST = { iterations: 1000 };

// ---------------------------------------------------------------------------
// Rétro-compatibilité v1
// ---------------------------------------------------------------------------

for (const fx of manifest) {
  test(`v1 : ${fx.file} est reconnu et déchiffré`, async () => {
    const bytes = load(fx.file);
    assert.equal(inspectFile(bytes)?.format, 'v1');

    // Détection automatique : doit retrouver AES-128/192/256
    const r = await decryptFile(bytes, fx.password, {
      outerName: `${fx.originalName}.encrypted`,
    });
    assert.equal(r.format, 'v1');
    assert.equal(r.algorithm, fx.algorithm);

    // Le contenu brut doit être identique à ce que renvoyait l'ancienne version
    const old = await original.decrypt(bytes.slice().buffer, fx.password, fx.algorithm);
    const raw = r.alternatives.find((a) => a.label.startsWith('Contenu brut'))?.content ?? r.content;
    assert.equal(sha256(raw), sha256(old.content));

    // Le nom complet est retrouvé grâce au nom du fichier .encrypted
    assert.equal(r.name, sanitizeFileName(fx.originalName));

    if (fx.readMode === 'arraybuffer') {
      assert.equal(sha256(r.content), fx.originalSha256, 'binaire restitué à l’identique');
    }
  });
}

test('v1 : les images (stockées en data-URL) sont restaurées à l’octet près', async () => {
  const fx = manifest.find((m) => m.readMode === 'dataurl');
  const r = await decryptFile(load(fx.file), fx.password);
  assert.equal(sha256(r.content), fx.originalSha256);
  assert.equal(r.type, 'image/png');
  assert.ok(r.warnings.length > 0);
});

test('v1 : texte avec accents Latin-1 restauré à l’identique en UTF-8', async () => {
  const fx = manifest.find((m) => m.file === 'texte-latin1.txt.encrypted');
  const r = await decryptFile(load(fx.file), fx.password);
  assert.equal(sha256(r.content), fx.originalSha256);
});

test('v1 : texte avec ’ et — récupérés au mieux', async () => {
  const fx = manifest.find((m) => m.file === 'texte-avec-pertes.txt.encrypted');
  const r = await decryptFile(load(fx.file), fx.password);
  const text = new TextDecoder().decode(r.content);
  assert.match(text, /l’apostrophe/);
  assert.match(text, /—/);
  assert.match(text, /10 ¬/); // € perdu à l'origine (0x20AC & 0xFF = 0xAC)
});

test('v1 : nom tronqué sans indice => avertissement', async () => {
  const fx = manifest.find((m) => m.file === 'nom-long.pdf.encrypted');
  const r = await decryptFile(load(fx.file), fx.password, { outerName: 'autre.encrypted' });
  assert.equal(new TextEncoder().encode(r.name).length <= 32, true);
  assert.ok(r.warnings.some((w) => w.includes('tronqué')));
});

test('v1 : nom retrouvé malgré le suffixe " (1)" ajouté par le navigateur', async () => {
  const fx = manifest.find((m) => m.file === 'nom-long.pdf.encrypted');
  const r = await decryptFile(load(fx.file), fx.password, {
    outerName: 'C:\\Users\\x\\Downloads\\Rapport annuel confidentiel 2024 version finale.pdf (1).encrypted',
  });
  assert.equal(r.name, fx.originalName);
});

test('v1 : mot de passe accentué (encodage historique) accepté', async () => {
  const fx = manifest.find((m) => m.file === 'mdp-accentue.bin.encrypted');
  const r = await decryptFile(load(fx.file), 'clé€secrète');
  assert.equal(sha256(r.content), fx.originalSha256);
});

test('v1 : algorithme imposé = comportement historique', async () => {
  const fx = manifest.find((m) => m.file === 'binaire-aes128.bin.encrypted');
  const ok = await decryptFile(load(fx.file), fx.password, { algorithm: 'aes-128-cbc' });
  assert.equal(sha256(ok.content), fx.originalSha256);
  await assert.rejects(decryptFile(load(fx.file), fx.password, { algorithm: 'aes-256-cbc' }), /Détection automatique/);
});

test('v1 : mauvaise clé => erreur explicite', async () => {
  const fx = manifest.find((m) => m.file === 'binaire-aes256.bin.encrypted');
  await assert.rejects(decryptFile(load(fx.file), 'mauvaise'), /Clé incorrecte/);
});

// ---------------------------------------------------------------------------
// Format v2
// ---------------------------------------------------------------------------

test('v2 : aller-retour binaire, nom et type chiffrés', async () => {
  const data = new Uint8Array(4096).map((_, i) => (i * 7) & 0xff);
  const name = 'Résumé confidentiel très très long de l’équipe 2026.pdf';
  const enc = await encryptFile(data, 'mot de passe', { name, type: 'application/pdf' }, FAST);
  assert.equal(inspectFile(enc).format, 'v2');
  assert.equal(Buffer.from(enc).includes(Buffer.from('confidentiel')), false, 'le nom ne doit pas être en clair');
  const dec = await decryptFile(enc, 'mot de passe');
  assert.deepEqual(dec.content, data);
  assert.equal(dec.name, name);
  assert.equal(dec.type, 'application/pdf');
  assert.deepEqual(dec.warnings, []);
});

test('v2 : paramètres par défaut (600 000 itérations)', async () => {
  const enc = await encryptFile(new Uint8Array([1, 2, 3]), 'x', { name: 'a.bin' });
  assert.equal(inspectFile(enc).iterations, 600000);
  assert.deepEqual((await decryptFile(enc, 'x')).content, new Uint8Array([1, 2, 3]));
});

test('v2 : fichier vide', async () => {
  const enc = await encryptFile(new Uint8Array(0), 'k', { name: 'vide.txt' }, FAST);
  const dec = await decryptFile(enc, 'k');
  assert.equal(dec.content.length, 0);
});

test('v2 : mauvaise clé => erreur', async () => {
  const enc = await encryptFile(new Uint8Array(10), 'bonne', { name: 'a' }, FAST);
  await assert.rejects(decryptFile(enc, 'mauvaise'), /Clé incorrecte ou fichier modifié/);
});

test('v2 : toute altération est détectée (en-tête ou données)', async () => {
  const enc = await encryptFile(new Uint8Array(100), 'k', { name: 'a' }, FAST);
  for (const pos of [15 + 3, 20, 40, enc.length - 1, enc.length - 30]) {
    const t = enc.slice();
    t[pos] ^= 1;
    await assert.rejects(decryptFile(t, 'k'), `altération à l'octet ${pos}`);
  }
});

test('v2 : mot de passe Unicode, NFC et NFD équivalents', async () => {
  const nfc = 'clé€🔑'.normalize('NFC');
  const nfd = 'clé€🔑'.normalize('NFD');
  assert.notEqual(nfc, nfd);
  const enc = await encryptFile(new Uint8Array([42]), nfc, { name: 'a' }, FAST);
  assert.deepEqual((await decryptFile(enc, nfd)).content, new Uint8Array([42]));
  await assert.rejects(decryptFile(enc, 'clé¬🔑'));
});

test('v2 : version future => message clair', async () => {
  const enc = await encryptFile(new Uint8Array(10), 'k', { name: 'a' }, FAST);
  enc[7] = 3;
  await assert.rejects(decryptFile(enc, 'k'), /plus récente/);
});

test('v2 : gros fichier (8 Mo)', async () => {
  const data = new Uint8Array(8 * 1024 * 1024);
  globalThis.crypto.getRandomValues(data.subarray(0, 65536));
  const enc = await encryptFile(data, 'k', { name: 'big.bin' }, FAST);
  const dec = await decryptFile(enc, 'k');
  assert.equal(sha256(dec.content), sha256(data));
});

// Fichiers témoins v2 commités : garantissent que les versions futures liront la 1.3
const v2Dir = path.join(here, 'fixtures', 'v2');
const v2Manifest = JSON.parse(readFileSync(path.join(v2Dir, 'manifest.json'), 'utf8'));
for (const fx of v2Manifest) {
  test(`v2 (témoin 1.3.0) : ${fx.file}`, async () => {
    const r = await decryptFile(new Uint8Array(readFileSync(path.join(v2Dir, fx.file))), fx.password);
    assert.equal(sha256(r.content), fx.originalSha256);
    assert.equal(r.name, fx.name);
    assert.equal(r.type, fx.type);
  });
}

// ---------------------------------------------------------------------------
// Divers
// ---------------------------------------------------------------------------

test('fichier quelconque non reconnu', () => {
  assert.equal(inspectFile(new TextEncoder().encode('bonjour, ceci est un texte ordinaire !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')), null);
  assert.equal(inspectFile(new Uint8Array(10)), null);
});

test('sanitizeFileName / nameFromEncryptedName', () => {
  assert.equal(sanitizeFileName('..\\..\\evil:name?.txt'), '_.._evil_name_.txt');
  assert.equal(sanitizeFileName(''), 'fichier');
  assert.equal(nameFromEncryptedName('/home/u/doc.pdf.encrypted'), 'doc.pdf');
  assert.equal(nameFromEncryptedName('doc.pdf (2).encrypted'), 'doc.pdf');
  assert.equal(nameFromEncryptedName('doc.pdf'), '');
});
