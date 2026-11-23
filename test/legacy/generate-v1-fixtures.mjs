// Génère des fichiers .encrypted au format v1 en utilisant le code ORIGINAL de
// Securio 1.2.1 (test/legacy/cryptoUtils.v1.original.js), en reproduisant
// fidèlement la façon dont l'interface lisait les fichiers :
//   - text/* et *.txt  -> FileReader.readAsText    (chaîne UTF-16)
//   - image/*          -> FileReader.readAsDataURL (chaîne "data:...;base64,...")
//   - le reste         -> FileReader.readAsArrayBuffer
//
// Usage : node test/legacy/generate-v1-fixtures.mjs
// Les fichiers produits sont commités : ils ne doivent normalement jamais être
// régénérés (le sel et l'IV sont aléatoires).

import { writeFileSync, mkdirSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

globalThis.window = globalThis;
const { encrypt } = await import('./cryptoUtils.v1.original.js');

const here = path.dirname(fileURLToPath(import.meta.url));
const outDir = path.join(here, '..', 'fixtures', 'v1');
mkdirSync(outDir, { recursive: true });

const sha256 = (buf) => createHash('sha256').update(Buffer.from(buf)).digest('hex');

// Contenus d'origine (octets tels qu'ils étaient sur le disque de l'utilisateur)
const allBytes = new Uint8Array(1000).map((_, i) => (i * 37 + 11) & 0xff);
const utf8Text = 'Bonjour Securio !\nAccents : é è à ç ù ô « guillemets »\n';
const utf8TextLossy = 'Prix : 10 € — l’apostrophe typographique 😀\n';
// Un mini PNG 1x1 (octets réels)
const png = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
  'base64'
);

const cases = [
  {
    file: 'binaire-aes256.bin.encrypted',
    name: 'binaire.bin', type: 'application/octet-stream',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: allBytes, read: 'arraybuffer',
  },
  {
    file: 'binaire-aes192.bin.encrypted',
    name: 'binaire.bin', type: 'application/octet-stream',
    password: 'motdepasse', algorithm: 'aes-192-cbc',
    original: allBytes, read: 'arraybuffer',
  },
  {
    file: 'binaire-aes128.bin.encrypted',
    name: 'binaire.bin', type: 'application/octet-stream',
    password: 'motdepasse', algorithm: 'aes-128-cbc',
    original: allBytes, read: 'arraybuffer',
  },
  {
    file: 'mdp-accentue.bin.encrypted',
    name: 'binaire.bin', type: 'application/octet-stream',
    password: 'clé€secrète', algorithm: 'aes-256-cbc',
    original: allBytes, read: 'arraybuffer',
  },
  {
    file: 'nom-long.pdf.encrypted',
    name: 'Rapport annuel confidentiel 2024 version finale.pdf', type: 'application/pdf',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: allBytes.slice(0, 100), read: 'arraybuffer',
  },
  {
    file: 'nom-accentue-tronque.docx.encrypted',
    name: 'Résumé des réunions de l’équipe été.docx', type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: allBytes.slice(0, 50), read: 'arraybuffer',
  },
  {
    file: 'vide.bin.encrypted',
    name: 'vide.bin', type: 'application/octet-stream',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: new Uint8Array(0), read: 'arraybuffer',
  },
  {
    file: 'texte-latin1.txt.encrypted',
    name: 'notes.txt', type: 'text/plain',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: new TextEncoder().encode(utf8Text), read: 'text',
  },
  {
    file: 'texte-avec-pertes.txt.encrypted',
    name: 'pertes.txt', type: 'text/plain',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: new TextEncoder().encode(utf8TextLossy), read: 'text',
  },
  {
    file: 'image.png.encrypted',
    name: 'photo.png', type: 'image/png',
    password: 'motdepasse', algorithm: 'aes-256-cbc',
    original: new Uint8Array(png), read: 'dataurl',
  },
];

const manifest = [];
for (const c of cases) {
  let input;
  if (c.read === 'text') {
    input = new TextDecoder().decode(c.original); // = readAsText (UTF-8)
  } else if (c.read === 'dataurl') {
    input = `data:${c.type};base64,${Buffer.from(c.original).toString('base64')}`; // = readAsDataURL
  } else {
    input = c.original.slice().buffer; // = readAsArrayBuffer
  }
  const out = await encrypt(input, c.password, c.algorithm, c.type, c.name);
  writeFileSync(path.join(outDir, c.file), Buffer.from(out));
  manifest.push({
    file: c.file,
    password: c.password,
    algorithm: c.algorithm,
    originalName: c.name,
    readMode: c.read,
    originalSha256: sha256(c.original),
    originalBase64: Buffer.from(c.original).toString('base64'),
  });
  console.log('écrit', c.file);
}

writeFileSync(path.join(outDir, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
