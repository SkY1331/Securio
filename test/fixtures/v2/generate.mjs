// Génère les fichiers témoins v2 (une seule fois ; ne jamais régénérer une fois commités).
import { writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { encryptFile } from '../../../src/utils/cryptoUtils.js';

const data = new Uint8Array(3000).map((_, i) => (i * 13 + 5) & 0xff);
const cases = [
  { file: 'binaire.v2.encrypted', password: 'motdepasse', name: 'Résumé très long de l’équipe — 2026 (final).pdf', type: 'application/pdf' },
  { file: 'mdp-unicode.v2.encrypted', password: 'clé€🔑 secrète', name: 'a.bin', type: 'application/octet-stream' },
];
const manifest = [];
for (const c of cases) {
  writeFileSync(new URL(c.file, import.meta.url), await encryptFile(data, c.password, { name: c.name, type: c.type }));
  manifest.push({ ...c, originalSha256: createHash('sha256').update(data).digest('hex') });
}
writeFileSync(new URL('manifest.json', import.meta.url), JSON.stringify(manifest, null, 2) + '\n');
