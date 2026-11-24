// Construit crates/securio-core/src/wordlist_fr.txt (générateur de phrases de passe).
// Source : liste de fréquences françaises de zxcvbn-ts (@zxcvbn-ts/language-fr, licence MIT).
// Usage : node tools/build-wordlist.mjs   (résultat déterministe)
import { writeFileSync } from 'node:fs';

const fr = (await import('@zxcvbn-ts/language-fr')).dictionary;
const en = (await import('@zxcvbn-ts/language-en')).dictionary;
const lower = (a) => new Set((a || []).map((x) => String(x).toLowerCase()));
const words = fr['commonWords-fr'];
const names = new Set([...lower(fr['firstnames-fr']), ...lower(fr['lastnames-fr']), ...lower(en['firstnames-en']), ...lower(en['lastnames-en'])]);
const english = new Set([...lower(en['commonWords-en']), ...lower(en['wikipedia-en'])]);
const deaccent = (s) => s.normalize('NFD').replace(/[̀-ͯ]/g, '');
// Mot sans accent alors qu'une forme accentuée plus fréquente existe (ex. « tres » pour « très »)
const accentedRank = new Map();
words.forEach((x, i) => {
  if (/[à-ÿ]/.test(x) && !accentedRank.has(deaccent(x))) accentedRank.set(deaccent(x), i);
});
// Grossièretés, violence, religion, insultes…
const blocked = /(merde|putain|pute|salop|connar|conne|bite|couill|encul|chier|chiant|niqu|fout|bordel|branl|baise|suce|sucer|nazi|hitler|negr|pede|tapette|gouine|viol|suicid|cocain|heroin|drogu|cadavr|meurtr|tuer|tueu|tuee|buter|assassin|tortur|sexe|sexy|nichon|fuck|shit|damn|bitch|dick|cock|pussy|whore|slut|kill|porn|penis|vagin|seins|crev|batard|abruti|debil|idiot|imbecil|cretin|cancer|guerre|bombe|flingu|fusil|pistolet|sang|saign|inject|terror|otage|enfer|diable|satan|dieu|allah|jesus|christ|bouddh|juif|juive|arabe|musulman|chretien|catholiq|islam|gros|grosse|moche|laid|stupide|nul|nulle|haine|hais|mort|mour|meur|pendu|noye|cul|plouc)/;

// Mots sensibles supplémentaires (violence, maladie, deuil, insultes, sexualité…)
const blockedWords = /^(racis.*|salaud.*|garces?|esclav.*|pervers.*|ordures?|vomi.*|attentats?|explos.*|couteaux?|poignards?|ivres?|ivrogne.*|ivresse|sadiques?|seringues?|avort.*|bouffons?|zizi|clopes?|tabass.*|gifl.*|fouett.*|cercueils?|tombeaux?|deuil|orphelin.*|victimes?|terreur|horreurs?|menac.*|malad.*|fesses?|enceinte|amants?|nues?|pourri|pourrie|pourris|pourries|pourrir|soldats?|ennemi.*|armes?|armement|tireurs?|cruel.*|bless.*|fourrer|alcool.*|cogner|frapper|punir|pendre|venger|enterrer|exploser|nuire|toxique|poison|prison|crimes?|criminel.*|voleurs?|police|flics?|mafia|gangs?|ennemi|vador|hitler|staline|crottes?)$/;

const out = [];
const seen = new Set();
for (const [i, w] of words.entries()) {
  if (!/^[a-z]{4,8}$/.test(w) || names.has(w) || english.has(w) || blocked.test(w) || blockedWords.test(w) || seen.has(w)) continue;
  if (accentedRank.has(w) && accentedRank.get(w) < i) continue;
  seen.add(w);
  out.push(w);
  if (out.length === 4096) break;
}
if (out.length !== 4096) throw new Error(`seulement ${out.length} mots`);
writeFileSync(new URL('../crates/securio-core/src/wordlist_fr.txt', import.meta.url), out.join('\n') + '\n');
console.log('4096 mots écrits');
