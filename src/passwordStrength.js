// Estimation de la robustesse d'une clé (zxcvbn-ts, dictionnaires français et anglais).
// Chargé à la demande : les dictionnaires ne pèsent rien au démarrage de l'application.

let factoryPromise = null;

function loadFactory() {
  factoryPromise ??= Promise.all([
    import('@zxcvbn-ts/core'),
    import('@zxcvbn-ts/language-common'),
    import('@zxcvbn-ts/language-fr'),
    import('@zxcvbn-ts/language-en'),
  ]).then(([core, common, fr, en]) =>
    new core.ZxcvbnFactory({
      translations: fr.translations,
      graphs: common.adjacencyGraphs,
      dictionary: { ...common.dictionary, ...en.dictionary, ...fr.dictionary },
      useLevenshteinDistance: true,
    })
  );
  return factoryPromise;
}

/** Score minimal exigé pour chiffrer (0 à 4). */
export const MIN_SCORE = 2;

export const SCORE_LABELS = ['Très faible', 'Faible', 'Moyenne', 'Bonne', 'Excellente'];

/**
 * @param {string} password
 * @param {string[]} userInputs mots liés au contexte (nom du fichier…) à ne pas utiliser
 * @returns {Promise<{score:number, label:string, warning:string|null, suggestions:string[]}>}
 */
export async function evaluatePassword(password, userInputs = []) {
  const zxcvbn = await loadFactory();
  const words = ['securio', ...userInputs].flatMap((s) => String(s || '').split(/[^\p{L}\p{N}]+/u)).filter((w) => w.length >= 3);
  const r = zxcvbn.check(password, words);
  return {
    score: r.score,
    label: SCORE_LABELS[r.score],
    warning: r.feedback.warning,
    suggestions: r.feedback.suggestions,
  };
}
