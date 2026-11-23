import { useCallback, useEffect, useState } from 'react';
import FileDropZone from './FileDropZone';
import {
  ENCRYPTED_EXTENSION,
  closeSession,
  encryptFile,
  inspectFile,
  launchFiles,
  onOpenFile,
  onSessionExpired,
  openEncrypted,
  pickSavePath,
  saveDecrypted,
  siblingPath,
} from '../api';
import { MIN_SCORE, evaluatePassword } from '../passwordStrength';

const LEGACY_ALGORITHMS = [
  { value: 'auto', label: 'Détection automatique (recommandé)' },
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-192-cbc', label: 'AES-192-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
];

const FORMAT_LABELS = {
  v3: { text: 'Fichier Securio (format v3 : Argon2id + AES-256-GCM).', color: 'text-green-700' },
  v2: { text: 'Fichier Securio 1.3 (format v2, AES-256-GCM).', color: 'text-green-700' },
  v1: { text: 'Fichier Securio ancien format (v1, ≤ 1.2.1) : lu en mode compatibilité.', color: 'text-amber-700' },
};

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} Ko`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} Mo`;
  return `${(bytes / 1024 ** 3).toFixed(2)} Go`;
}

const message = (e) => (typeof e === 'string' ? e : e?.message || String(e));

function EncryptForm() {
  const [file, setFile] = useState(null); // { path, name, size, inspection }
  const [key, setKey] = useState('');
  const [confirmKey, setConfirmKey] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [legacyAlgorithm, setLegacyAlgorithm] = useState('auto');
  const [forceEncrypt, setForceEncrypt] = useState(false);
  const [busy, setBusy] = useState(null); // libellé de l'opération en cours
  const [progress, setProgress] = useState(null); // { done, total }
  const [opened, setOpened] = useState(null); // résultat de open_encrypted
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [strength, setStrength] = useState(null); // { forKey, score, label, warning, suggestions }

  const format = file?.inspection?.format;
  const mode = format && format !== 'future' && !forceEncrypt ? 'decrypt' : 'encrypt';

  const loadPath = useCallback(async (path) => {
    let summary = null;
    let failure = '';
    try {
      summary = await inspectFile(path);
      if (summary.inspection?.format === 'future') {
        failure = `Ce fichier utilise le format v${summary.inspection.version}, créé par une version plus récente de Securio. Mettez l'application à jour.`;
      }
    } catch (e) {
      failure = message(e);
    }
    await closeSession().catch(() => {});
    setFile(summary);
    setOpened(null);
    setForceEncrypt(false);
    setConfirmKey('');
    setStrength(null);
    setProgress(null);
    setNotice('');
    setError(failure);
  }, []);

  // Fichiers ouverts depuis le système : au lancement (double-clic, « Ouvrir avec »)
  // ou pendant que l'application tourne (transmis par l'instance unique).
  useEffect(() => {
    let cancelled = false;
    let unlisten;
    launchFiles()
      .then((files) => !cancelled && files?.length && loadPath(files[0]))
      .catch((e) => console.error(e));
    onOpenFile((path) => loadPath(path)).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [loadPath]);

  // Le cœur Rust efface le contenu déchiffré / la clé après 5 min d'inactivité
  useEffect(() => {
    let cancelled = false;
    let unlisten;
    // Émis seulement si une session existait
    onSessionExpired(() => {
      setOpened(null);
      setNotice("Par sécurité, le contenu déchiffré a été effacé de la mémoire après 5 minutes d'inactivité.");
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, []);

  // Robustesse de la clé (chiffrement uniquement), calculée après une courte pause de frappe
  useEffect(() => {
    if (mode !== 'encrypt' || !key) return undefined;
    let cancelled = false;
    const timer = setTimeout(async () => {
      const result = await evaluatePassword(key, [file?.name]);
      if (!cancelled) setStrength({ forKey: key, ...result });
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [key, mode, file]);
  const keyStrength = mode === 'encrypt' && strength?.forKey === key ? strength : null;

  const run = async (label, fn) => {
    setError('');
    setNotice('');
    setBusy(label);
    try {
      await fn();
    } catch (e) {
      setError(message(e));
    } finally {
      setBusy(null);
      setProgress(null);
    }
  };

  const handleEncrypt = () =>
    run('Chiffrement…', async () => {
      if (key !== confirmKey) throw new Error('Les deux clés saisies ne correspondent pas.');
      const check = await evaluatePassword(key, [file.name]);
      if (check.score < MIN_SCORE) {
        throw new Error(
          `Clé trop facile à deviner (robustesse : ${check.label.toLowerCase()}). ${check.warning ? `${check.warning} ` : ''}` +
            'Utilisez par exemple une phrase de passe de 4 mots ou plus, sans lien avec vous ni avec le fichier.'
        );
      }
      const output = await pickSavePath(`${file.path}${ENCRYPTED_EXTENSION}`, 'Enregistrer le fichier chiffré');
      if (!output) return;
      setProgress({ done: 0, total: file.size });
      await encryptFile(file.path, output, key, (done) => setProgress({ done, total: file.size }));
      setKey('');
      setConfirmKey('');
      setStrength(null);
      setNotice(`Fichier chiffré enregistré : ${output}`);
    });

  const handleDecrypt = () =>
    run('Vérification de la clé…', async () => {
      setOpened(null);
      setOpened(await openEncrypted(file.path, key, legacyAlgorithm));
      setKey(''); // la clé n'est plus utile côté interface : le cœur Rust a ouvert la session
    });

  const handleSave = (index) =>
    run('Déchiffrement…', async () => {
      const variant = opened.variants[index];
      const output = await pickSavePath(await siblingPath(file.path, variant.name), 'Enregistrer le fichier déchiffré');
      if (!output) return;
      setProgress({ done: 0, total: variant.size });
      await saveDecrypted(opened.session, index, output, (done) => setProgress({ done, total: variant.size }));
      setNotice(`Fichier déchiffré enregistré : ${output}`);
    });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!file) return setError('Veuillez sélectionner un fichier.');
    if (!key) return setError('Veuillez entrer une clé secrète.');
    return mode === 'encrypt' ? handleEncrypt() : handleDecrypt();
  };

  const percent = progress?.total ? Math.min(100, Math.round((progress.done / progress.total) * 100)) : null;

  return (
    <div className="max-w-4xl mx-auto p-4">
      <form className="bg-white rounded-lg shadow-lg p-6" onSubmit={handleSubmit}>
        <h2 className="text-2xl font-bold mb-6">Chiffrement/Déchiffrement de fichiers</h2>

        <div className="space-y-6">
          <div>
            <span className="block text-sm font-medium text-gray-700 mb-2">Fichier à traiter</span>
            <FileDropZone onFile={loadPath} disabled={!!busy} />
            {file && (
              <div className="mt-2 text-sm text-gray-600 space-y-1">
                <div className="break-all">
                  Fichier sélectionné : <strong>{file.name}</strong> ({formatSize(file.size)})
                </div>
                {FORMAT_LABELS[format] && !forceEncrypt && (
                  <div className={FORMAT_LABELS[format].color}>{FORMAT_LABELS[format].text}</div>
                )}
                {format && format !== 'future' && (
                  <button
                    type="button"
                    className="text-xs text-blue-600 underline"
                    onClick={() => {
                      setForceEncrypt((v) => !v);
                      setOpened(null);
                    }}
                  >
                    {forceEncrypt ? 'Revenir au déchiffrement' : 'Chiffrer ce fichier une seconde fois'}
                  </button>
                )}
              </div>
            )}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="key">
              Clé secrète
            </label>
            <div className="flex gap-2">
              <input
                id="key"
                type={showKey ? 'text' : 'password'}
                value={key}
                onChange={(e) => setKey(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="Entrez votre clé secrète"
                autoComplete="off"
              />
              <button
                type="button"
                className="px-3 border rounded-md text-sm text-gray-600"
                onClick={() => setShowKey((v) => !v)}
              >
                {showKey ? 'Masquer' : 'Afficher'}
              </button>
            </div>
            {keyStrength && (
              <div className="mt-2 text-xs" aria-live="polite">
                <div className="flex items-center gap-2">
                  <meter
                    className="w-40 h-2"
                    min={0}
                    max={5}
                    low={2.5}
                    high={3.5}
                    optimum={5}
                    value={keyStrength.score + 1}
                  />
                  <span className={keyStrength.score < MIN_SCORE ? 'text-red-600' : 'text-gray-600'}>
                    Robustesse : {keyStrength.label}
                    {keyStrength.score < MIN_SCORE && ' — insuffisante pour chiffrer'}
                  </span>
                </div>
                {keyStrength.score < 3 && (keyStrength.warning || keyStrength.suggestions.length > 0) && (
                  <p className="mt-1 text-amber-700">
                    {[keyStrength.warning, ...keyStrength.suggestions].filter(Boolean).join(' ')}
                  </p>
                )}
              </div>
            )}
          </div>

          {mode === 'encrypt' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="confirmKey">
                Confirmer la clé
              </label>
              <input
                id="confirmKey"
                type={showKey ? 'text' : 'password'}
                value={confirmKey}
                onChange={(e) => setConfirmKey(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
                placeholder="Saisissez à nouveau la clé"
                autoComplete="off"
              />
              <p className="mt-1 text-xs text-gray-500">Aucune récupération n'est possible en cas d'oubli de la clé.</p>
            </div>
          )}

          {mode === 'decrypt' && format === 'v1' && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="algo">
                Algorithme utilisé à l'époque
              </label>
              <select
                id="algo"
                value={legacyAlgorithm}
                onChange={(e) => setLegacyAlgorithm(e.target.value)}
                className="w-full px-3 py-2 border rounded-md"
              >
                {LEGACY_ALGORITHMS.map((a) => (
                  <option key={a.value} value={a.value}>
                    {a.label}
                  </option>
                ))}
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={!!busy || !file || format === 'future'}
            className={`w-full text-white py-2 px-4 rounded-md disabled:opacity-50 ${
              mode === 'encrypt' ? 'bg-blue-600 hover:bg-blue-700' : 'bg-green-600 hover:bg-green-700'
            }`}
          >
            {busy || (mode === 'encrypt' ? 'Chiffrer…' : 'Déchiffrer')}
          </button>

          {busy && percent !== null && (
            <div>
              <progress className="w-full h-2" value={percent} max={100} />
              <div className="text-xs text-gray-500 mt-1">
                {formatSize(progress.done)} / {formatSize(progress.total)} ({percent} %)
              </div>
            </div>
          )}

          {error && <div className="text-red-600 text-sm">Erreur : {error}</div>}
          {notice && <div className="text-green-700 text-sm break-all">{notice}</div>}

          {opened && mode === 'decrypt' && (
            <div className="mt-4 p-3 border rounded-md bg-gray-50 space-y-3">
              <div className="text-xs text-gray-500">
                Clé correcte · format {opened.format} · {opened.algorithm.toUpperCase()}
              </div>

              {opened.warnings.length > 0 && (
                <ul className="text-xs text-amber-800 list-disc pl-5 space-y-1">
                  {opened.warnings.map((w) => (
                    <li key={w}>{w}</li>
                  ))}
                </ul>
              )}

              {opened.variants.map((v, i) => (
                <div key={v.label} className="flex justify-between items-center gap-4">
                  <div className="text-sm text-gray-700 break-all">
                    <div className={i === 0 ? 'font-medium' : ''}>{v.name}</div>
                    <div className="text-xs text-gray-500">
                      {i > 0 && `${v.label} · `}
                      {formatSize(v.size)}
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={!!busy}
                    onClick={() => handleSave(i)}
                    className={`shrink-0 py-1 px-3 rounded-md disabled:opacity-50 ${
                      i === 0
                        ? 'bg-gray-700 text-white hover:bg-gray-800'
                        : 'border border-gray-400 text-xs hover:bg-gray-100'
                    }`}
                  >
                    {i === 0 ? 'Sauvegarder' : 'Sauvegarder cette version'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </form>
    </div>
  );
}

export default EncryptForm;
