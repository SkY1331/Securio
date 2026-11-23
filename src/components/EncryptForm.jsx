import { useCallback, useEffect, useRef, useState } from 'react';
import FileDropZone from './FileDropZone';
import ItemList from './ItemList';
import KeyFields from './KeyFields';
import { assertNewKey } from '../passwordStrength';
import Preview from './Preview';
import BatchResults from './BatchResults';
import {
  ENCRYPTED_EXTENSION,
  closeSession,
  confirmDialog,
  convertToV3,
  decryptMany,
  encryptArchive,
  encryptFile,
  encryptSeparately,
  extractArchive,
  inspectFile,
  onOpenRequests,
  onSessionExpired,
  openEncrypted,
  parentOf,
  pickFolder,
  pickSavePath,
  saveDecrypted,
  siblingPath,
  takePendingRequests,
} from '../api';
import { PREVIEW_MAX, errorMessage, formatSize, previewKind } from '../format';

const LEGACY_ALGORITHMS = [
  { value: 'auto', label: 'Détection automatique (recommandé)' },
  { value: 'aes-256-cbc', label: 'AES-256-CBC' },
  { value: 'aes-192-cbc', label: 'AES-192-CBC' },
  { value: 'aes-128-cbc', label: 'AES-128-CBC' },
];

const isEncrypted = (item) => !item.isDir && item.inspection && item.inspection.format !== 'future';

function EncryptForm() {
  const [items, setItems] = useState([]); // résultats de inspect_file
  const [key, setKey] = useState('');
  const [confirmKey, setConfirmKey] = useState('');
  const [legacyAlgorithm, setLegacyAlgorithm] = useState('auto');
  const [forceEncrypt, setForceEncrypt] = useState(false);
  const [groupMode, setGroupMode] = useState('separate'); // 'separate' | 'archive'
  const [deleteOriginal, setDeleteOriginal] = useState(false);
  const [busy, setBusy] = useState(null);
  const [progress, setProgress] = useState(null); // { done, total, label }
  const [opened, setOpened] = useState(null);
  const [previewIndex, setPreviewIndex] = useState(null);
  const [convert, setConvert] = useState(null); // { key, confirm }
  const [results, setResults] = useState(null); // { title, list }
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  // Après un travail terminé (résultat affiché), de nouveaux éléments démarrent une
  // nouvelle sélection au lieu de s'ajouter aux anciens.
  const workDone = useRef(false);
  useEffect(() => {
    workDone.current = Boolean(opened || results || notice);
  }, [opened, results, notice]);

  // ---------------------------------------------------------------- mode
  const hasDir = items.some((i) => i.isDir);
  const encryptedCount = items.filter(isEncrypted).length;
  const future = items.find((i) => i.inspection?.format === 'future');
  let mode = 'none';
  if (items.length) {
    if (future) mode = 'future';
    else if (forceEncrypt || encryptedCount === 0) mode = items.length === 1 && !hasDir ? 'encrypt' : 'encrypt-batch';
    else if (encryptedCount === items.length) mode = items.length === 1 ? 'decrypt' : 'decrypt-batch';
    else mode = 'mixed';
  }
  const encrypting = mode === 'encrypt' || mode === 'encrypt-batch';
  const effectiveGroup = hasDir ? 'archive' : groupMode;
  const canDelete = mode === 'encrypt' || (mode === 'encrypt-batch' && !hasDir);
  const hasLegacy = items.some((i) => i.inspection?.format === 'v1');
  const contextNames = items.map((i) => i.name);

  const resetResults = () => {
    setOpened(null);
    setPreviewIndex(null);
    setConvert(null);
    setResults(null);
    setProgress(null);
    setNotice('');
    setError('');
  };

  // ---------------------------------------------------------------- ajout d'éléments
  const addPaths = useCallback(async (paths, { encrypt = false } = {}) => {
    const settled = await Promise.allSettled(paths.map((p) => inspectFile(p)));
    const added = settled.filter((s) => s.status === 'fulfilled').map((s) => s.value);
    const failures = settled.filter((s) => s.status === 'rejected').map((s, i) => `${paths[i]} : ${errorMessage(s.reason)}`);
    await closeSession().catch(() => {});
    const replace = workDone.current;
    workDone.current = false;
    setItems((prev) => {
      const base = replace ? [] : prev;
      const known = new Set(base.map((i) => i.path));
      return [...base, ...added.filter((i) => !known.has(i.path))];
    });
    if (replace) setForceEncrypt(encrypt);
    else if (encrypt) setForceEncrypt(true);
    setOpened(null);
    setPreviewIndex(null);
    setConvert(null);
    setResults(null);
    setProgress(null);
    setNotice('');
    setError(failures.join('\n'));
  }, []);

  const onPaths = useCallback((paths) => addPaths(paths), [addPaths]);

  // Fichiers envoyés par le système : lancement, double-clic, clic droit de l'Explorateur
  useEffect(() => {
    let cancelled = false;
    let unlisten;
    const drain = async () => {
      const requests = await takePendingRequests().catch(() => []);
      const toOpen = requests.filter((r) => r.action === 'open').map((r) => r.path);
      const toEncrypt = requests.filter((r) => r.action === 'encrypt').map((r) => r.path);
      if (toEncrypt.length) await addPaths(toEncrypt, { encrypt: true });
      if (toOpen.length) await addPaths(toOpen);
    };
    drain();
    onOpenRequests(drain).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [addPaths]);

  // Le cœur Rust efface le contenu déchiffré / la clé après 5 min d'inactivité
  useEffect(() => {
    let cancelled = false;
    let unlisten;
    onSessionExpired(() => {
      setOpened(null);
      setPreviewIndex(null);
      setConvert(null);
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

  const removeItem = (path) => {
    closeSession().catch(() => {});
    setItems((prev) => prev.filter((i) => i.path !== path));
    resetResults();
  };
  const clearItems = () => {
    closeSession().catch(() => {});
    setItems([]);
    setForceEncrypt(false);
    resetResults();
  };

  // ---------------------------------------------------------------- exécution
  const run = async (label, fn) => {
    setError('');
    setNotice('');
    setBusy(label);
    try {
      await fn();
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(null);
      setProgress(null);
    }
  };

  const confirmDeletion = async (several) => {
    if (!deleteOriginal || !canDelete) return true;
    return confirmDialog(
      `${several ? 'Les fichiers d’origine seront écrasés puis supprimés' : 'Le fichier d’origine sera écrasé puis supprimé'} ` +
        'définitivement (sans corbeille), après vérification complète du fichier chiffré.\n\n' +
        'Sur un SSD ou une clé USB, des traces peuvent malgré tout subsister sur le support.\n\nContinuer ?'
    );
  };

  const encryptSingle = () =>
    run('Chiffrement…', async () => {
      const item = items[0];
      await assertNewKey(key, confirmKey, contextNames);
      if (!(await confirmDeletion(false))) return;
      const output = await pickSavePath(`${item.path}${ENCRYPTED_EXTENSION}`, 'Enregistrer le fichier chiffré');
      if (!output) return;
      setProgress({ done: 0, total: item.size, label: item.name });
      const res = await encryptFile(item.path, output, key, deleteOriginal, (done) =>
        setProgress({ done, total: item.size, label: item.name })
      );
      setKey('');
      setConfirmKey('');
      setItems([]);
      setForceEncrypt(false);
      setNotice(`Fichier chiffré enregistré : ${res.output}${res.originalDeleted ? ' — original supprimé.' : ''}`);
    });

  const encryptBatch = () =>
    run('Chiffrement…', async () => {
      await assertNewKey(key, confirmKey, contextNames);
      if (!(await confirmDeletion(true))) return;
      const paths = items.map((i) => i.path);
      const total = items.reduce((s, i) => s + i.size, 0);
      if (effectiveGroup === 'archive') {
        const name = items.length === 1 ? `${items[0].name}.tar` : `${items.length} éléments.tar`;
        const output = await pickSavePath(
          await siblingPath(items[0].path, `${name}${ENCRYPTED_EXTENSION}`),
          'Enregistrer l’archive chiffrée'
        );
        if (!output) return;
        setProgress({ done: 0, total, label: 'archive' });
        const res = await encryptArchive(paths, output, key, deleteOriginal && canDelete, (done) =>
          setProgress((p) => ({ done, total: Math.max(p?.total || 0, done), label: 'archive' }))
        );
        setNotice(
          `Archive chiffrée enregistrée : ${res.output} (${res.summary.files} fichier(s), ${res.summary.dirs} dossier(s), ` +
            `${formatSize(res.summary.bytes)})` +
            (res.originalsDeleted ? ` — ${res.originalsDeleted} original(aux) supprimé(s).` : '.') +
            (res.warnings.length ? `\n${res.warnings.join('\n')}` : '')
        );
        setItems([]);
        setForceEncrypt(false);
      } else {
        setProgress({ done: 0, total, label: '' });
        const list = await encryptSeparately(paths, key, deleteOriginal && canDelete, (p) =>
          setProgress({ done: p.done, total: p.total, label: `${p.index + 1}/${p.count} · ${p.name}` })
        );
        setResults({ title: 'Chiffrement', list });
        // en cas d'échec partiel, seuls les éléments en erreur restent dans la liste
        const failed = new Set(list.filter((r) => !r.output).map((r) => r.input));
        setItems((prev) => prev.filter((i) => failed.has(i.path)));
        setForceEncrypt(false);
      }
      setKey('');
      setConfirmKey('');
    });

  const decryptSingle = () =>
    run('Vérification de la clé…', async () => {
      if (!key) throw new Error('Veuillez entrer une clé secrète.');
      setOpened(null);
      setPreviewIndex(null);
      setConvert(null);
      setOpened(await openEncrypted(items[0].path, key, legacyAlgorithm));
      setKey(''); // la clé n'est plus utile côté interface : le cœur Rust a ouvert la session
    });

  const decryptBatch = () =>
    run('Déchiffrement…', async () => {
      if (!key) throw new Error('Veuillez entrer une clé secrète.');
      const dir = await pickFolder('Choisir où enregistrer les fichiers déchiffrés', await parentOf(items[0].path));
      if (!dir) return;
      const total = items.reduce((s, i) => s + i.size, 0);
      setProgress({ done: 0, total, label: '' });
      const list = await decryptMany(
        items.map((i) => i.path),
        key,
        legacyAlgorithm,
        dir,
        (p) => setProgress({ done: p.done, total: p.total, label: `${p.index + 1}/${p.count} · ${p.name}` })
      );
      setKey('');
      setResults({ title: 'Déchiffrement', list });
      const failed = new Set(list.filter((r) => !r.output).map((r) => r.input));
      setItems((prev) => prev.filter((i) => failed.has(i.path)));
    });

  const saveVariant = (index) =>
    run('Déchiffrement…', async () => {
      const variant = opened.variants[index];
      const output = await pickSavePath(await siblingPath(items[0].path, variant.name), 'Enregistrer le fichier déchiffré');
      if (!output) return;
      setProgress({ done: 0, total: variant.size, label: variant.name });
      await saveDecrypted(opened.session, index, output, (done) =>
        setProgress({ done, total: variant.size, label: variant.name })
      );
      setNotice(`Fichier déchiffré enregistré : ${output}`);
    });

  const extract = () =>
    run('Extraction…', async () => {
      const parent = await pickFolder('Choisir où extraire le dossier', await parentOf(items[0].path));
      if (!parent) return;
      const total = opened.variants[0].size;
      setProgress({ done: 0, total, label: opened.variants[0].name });
      const res = await extractArchive(opened.session, parent, (done) =>
        setProgress({ done, total, label: opened.variants[0].name })
      );
      const s = res.summary;
      setNotice(
        `Archive extraite : ${res.output} (${s.files} fichier(s), ${s.dirs} dossier(s))` +
          (s.skipped ? ` — ${s.skipped} élément(s) non sûrs ignorés (liens, chemins invalides).` : '.')
      );
    });

  const doConvert = () =>
    run('Conversion…', async () => {
      const item = items[0];
      await assertNewKey(convert.key, convert.confirm, contextNames);
      const output = await pickSavePath(item.path, 'Enregistrer le fichier converti (v3)');
      if (!output) return;
      await convertToV3(opened.session, 0, output, convert.key);
      setConvert(null);
      if (output === item.path) {
        const refreshed = await inspectFile(item.path);
        await closeSession().catch(() => {});
        setOpened(null);
        setItems([refreshed]);
        setNotice(`Fichier converti au format v3 (Argon2id + AES-256-GCM) : ${output}`);
      } else {
        setNotice(`Copie au format v3 enregistrée : ${output}. L'ancien fichier est conservé.`);
      }
    });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (mode === 'encrypt') return encryptSingle();
    if (mode === 'encrypt-batch') return encryptBatch();
    if (mode === 'decrypt') return decryptSingle();
    if (mode === 'decrypt-batch') return decryptBatch();
    return undefined;
  };

  // ---------------------------------------------------------------- rendu
  const percent = progress?.total ? Math.min(100, Math.round((progress.done / progress.total) * 100)) : null;
  const submitLabel = {
    encrypt: 'Chiffrer…',
    'encrypt-batch': effectiveGroup === 'archive' ? 'Créer l’archive chiffrée…' : `Chiffrer les ${items.length} fichiers`,
    decrypt: 'Déchiffrer',
    'decrypt-batch': `Déchiffrer les ${items.length} fichiers…`,
  }[mode];
  const variant0 = opened?.variants[0];
  const legacyOpened = opened && (opened.format === 'v1' || opened.format === 'v2');

  return (
    <div className="max-w-4xl mx-auto p-4">
      <form className="bg-white rounded-lg shadow-lg p-6" onSubmit={handleSubmit}>
        <h2 className="text-2xl font-bold mb-6">Chiffrement/Déchiffrement de fichiers</h2>

        <div className="space-y-6">
          <div>
            <span className="block text-sm font-medium text-gray-700 mb-2">Fichiers à traiter</span>
            <FileDropZone onPaths={onPaths} disabled={!!busy} />
            <ItemList items={items} onRemove={removeItem} onClear={clearItems} disabled={!!busy} />
            {mode === 'mixed' && (
              <p className="mt-2 text-sm text-amber-700">
                Sélection mixte : retirez soit les fichiers chiffrés, soit les autres, ou{' '}
                <button type="button" className="underline" onClick={() => setForceEncrypt(true)}>
                  chiffrer l'ensemble
                </button>
                .
              </p>
            )}
            {mode === 'future' && (
              <p className="mt-2 text-sm text-red-600">
                « {future.name} » utilise le format v{future.inspection.version}, créé par une version plus récente de
                Securio. Mettez l'application à jour.
              </p>
            )}
            {encryptedCount > 0 && (mode === 'decrypt' || mode === 'decrypt-batch' || forceEncrypt) && (
              <button
                type="button"
                className="mt-1 text-xs text-blue-600 underline"
                onClick={() => {
                  setForceEncrypt((v) => !v);
                  resetResults();
                }}
              >
                {forceEncrypt ? 'Revenir au déchiffrement' : 'Chiffrer une seconde fois'}
              </button>
            )}
          </div>

          {(encrypting || mode === 'decrypt' || mode === 'decrypt-batch') && (
            <KeyFields
              id="key"
              value={key}
              onChange={setKey}
              confirm={confirmKey}
              onConfirmChange={encrypting ? setConfirmKey : undefined}
              isNew={encrypting}
              contextNames={contextNames}
              disabled={!!busy}
            />
          )}

          {mode === 'encrypt-batch' && (
            <fieldset className="text-sm space-y-1">
              <legend className="font-medium text-gray-700 mb-1">Mode</legend>
              <label className={`flex items-center gap-2 ${hasDir ? 'text-gray-400' : ''}`}>
                <input
                  type="radio"
                  name="group"
                  disabled={hasDir}
                  checked={effectiveGroup === 'separate'}
                  onChange={() => setGroupMode('separate')}
                />
                Chiffrer chaque fichier séparément (à côté de l'original)
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  name="group"
                  checked={effectiveGroup === 'archive'}
                  onChange={() => setGroupMode('archive')}
                />
                Tout regrouper dans une archive chiffrée (.tar)
              </label>
              {hasDir && <p className="text-xs text-gray-500">Les dossiers sont toujours regroupés dans une archive.</p>}
            </fieldset>
          )}

          {canDelete && (
            <div className="text-sm">
              <label className="flex items-center gap-2">
                <input type="checkbox" checked={deleteOriginal} onChange={(e) => setDeleteOriginal(e.target.checked)} />
                Supprimer {items.length > 1 ? 'les fichiers' : 'le fichier'} d'origine après vérification du chiffrement
              </label>
              {deleteOriginal && (
                <p className="mt-1 text-xs text-amber-800">
                  Écrasé puis supprimé définitivement (sans corbeille). Sur SSD ou clé USB, des traces peuvent subsister
                  sur le support : pour une garantie complète, utilisez un disque chiffré (BitLocker).
                </p>
              )}
            </div>
          )}

          {(mode === 'decrypt' || mode === 'decrypt-batch') && hasLegacy && (
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor="algo">
                Algorithme utilisé à l'époque (anciens fichiers)
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

          {submitLabel && (
            <button
              type="submit"
              disabled={!!busy}
              className={`w-full text-white py-2 px-4 rounded-md disabled:opacity-50 ${
                encrypting ? 'bg-blue-600 hover:bg-blue-700' : 'bg-green-600 hover:bg-green-700'
              }`}
            >
              {busy || submitLabel}
            </button>
          )}

          {busy && percent !== null && (
            <div>
              <progress className="w-full h-2" value={percent} max={100} />
              <div className="text-xs text-gray-500 mt-1 break-all">
                {progress.label && `${progress.label} · `}
                {formatSize(progress.done)} / {formatSize(progress.total)} ({percent} %)
              </div>
            </div>
          )}

          {error && <div className="text-red-600 text-sm whitespace-pre-line">Erreur : {error}</div>}
          {notice && <div className="text-green-700 text-sm break-all whitespace-pre-line">{notice}</div>}

          <BatchResults title={results?.title} results={results?.list} />

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

              {opened.isArchive ? (
                <div className="flex flex-wrap justify-between items-center gap-2">
                  <div className="text-sm text-gray-700 break-all">
                    <div className="font-medium">{variant0.name}</div>
                    <div className="text-xs text-gray-500">Archive chiffrée · {formatSize(variant0.size)}</div>
                  </div>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={!!busy}
                      onClick={extract}
                      className="py-1 px-3 rounded-md bg-gray-700 text-white hover:bg-gray-800 disabled:opacity-50"
                    >
                      Extraire dans un dossier…
                    </button>
                    <button
                      type="button"
                      disabled={!!busy}
                      onClick={() => saveVariant(0)}
                      className="py-1 px-3 rounded-md border border-gray-400 text-xs hover:bg-gray-100 disabled:opacity-50"
                    >
                      Enregistrer le .tar
                    </button>
                  </div>
                </div>
              ) : (
                opened.variants.map((v, i) => {
                  const canPreview = previewKind(v.name) && v.size <= PREVIEW_MAX;
                  return (
                    <div key={v.label} className="flex flex-wrap justify-between items-center gap-2">
                      <div className="text-sm text-gray-700 break-all">
                        <div className={i === 0 ? 'font-medium' : ''}>{v.name}</div>
                        <div className="text-xs text-gray-500">
                          {i > 0 && `${v.label} · `}
                          {formatSize(v.size)}
                        </div>
                      </div>
                      <div className="flex gap-2">
                        {canPreview && (
                          <button
                            type="button"
                            disabled={!!busy}
                            onClick={() => setPreviewIndex(previewIndex === i ? null : i)}
                            className="py-1 px-3 rounded-md border border-gray-400 text-xs hover:bg-gray-100"
                          >
                            {previewIndex === i ? 'Masquer l’aperçu' : 'Aperçu'}
                          </button>
                        )}
                        <button
                          type="button"
                          disabled={!!busy}
                          onClick={() => saveVariant(i)}
                          className={`py-1 px-3 rounded-md disabled:opacity-50 ${
                            i === 0
                              ? 'bg-gray-700 text-white hover:bg-gray-800'
                              : 'border border-gray-400 text-xs hover:bg-gray-100'
                          }`}
                        >
                          {i === 0 ? 'Sauvegarder' : 'Sauvegarder cette version'}
                        </button>
                      </div>
                    </div>
                  );
                })
              )}

              {previewIndex !== null && opened.variants[previewIndex] && (
                <Preview
                  session={opened.session}
                  variant={previewIndex}
                  name={opened.variants[previewIndex].name}
                  onClose={() => setPreviewIndex(null)}
                />
              )}

              {legacyOpened && !convert && (
                <div className="pt-2 border-t text-sm">
                  <p className="text-xs text-gray-600 mb-1">
                    Ce fichier utilise un ancien format ({opened.format}), moins résistant aux attaques par force brute
                    {opened.format === 'v1' ? ' et sans contrôle d’intégrité' : ''}.
                  </p>
                  <button
                    type="button"
                    disabled={!!busy}
                    onClick={() => setConvert({ key: '', confirm: '' })}
                    className="py-1 px-3 rounded-md border border-blue-500 text-blue-700 text-xs hover:bg-blue-50"
                  >
                    Convertir au format v3…
                  </button>
                </div>
              )}

              {legacyOpened && convert && (
                <div className="pt-3 border-t space-y-3">
                  <p className="text-sm font-medium">Conversion au format v3</p>
                  <p className="text-xs text-gray-600">
                    Choisissez la clé du nouveau fichier (vous pouvez reprendre l'ancienne si elle est assez robuste).
                    Enregistrez-le à la place de l'ancien pour le remplacer : celui-ci n'est remplacé qu'une fois le
                    nouveau entièrement écrit et vérifié.
                  </p>
                  <KeyFields
                    id="convert-key"
                    label="Clé du fichier converti"
                    value={convert.key}
                    onChange={(v) => setConvert((c) => ({ ...c, key: v }))}
                    confirm={convert.confirm}
                    onConfirmChange={(v) => setConvert((c) => ({ ...c, confirm: v }))}
                    isNew
                    contextNames={contextNames}
                    disabled={!!busy}
                  />
                  <div className="flex gap-2">
                    <button
                      type="button"
                      disabled={!!busy}
                      onClick={doConvert}
                      className="py-1 px-3 rounded-md bg-blue-600 text-white text-sm hover:bg-blue-700 disabled:opacity-50"
                    >
                      Convertir…
                    </button>
                    <button
                      type="button"
                      onClick={() => setConvert(null)}
                      className="py-1 px-3 rounded-md border text-sm hover:bg-gray-100"
                    >
                      Annuler
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </form>
    </div>
  );
}

export default EncryptForm;
