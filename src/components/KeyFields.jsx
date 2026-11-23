import { useEffect, useState } from 'react';
import { generatePassphrase } from '../api';
import { MIN_SCORE, evaluatePassword } from '../passwordStrength';
import { errorMessage } from '../format';

/**
 * Saisie de clé : affichage/masquage, confirmation, robustesse et générateur de
 * phrase de passe (mode « nouvelle clé »).
 */
function KeyFields({ id, label = 'Clé secrète', value, onChange, confirm, onConfirmChange, isNew, contextNames = [], disabled }) {
  const [show, setShow] = useState(false);
  const [strength, setStrength] = useState(null);
  const [generated, setGenerated] = useState(false);
  const [genError, setGenError] = useState('');
  const contextKey = contextNames.join('|');

  // Robustesse (nouvelle clé uniquement), après une courte pause de frappe
  useEffect(() => {
    if (!isNew || !value) return undefined;
    let cancelled = false;
    const timer = setTimeout(async () => {
      const result = await evaluatePassword(value, contextKey.split('|'));
      if (!cancelled) setStrength({ forKey: value, ...result });
    }, 150);
    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [value, isNew, contextKey]);
  const current = isNew && strength?.forKey === value ? strength : null;

  const generate = async () => {
    try {
      const phrase = await generatePassphrase(6);
      onChange(phrase);
      onConfirmChange?.(phrase);
      setShow(true);
      setGenerated(true);
      setGenError('');
    } catch (e) {
      setGenError(errorMessage(e));
    }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor={id}>
          {label}
        </label>
        <div className="flex gap-2">
          <input
            id={id}
            type={show ? 'text' : 'password'}
            value={value}
            disabled={disabled}
            onChange={(e) => {
              onChange(e.target.value);
              setGenerated(false);
            }}
            className="w-full px-3 py-2 border rounded-md font-mono"
            placeholder="Entrez votre clé secrète"
            autoComplete="off"
            spellCheck={false}
          />
          <button type="button" className="px-3 border rounded-md text-sm text-gray-600" onClick={() => setShow((v) => !v)}>
            {show ? 'Masquer' : 'Afficher'}
          </button>
        </div>
        {isNew && (
          <button type="button" disabled={disabled} onClick={generate} className="mt-1 text-xs text-blue-600 underline">
            Générer une phrase de passe (6 mots)
          </button>
        )}
        {generated && value && (
          <p className="mt-1 text-xs text-amber-800">
            Notez cette phrase de passe maintenant (sur papier ou dans un gestionnaire de mots de passe) : elle ne
            pourra jamais être retrouvée.
          </p>
        )}
        {genError && <p className="mt-1 text-xs text-red-600">{genError}</p>}
        {current && (
          <div className="mt-2 text-xs" aria-live="polite">
            <div className="flex items-center gap-2">
              <meter className="w-40 h-2" min={0} max={5} low={2.5} high={3.5} optimum={5} value={current.score + 1} />
              <span className={current.score < MIN_SCORE ? 'text-red-600' : 'text-gray-600'}>
                Robustesse : {current.label}
                {current.score < MIN_SCORE && ' — insuffisante pour chiffrer'}
              </span>
            </div>
            {current.score < 3 && (current.warning || current.suggestions.length > 0) && (
              <p className="mt-1 text-amber-700">{[current.warning, ...current.suggestions].filter(Boolean).join(' ')}</p>
            )}
          </div>
        )}
      </div>

      {isNew && onConfirmChange && (
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-2" htmlFor={`${id}-confirm`}>
            Confirmer la clé
          </label>
          <input
            id={`${id}-confirm`}
            type={show ? 'text' : 'password'}
            value={confirm}
            disabled={disabled}
            onChange={(e) => onConfirmChange(e.target.value)}
            className="w-full px-3 py-2 border rounded-md font-mono"
            placeholder="Saisissez à nouveau la clé"
            autoComplete="off"
            spellCheck={false}
          />
          <p className="mt-1 text-xs text-gray-500">Aucune récupération n'est possible en cas d'oubli de la clé.</p>
        </div>
      )}
    </div>
  );
}

export default KeyFields;
