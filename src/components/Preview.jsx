import { useEffect, useState } from 'react';
import { previewContent } from '../api';
import { errorMessage, imageMime, previewKind } from '../format';

const TEXT_LIMIT = 2_000_000; // caractères affichés au maximum

/**
 * Aperçu en mémoire du contenu déchiffré : rien n'est écrit sur le disque. Le
 * contenu est libéré à la fermeture. Le texte (y compris HTML/SVG) est affiché
 * brut, jamais interprété.
 */
function Preview({ session, variant, name, onClose }) {
  const kind = previewKind(name);
  const [state, setState] = useState({ loading: true });

  useEffect(() => {
    let url = null;
    let cancelled = false;
    previewContent(session, variant)
      .then((buffer) => {
        if (cancelled) return;
        if (kind === 'text') {
          const text = new TextDecoder('utf-8').decode(buffer);
          setState({ text: text.length > TEXT_LIMIT ? `${text.slice(0, TEXT_LIMIT)}\n\n[… aperçu tronqué]` : text });
        } else {
          url = URL.createObjectURL(new Blob([buffer], { type: kind === 'pdf' ? 'application/pdf' : imageMime(name) }));
          setState({ url });
        }
      })
      .catch((e) => !cancelled && setState({ error: errorMessage(e) }));
    return () => {
      cancelled = true;
      if (url) URL.revokeObjectURL(url);
    };
  }, [session, variant, name, kind]);

  return (
    <div className="mt-3 border rounded-md bg-white">
      <div className="flex justify-between items-center px-3 py-2 border-b bg-gray-50">
        <span className="text-sm font-medium break-all">Aperçu : {name}</span>
        <button type="button" onClick={onClose} className="text-sm text-gray-600 border rounded px-2 hover:bg-gray-100">
          Fermer l'aperçu
        </button>
      </div>
      <div className="p-2">
        {state.loading && <p className="text-sm text-gray-500">Déchiffrement en mémoire…</p>}
        {state.error && <p className="text-sm text-red-600">Erreur : {state.error}</p>}
        {state.text !== undefined && (
          <pre className="text-xs whitespace-pre-wrap break-words max-h-[60vh] overflow-auto">{state.text}</pre>
        )}
        {state.url && kind === 'image' && (
          <img src={state.url} alt={name} className="max-w-full max-h-[60vh] mx-auto" />
        )}
        {state.url && kind === 'pdf' && (
          <>
            <iframe src={state.url} title={name} className="w-full h-[60vh] border-0" />
            <p className="mt-1 text-xs text-gray-500">
              Si le document ne s'affiche pas, enregistrez-le pour l'ouvrir dans votre lecteur PDF.
            </p>
          </>
        )}
      </div>
      <p className="px-3 pb-2 text-xs text-gray-500">
        Le contenu n'est déchiffré qu'en mémoire et libéré à la fermeture de l'aperçu ; il n'est jamais écrit sur le
        disque.
      </p>
    </div>
  );
}

export default Preview;
