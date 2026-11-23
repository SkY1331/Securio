import { useEffect, useState } from 'react';
import { onDragDrop, pickFile } from '../api';

// Zone de dépôt : on ne récupère que le CHEMIN du fichier ; c'est le cœur Rust
// qui le lit, en flux, sans le charger dans l'interface.
function FileDropZone({ onFile, disabled }) {
  const [isDragging, setIsDragging] = useState(false);

  useEffect(() => {
    let unlisten;
    let cancelled = false;
    onDragDrop((event) => {
      if (event.type === 'enter' || event.type === 'over') setIsDragging(true);
      else if (event.type === 'leave') setIsDragging(false);
      else if (event.type === 'drop') {
        setIsDragging(false);
        if (!disabled && event.paths?.length) onFile(event.paths[0]);
      }
    }).then((fn) => {
      if (cancelled) fn();
      else unlisten = fn;
    });
    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [onFile, disabled]);

  const choose = async () => {
    if (disabled) return;
    const path = await pickFile();
    if (path) onFile(path);
  };

  return (
    <button
      type="button"
      onClick={choose}
      disabled={disabled}
      className={`w-full border-2 border-dashed rounded-lg p-4 sm:p-6 text-center transition-colors disabled:opacity-50 ${
        isDragging ? 'border-blue-500 bg-blue-50' : 'border-gray-300 hover:border-gray-400'
      }`}
    >
      <div className="flex flex-col items-center justify-center space-y-2">
        <svg
          className="w-8 h-8 sm:w-12 sm:h-8 text-gray-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          xmlns="http://www.w3.org/2000/svg"
          aria-hidden="true"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={2}
            d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"
          />
        </svg>
        <p className="text-xs sm:text-sm text-gray-600">
          {isDragging ? 'Déposez le fichier ici' : 'Glissez-déposez un fichier ici ou cliquez pour sélectionner'}
        </p>
      </div>
    </button>
  );
}

export default FileDropZone;
