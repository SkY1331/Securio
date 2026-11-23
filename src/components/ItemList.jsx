import { formatSize } from '../format';

const FORMAT_BADGES = {
  v3: { text: 'chiffré v3', color: 'bg-green-100 text-green-800' },
  v2: { text: 'chiffré v2 (1.3)', color: 'bg-green-100 text-green-800' },
  v1: { text: 'chiffré v1 (ancien)', color: 'bg-amber-100 text-amber-800' },
  future: { text: 'format plus récent', color: 'bg-red-100 text-red-800' },
};

function Badge({ item }) {
  if (item.isDir) return <span className="px-2 rounded bg-blue-100 text-blue-800">dossier · {item.fileCount} fichier(s)</span>;
  const b = FORMAT_BADGES[item.inspection?.format];
  if (b) return <span className={`px-2 rounded ${b.color}`}>{b.text}</span>;
  return <span className="px-2 rounded bg-gray-100 text-gray-700">fichier</span>;
}

function ItemList({ items, onRemove, onClear, disabled }) {
  if (!items.length) return null;
  return (
    <div className="mt-2 text-sm text-gray-700">
      <ul className="divide-y border rounded-md max-h-48 overflow-y-auto">
        {items.map((item) => (
          <li key={item.path} className="flex items-center gap-2 px-2 py-1">
            <span className="flex-1 break-all" title={item.path}>
              {item.name}
            </span>
            <span className="text-xs text-gray-500 shrink-0">{formatSize(item.size)}</span>
            <span className="text-xs shrink-0">
              <Badge item={item} />
            </span>
            <button
              type="button"
              disabled={disabled}
              onClick={() => onRemove(item.path)}
              className="text-gray-400 hover:text-red-600 px-1"
              aria-label={`Retirer ${item.name}`}
            >
              ×
            </button>
          </li>
        ))}
      </ul>
      {items.length > 1 && (
        <button type="button" disabled={disabled} onClick={onClear} className="mt-1 text-xs text-blue-600 underline">
          Tout retirer
        </button>
      )}
    </div>
  );
}

export default ItemList;
