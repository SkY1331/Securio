export function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} Ko`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} Mo`;
  return `${(bytes / 1024 ** 3).toFixed(2)} Go`;
}

export const errorMessage = (e) => (typeof e === 'string' ? e : e?.message || String(e));

const ext = (name) => (name.includes('.') ? name.split('.').pop().toLowerCase() : '');

const IMAGE = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', webp: 'image/webp', bmp: 'image/bmp', ico: 'image/x-icon', avif: 'image/avif' };
const TEXT = ['txt', 'text', 'md', 'markdown', 'csv', 'tsv', 'log', 'json', 'xml', 'yml', 'yaml', 'ini', 'conf', 'cfg', 'toml', 'html', 'htm', 'css', 'js', 'svg', 'srt', 'vcf', 'ics'];

/** Type d'aperçu possible pour un nom de fichier : 'image' | 'text' | 'pdf' | null. */
export function previewKind(name) {
  const e = ext(name);
  if (IMAGE[e]) return 'image';
  if (TEXT.includes(e)) return 'text';
  if (e === 'pdf') return 'pdf';
  return null;
}

export const imageMime = (name) => IMAGE[ext(name)] || 'application/octet-stream';

export const PREVIEW_MAX = 64 * 1024 * 1024;
