function BatchResults({ title, results }) {
  if (!results?.length) return null;
  const ok = results.filter((r) => r.output).length;
  return (
    <div className="mt-4 p-3 border rounded-md bg-gray-50 text-sm">
      <div className="font-medium mb-2">
        {title} : {ok} / {results.length} réussi(s)
      </div>
      <ul className="space-y-1 max-h-64 overflow-y-auto">
        {results.map((r) => (
          <li key={r.input} className="break-all">
            {r.output ? (
              <span className="text-green-700">✓ {r.output}</span>
            ) : (
              <span className="text-red-600">
                ✗ {r.input} : {r.error}
              </span>
            )}
            {r.originalDeleted && <span className="text-xs text-gray-500"> (original supprimé)</span>}
            {r.warnings?.map((w) => (
              <div key={w} className="text-xs text-amber-800 pl-4">
                {w}
              </div>
            ))}
          </li>
        ))}
      </ul>
    </div>
  );
}

export default BatchResults;
