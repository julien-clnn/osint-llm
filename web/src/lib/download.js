// Client-side download from an in-memory string (no server round trip).
// The report data already lives in React state, so clicking an export button
// never re-runs the analysis and never clears anything.
export function downloadText(filename, text, mime) {
  const blob = new Blob([text], { type: `${mime};charset=utf-8` });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  // Give the browser time to start the download before revoking the URL.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
