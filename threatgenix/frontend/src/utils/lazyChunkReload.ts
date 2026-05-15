export function lazyChunkReloadKey(buildCommit?: string | null): string {
  return `threatgenix:lazy-chunk-reload:${buildCommit ?? "unknown"}`;
}

export function isLazyChunkLoadError(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error ?? "");
  return [
    "Failed to fetch dynamically imported module",
    "Importing a module script failed",
    "error loading dynamically imported module",
    "ChunkLoadError",
    "Loading chunk",
  ].some((needle) => message.includes(needle));
}

export function shouldReloadForLazyChunkError(
  error: unknown,
  storage: Pick<Storage, "getItem" | "setItem"> | null | undefined,
  buildCommitOrKey?: string | null,
): boolean {
  if (!isLazyChunkLoadError(error) || !storage) return false;
  const key = buildCommitOrKey?.startsWith("threatgenix:lazy-chunk-reload:")
    ? buildCommitOrKey
    : lazyChunkReloadKey(buildCommitOrKey);
  try {
    if (storage.getItem(key) === "1") return false;
    storage.setItem(key, "1");
    return true;
  } catch {
    return false;
  }
}
