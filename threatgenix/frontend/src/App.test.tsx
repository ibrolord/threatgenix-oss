import { describe, expect, it } from "vitest";

import { isLazyChunkLoadError, shouldReloadForLazyChunkError } from "./utils/lazyChunkReload";

function memoryStorage(seed: Record<string, string> = {}) {
  return {
    getItem: (key: string) => seed[key] ?? null,
    setItem: (key: string, value: string) => {
      seed[key] = value;
    },
  };
}

describe("lazy chunk reload guard", () => {
  it("detects stale dynamic import failures from deployed chunks", () => {
    expect(
      isLazyChunkLoadError(
        new TypeError(
          "Failed to fetch dynamically imported module: https://threatgenix.vercel.app/assets/DashboardPage-6XOF6_Cr.js",
        ),
      ),
    ).toBe(true);
    expect(isLazyChunkLoadError(new Error("API request failed with 500"))).toBe(false);
  });

  it("allows a single reload per build key", () => {
    const storage = memoryStorage();

    expect(shouldReloadForLazyChunkError(new Error("ChunkLoadError"), storage, "build-a")).toBe(true);
    expect(shouldReloadForLazyChunkError(new Error("ChunkLoadError"), storage, "build-a")).toBe(false);
    expect(shouldReloadForLazyChunkError(new Error("ChunkLoadError"), storage, "build-b")).toBe(true);
  });
});
