import { describe, expect, it } from "vitest";

const sourceFiles = import.meta.glob(
  ["./**/*.{css,ts,tsx}", "!./**/*.test.ts", "!./**/*.test.tsx", "!./productIdentity.test.ts"],
  { eager: true, import: "default", query: "?raw" },
) as Record<string, string>;

const rootFiles = import.meta.glob("../index.html", {
  eager: true,
  import: "default",
  query: "?raw",
}) as Record<string, string>;

describe("product identity", () => {
  it("keeps active frontend source branded as ThreatGenix", () => {
    const offenders = Object.entries({ ...rootFiles, ...sourceFiles })
      .filter(([, body]) => body.includes("Semantic Security Review"))
      .map(([file]) => file);

    expect(offenders).toEqual([]);
  });
});
