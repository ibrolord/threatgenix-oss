import { describe, expect, it } from "vitest";

import { classificationColor } from "./classification";

describe("classificationColor", () => {
  it("maps classification levels to the updated pilot palette", () => {
    expect(classificationColor("Restricted")).toBe("#7c3aed");
    expect(classificationColor("Confidential")).toBe("#d97706");
    expect(classificationColor("Internal")).toBe("#2563eb");
    expect(classificationColor("Public")).toBe("#059669");
    expect(classificationColor("Unknown")).toBe("#64748b");
  });
});
