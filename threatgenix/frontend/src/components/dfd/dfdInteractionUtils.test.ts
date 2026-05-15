import { describe, expect, it } from "vitest";

import {
  getCanvasFooterHint,
  getHistoryShortcutAction,
  getPaletteToggleTooltip,
  getShortcutSections,
  getSnapToggleTooltip,
  isShortcutHelpKey,
} from "./dfdInteractionUtils";

describe("dfdInteractionUtils", () => {
  it("maps undo and redo shortcuts", () => {
    expect(
      getHistoryShortcutAction({
        key: "z",
        metaKey: true,
        ctrlKey: false,
        altKey: false,
        shiftKey: false,
      })
    ).toBe("undo");
    expect(
      getHistoryShortcutAction({
        key: "Z",
        metaKey: false,
        ctrlKey: true,
        altKey: false,
        shiftKey: true,
      })
    ).toBe("redo");
    expect(
      getHistoryShortcutAction({
        key: "y",
        metaKey: false,
        ctrlKey: true,
        altKey: false,
        shiftKey: false,
      })
    ).toBe("redo");
    expect(
      getHistoryShortcutAction({
        key: "z",
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        shiftKey: false,
      })
    ).toBeNull();
  });

  it("detects the shortcut help hotkey", () => {
    expect(
      isShortcutHelpKey({
        key: "?",
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        shiftKey: true,
      })
    ).toBe(true);
    expect(
      isShortcutHelpKey({
        key: "/",
        metaKey: false,
        ctrlKey: false,
        altKey: false,
        shiftKey: true,
      })
    ).toBe(true);
    expect(
      isShortcutHelpKey({
        key: "?",
        metaKey: true,
        ctrlKey: false,
        altKey: false,
        shiftKey: true,
      })
    ).toBe(false);
  });

  it("builds the right footer hints for editable and read-only canvases", () => {
    expect(
      getCanvasFooterHint({
        isReadOnlyView: false,
        isDecompositionView: false,
        isFullscreen: false,
      })
    ).toContain("hold Shift or S and drag to box-select");
    expect(
      getCanvasFooterHint({
        isReadOnlyView: true,
        isDecompositionView: false,
        isFullscreen: false,
      })
    ).toContain("hold Shift and drag to box-select");
    expect(
      getCanvasFooterHint({
        isReadOnlyView: false,
        isDecompositionView: true,
        isFullscreen: true,
      })
    ).toContain("Decomposition view");
  });

  it("returns toolbar tooltip copy and shortcut sections", () => {
    expect(getPaletteToggleTooltip(true)).toBe("Hide Component Palette");
    expect(getSnapToggleTooltip(false)).toContain("20px grid");
    expect(
      getShortcutSections({
        isReadOnlyView: false,
        isDecompositionView: false,
      })[0]?.items.some((item) => item.keys === "S + drag")
    ).toBe(true);
  });
});
