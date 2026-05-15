import type { ComponentProps } from "react";

import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { DFDToolbar } from "./DFDToolbar";

function renderToolbar(
  overrides: Partial<ComponentProps<typeof DFDToolbar>> = {}
) {
  const props: ComponentProps<typeof DFDToolbar> = {
    onOpenTemplates: vi.fn(),
    onAddNode: vi.fn(),
    onTogglePalette: vi.fn(),
    onShowShortcuts: vi.fn(),
    onUndo: vi.fn(),
    onRedo: vi.fn(),
    onAutoLayout: vi.fn(),
    onToggleSnap: vi.fn(),
    onBulkEdit: vi.fn(),
    onDeleteSelected: vi.fn(),
    onCreateBoundary: vi.fn(),
    onSave: vi.fn(),
    saveStatus: "idle",
    hasNodes: true,
    hasSelection: true,
    canCreateBoundary: true,
    canBulkEdit: true,
    canUndo: true,
    canRedo: true,
    ...overrides,
  };

  render(<DFDToolbar {...props} />);
  return props;
}

describe("DFDToolbar", () => {
  it("shows palette state, snap copy, and shortcuts affordance", async () => {
    const user = userEvent.setup();
    const props = renderToolbar({ paletteVisible: false, snapToGrid: false });

    const paletteButton = screen.getByRole("button", { name: "Show Palette" });
    expect(paletteButton).toHaveAttribute("title", "Show Component Palette");

    const snapButton = screen.getByRole("button", { name: "Snap" });
    expect(snapButton).toHaveAttribute(
      "title",
      "Enable snap-to-grid. Dragged components and boundaries lock to a 20px grid."
    );

    const shortcutsButton = screen.getByRole("button", { name: "Shortcuts" });
    await user.click(shortcutsButton);
    expect(props.onShowShortcuts).toHaveBeenCalledTimes(1);
  });

  it("disables undo and redo when history is unavailable", () => {
    renderToolbar({ canUndo: false, canRedo: false });

    expect(screen.getByRole("button", { name: "Undo" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Redo" })).toBeDisabled();
  });
});
