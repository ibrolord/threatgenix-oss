export type HistoryShortcutAction = "undo" | "redo" | null;
type ModifierKeyLike = Pick<
  KeyboardEvent,
  "key" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey"
>;

type CanvasFooterHintOptions = {
  isReadOnlyView: boolean;
  isDecompositionView: boolean;
  isFullscreen: boolean;
};

type ShortcutSectionContext = Pick<
  CanvasFooterHintOptions,
  "isReadOnlyView" | "isDecompositionView"
>;

export type DFDShortcutItem = {
  keys: string;
  description: string;
};

export type DFDShortcutSection = {
  title: string;
  items: DFDShortcutItem[];
};

export function getPaletteToggleTooltip(paletteVisible: boolean): string {
  return paletteVisible ? "Hide Component Palette" : "Show Component Palette";
}

export function getSnapToggleTooltip(snapToGrid: boolean): string {
  return snapToGrid
    ? "Disable snap-to-grid. Components can move freely again."
    : "Enable snap-to-grid. Dragged components and boundaries lock to a 20px grid.";
}

export function getHistoryShortcutAction(
  event: ModifierKeyLike
): HistoryShortcutAction {
  const lowerKey = event.key.toLowerCase();
  if ((event.metaKey || event.ctrlKey) && !event.altKey && lowerKey === "z") {
    return event.shiftKey ? "redo" : "undo";
  }

  if ((event.metaKey || event.ctrlKey) && !event.altKey && lowerKey === "y") {
    return "redo";
  }

  return null;
}

export function isShortcutHelpKey(event: ModifierKeyLike): boolean {
  if (event.metaKey || event.ctrlKey || event.altKey) {
    return false;
  }

  return event.key === "?" || (event.key === "/" && event.shiftKey);
}

export function getCanvasFooterHint(
  options: CanvasFooterHintOptions
): string {
  if (options.isReadOnlyView) {
    return options.isFullscreen
      ? "View only. Drag the canvas to pan, hold Shift and drag to box-select, switch to System View or another editable DFD tab to edit the model, and press Esc to exit full screen."
      : "View only. Drag the canvas to pan, hold Shift and drag to box-select, or switch to System View or another editable DFD tab to edit the model.";
  }

  if (options.isDecompositionView) {
    return options.isFullscreen
      ? "Decomposition view. Drag blank canvas to pan, hold Shift or S and drag to box-select internals, use the component palette or right-click to add internals, use + handles to branch flows, use Cmd/Ctrl+Z to undo, and press Esc to exit full screen."
      : "Decomposition view. Drag blank canvas to pan, hold Shift or S and drag to box-select internals, use the component palette or right-click to add internals, use + handles to branch flows, and use Cmd/Ctrl+Z to undo.";
  }

  return options.isFullscreen
    ? "Drag blank canvas to pan, hold Shift or S and drag to box-select, use the component palette or right-click blank canvas to add nodes, double-click nodes to edit, use + handles to branch flows, use Cmd/Ctrl+Z to undo, and press Esc to exit full screen."
    : "Drag blank canvas to pan, hold Shift or S and drag to box-select, use the component palette or right-click blank canvas to add nodes, double-click nodes to edit, and use Cmd/Ctrl+Z to undo.";
}

export function getShortcutSections(
  context: ShortcutSectionContext
): DFDShortcutSection[] {
  if (context.isReadOnlyView) {
    return [
      {
        title: "Canvas",
        items: [
          {
            keys: "Drag canvas",
            description: "Pan across the current diagram without editing it.",
          },
          {
            keys: "Shift + drag",
            description:
              "Box-select nodes and boundaries when you need to inspect a subset.",
          },
          {
            keys: "?",
            description: "Reopen this shortcut guide at any time.",
          },
        ],
      },
      {
        title: "Editing",
        items: [
          {
            keys: "Editable DFD tab",
            description:
              "Switch to System View or another editable DFD tab before moving or changing nodes.",
          },
        ],
      },
    ];
  }

  return [
    {
      title: "Canvas",
      items: [
        {
          keys: "Drag blank canvas",
          description: "Pan across the current diagram.",
        },
        {
          keys: "Shift + drag",
          description: context.isDecompositionView
            ? "Box-select internal components inside the current decomposition."
            : "Box-select components, flows, and trust boundaries.",
        },
        {
          keys: "S + drag",
          description:
            "Use marquee selection without reaching for Shift.",
        },
        {
          keys: "Right-click blank canvas",
          description: context.isDecompositionView
            ? "Create internal components exactly where you clicked."
            : "Create a new component exactly where you clicked.",
        },
        {
          keys: "Snap",
          description:
            "Toggle the 20px grid lock for dragged components and trust boundaries.",
        },
      ],
    },
    {
      title: "Editing",
      items: [
        {
          keys: "Double-click node",
          description: "Open the node editor to update metadata and controls.",
        },
        {
          keys: "+ handle",
          description: "Branch a new data flow from an existing node.",
        },
        {
          keys: "Cmd/Ctrl + Z",
          description: "Undo the last settled canvas change.",
        },
        {
          keys: "Cmd/Ctrl + Shift + Z",
          description: "Redo the last undone canvas change.",
        },
        {
          keys: "Ctrl + Y",
          description: "Redo on Windows and Linux keyboards.",
        },
        {
          keys: "?",
          description: "Open this shortcut guide.",
        },
      ],
    },
  ];
}
