export const CLASSIFICATION_COLORS: Record<string, string> = {
  Restricted: "#7c3aed",
  Confidential: "#d97706",
  Internal: "#2563eb",
  Public: "#059669",
};

export function classificationColor(level: string): string {
  return CLASSIFICATION_COLORS[level] ?? "#64748b";
}
