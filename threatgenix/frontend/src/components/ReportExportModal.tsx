import { useEffect, useMemo, useRef, useState } from "react";
import type { ChangeEvent, CSSProperties } from "react";

import type {
  ReportSectionId,
  ReportTemplateDefinition,
  ReportTemplateSection,
} from "../types/api";

const BUILT_IN_SECTION_LIBRARY: {
  id: ReportSectionId;
  label: string;
  description: string;
}[] = [
  { id: "executive_summary", label: "Executive Summary", description: "Decision-ready summary of what matters now and the current residual posture." },
  { id: "scope", label: "Scope", description: "System purpose, data classification, and basic model metadata." },
  { id: "system_context", label: "System Context", description: "Dependencies, integrations, data stores, and exposure context." },
  { id: "dfd", label: "Data Flow Diagram", description: "Primary DFD with trust boundaries and protected assets." },
  { id: "arch_diagrams", label: "Architectural Diagrams", description: "Supporting architecture images and views." },
  { id: "threats", label: "Findings and Actions", description: "Threat inventory, engineering actions, queue status, and mitigations." },
  { id: "controls", label: "Controls and Risk Treatment", description: "Mapped controls, treatment posture, and required control changes." },
  { id: "assumptions", label: "Assumptions", description: "Assumptions, constraints, and external dependencies." },
  { id: "compliance", label: "Compliance Evidence", description: "Framework mappings, evidence gaps, and control assertions." },
  { id: "scan_validation", label: "Validation and Verification Evidence", description: "Testing, scan correlation, and verification proof." },
  { id: "responsibility_matrix", label: "Responsibility Matrix", description: "Provider-managed versus organization-managed exposure." },
  { id: "methodology", label: "Methodology", description: "Threat modeling method, evidence sources, and caveats." },
];

const EXPORT_FOCUS_GROUPS: {
  id: string;
  title: string;
  description: string;
  sections: ReportSectionId[];
}[] = [
  {
    id: "action",
    title: "Engineer action summary",
    description: "What is real, what matters now, and what engineering should do next.",
    sections: ["executive_summary", "threats", "controls"],
  },
  {
    id: "evidence",
    title: "Compliance and evidence",
    description: "What supports the control story and what still needs proof.",
    sections: ["compliance", "scan_validation", "responsibility_matrix"],
  },
  {
    id: "context",
    title: "Formal model context",
    description: "Architecture, scope, assumptions, and the formal record of the review.",
    sections: ["scope", "system_context", "dfd", "arch_diagrams", "assumptions", "methodology"],
  },
];

const FALLBACK_REPORT_TEMPLATES: ReportTemplateDefinition[] = [
  {
    id: "default",
    name: "Default",
    description: "Engineer-first document with action items, evidence posture, and the formal model record.",
    audience: "engineering",
    cover_title: "Security Review Report",
    cover_subtitle: "Engineer action and evidence view",
    built_in: true,
    sections: [
      "executive_summary",
      "scope",
      "system_context",
      "dfd",
      "threats",
      "controls",
      "compliance",
      "scan_validation",
      "assumptions",
      "responsibility_matrix",
      "arch_diagrams",
      "methodology",
    ].map((id) => ({
      id,
      kind: "built_in",
      source_section_id: id as ReportSectionId,
      title: BUILT_IN_SECTION_LIBRARY.find((item) => item.id === id)?.label ?? id,
      intro_text: null,
      body: null,
    })),
  },
  {
    id: "minimal",
    name: "Minimal",
    description: "Compact engineering decision packet with core findings and next actions.",
    audience: "engineering",
    cover_title: "Security Review Summary",
    cover_subtitle: "Compact findings and next steps",
    built_in: true,
    sections: ["executive_summary", "dfd", "threats", "controls", "methodology"].map((id) => ({
      id,
      kind: "built_in" as const,
      source_section_id: id as ReportSectionId,
      title: BUILT_IN_SECTION_LIBRARY.find((item) => item.id === id)?.label ?? id,
      intro_text: null,
      body: null,
    })),
  },
  {
    id: "executive",
    name: "Executive",
    description: "Leadership-friendly summary of urgent findings, evidence posture, and top actions.",
    audience: "executive",
    cover_title: "Executive Security Review Summary",
    cover_subtitle: "Leadership risk posture and action view",
    built_in: true,
    sections: ["executive_summary", "system_context", "threats", "controls", "compliance", "dfd", "methodology"].map((id) => ({
      id,
      kind: "built_in" as const,
      source_section_id: id as ReportSectionId,
      title: BUILT_IN_SECTION_LIBRARY.find((item) => item.id === id)?.label ?? id,
      intro_text: null,
      body: null,
    })),
  },
  {
    id: "financial_services",
    name: "Financial Services Detailed",
    description:
      "Banking-oriented packet aligned to engineering action, regulatory evidence, residual risk, and control mapping.",
    audience: "financial_services",
    cover_title: "Financial Services Security Review",
    cover_subtitle: "Banking and regulated-service review packet",
    built_in: true,
    sections: (
      [
        "executive_summary",
        "scope",
        "system_context",
        "dfd",
        "arch_diagrams",
        "threats",
        "controls",
        "assumptions",
        "compliance",
        "scan_validation",
        "responsibility_matrix",
        "methodology",
      ].map((id) => ({
        id,
        kind: "built_in" as const,
        source_section_id: id as ReportSectionId,
        title: BUILT_IN_SECTION_LIBRARY.find((item) => item.id === id)?.label ?? id,
        intro_text: null,
        body: null,
      })) as ReportTemplateSection[]
    ).concat([
      {
        id: "review-prompts",
        kind: "custom_text" as const,
        title: "Review Prompts",
        intro_text: "Banking-grade review prompts commonly expected in regulated governance cycles.",
        body:
          "Confirm whether residual risk remains within risk appetite, whether critical outsourced services are adequately covered by controls and testing, and whether open actions have accountable owners and target completion dates.",
      },
    ]),
  },
];

export interface ArchDiagram {
  name: string;
  image_base64: string;
}

type DraftScope = "model" | "shared";
const EMPTY_ARCH_DIAGRAMS: ArchDiagram[] = [];
const EMPTY_REPORT_TEMPLATES: ReportTemplateDefinition[] = [];

interface Props {
  onClose: () => void;
  onExport: (
    sections: string[],
    archDiagrams: ArchDiagram[],
    reportTemplateId: string,
    reportTemplates: ReportTemplateDefinition[],
  ) => void;
  exporting: boolean;
  exportStage?: "idle" | "capturing_dfd" | "saving_config" | "generating_pdf" | "failed";
  exportError?: string | null;
  existingArchDiagrams?: ArchDiagram[];
  existingReportTemplates?: ReportTemplateDefinition[];
  sharedReportTemplates?: ReportTemplateDefinition[];
  onUpdateSharedReportTemplates?: (templates: ReportTemplateDefinition[]) => Promise<void> | void;
  initialTemplateId?: string;
}

function cloneTemplate(template: ReportTemplateDefinition): ReportTemplateDefinition {
  return JSON.parse(JSON.stringify(template)) as ReportTemplateDefinition;
}

function getSourceSectionId(section: ReportTemplateSection): ReportSectionId | null {
  if (section.kind !== "built_in") {
    return null;
  }
  return (section.source_section_id ?? section.id) as ReportSectionId;
}

function buildEnabledMap(template: ReportTemplateDefinition | null): Record<ReportSectionId, boolean> {
  return Object.fromEntries(
    BUILT_IN_SECTION_LIBRARY.map((section) => [
      section.id,
      Boolean(
        template?.sections.some(
          (item) => item.kind === "built_in" && getSourceSectionId(item) === section.id
        )
      ),
    ])
  ) as Record<ReportSectionId, boolean>;
}

function makeTemplateId(label: string, templates: ReportTemplateDefinition[]): string {
  const base = label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "custom-report-template";
  let candidate = base;
  let index = 2;
  const existing = new Set([
    ...FALLBACK_REPORT_TEMPLATES.map((template) => template.id),
    ...templates.map((template) => template.id),
  ]);
  while (existing.has(candidate)) {
    candidate = `${base}-${index}`;
    index += 1;
  }
  return candidate;
}

function makeSectionId(label: string, sections: ReportTemplateSection[]): string {
  const base = label
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "custom-section";
  let candidate = base;
  let index = 2;
  const existing = new Set(sections.map((section) => section.id));
  while (existing.has(candidate)) {
    candidate = `${base}-${index}`;
    index += 1;
  }
  return candidate;
}

function buildExportSections(
  template: ReportTemplateDefinition,
  enabled: Record<ReportSectionId, boolean>
): string[] {
  return template.sections.flatMap((section) => {
    const sourceSectionId = getSourceSectionId(section);
    if (!sourceSectionId) {
      return [];
    }
    return enabled[sourceSectionId] ? [sourceSectionId] : [];
  });
}

function templateFocusSummary(template: ReportTemplateDefinition | null): {
  title: string;
  description: string;
  bullets: string[];
} {
  if (!template) {
    return {
      title: "Balanced engineering review",
      description: "Action, evidence, and formal context stay balanced in the export.",
      bullets: [],
    };
  }
  if (template.id === "minimal") {
    return {
      title: "Fast engineering handoff",
      description: "Compact packet for what to fix now, what to verify, and the minimum context required.",
      bullets: [
        "Optimized for engineers reviewing the next action instead of a long appendix.",
        "Keeps the DFD and methodology, but trims the broader evidence packet.",
      ],
    };
  }
  if (template.id === "executive") {
    return {
      title: "Leadership and review summary",
      description: "Highlights urgency, control posture, and compliance evidence without turning into a giant engineering dump.",
      bullets: [
        "Best when you need current posture and top actions for non-implementers.",
        "Keeps evidence and compliance visible enough for audit conversations.",
      ],
    };
  }
  if (template.id === "financial_services") {
    return {
      title: "Regulated evidence packet",
      description: "Biases toward engineer action, residual risk, and compliance evidence for regulated environments.",
      bullets: [
        "Includes explicit compliance and validation sections for audit-heavy reviews.",
        "Keeps action ownership and evidence posture closer to the front of the packet.",
      ],
    };
  }
  return {
    title: "Balanced engineering review",
    description: "Default export favors engineer action, compliance evidence, and the formal threat-model record in one packet.",
    bullets: [
      "Best starting point for one application review with both engineering and compliance stakeholders.",
      "Keeps findings, controls, compliance evidence, and the formal model together.",
    ],
  };
}

export function ReportExportModal({
  onClose,
  onExport,
  exporting,
  exportStage = "idle",
  exportError = null,
  existingArchDiagrams = EMPTY_ARCH_DIAGRAMS,
  existingReportTemplates = EMPTY_REPORT_TEMPLATES,
  sharedReportTemplates = EMPTY_REPORT_TEMPLATES,
  onUpdateSharedReportTemplates,
  initialTemplateId = "default",
}: Props) {
  const [templates, setTemplates] = useState<ReportTemplateDefinition[]>(
    existingReportTemplates.length > 0 ? existingReportTemplates : FALLBACK_REPORT_TEMPLATES
  );
  const [sharedTemplates, setSharedTemplates] = useState<ReportTemplateDefinition[]>(sharedReportTemplates);
  const [selectedTemplateId, setSelectedTemplateId] = useState(initialTemplateId);
  const [enabled, setEnabled] = useState<Record<ReportSectionId, boolean>>(
    buildEnabledMap(
      (existingReportTemplates.length > 0 ? existingReportTemplates : FALLBACK_REPORT_TEMPLATES).find(
        (template) => template.id === initialTemplateId
      ) ?? (existingReportTemplates.length > 0 ? existingReportTemplates[0] : FALLBACK_REPORT_TEMPLATES[0]) ?? null
    )
  );
  const [archDiagrams, setArchDiagrams] = useState<ArchDiagram[]>(existingArchDiagrams);
  const [diagramName, setDiagramName] = useState("");
  const [draft, setDraft] = useState<ReportTemplateDefinition | null>(null);
  const [draftScope, setDraftScope] = useState<DraftScope>("model");
  const [savingSharedTemplates, setSavingSharedTemplates] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const selectedTemplate = useMemo(
    () => templates.find((template) => template.id === selectedTemplateId) ?? templates[0] ?? null,
    [selectedTemplateId, templates]
  );
  const focusSummary = useMemo(() => templateFocusSummary(selectedTemplate), [selectedTemplate]);

  useEffect(() => {
    if (!selectedTemplate) {
      return;
    }
    setEnabled(buildEnabledMap(selectedTemplate));
  }, [selectedTemplate]);

  useEffect(() => {
    if (templates.some((template) => template.id === selectedTemplateId)) {
      return;
    }
    setSelectedTemplateId(templates[0]?.id ?? "default");
  }, [selectedTemplateId, templates]);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !exporting) {
        event.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [exporting, onClose]);

  useEffect(() => {
    setSharedTemplates(sharedReportTemplates);
  }, [sharedReportTemplates]);

  const customTemplates = useMemo(
    () => templates.filter((template) => !template.built_in),
    [templates]
  );

  const persistSharedTemplates = async (
    nextTemplates: ReportTemplateDefinition[]
  ): Promise<boolean> => {
    const previousTemplates = sharedTemplates;
    setSharedTemplates(nextTemplates);
    if (!onUpdateSharedReportTemplates) {
      return true;
    }
    setSavingSharedTemplates(true);
    try {
      await onUpdateSharedReportTemplates(nextTemplates);
      return true;
    } catch (error) {
      setSharedTemplates(previousTemplates);
      alert(
        error instanceof Error
          ? error.message
          : "Failed to update the shared template library."
      );
      return false;
    } finally {
      setSavingSharedTemplates(false);
    }
  };

  const handleFileAdd = (event: ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;
    const name = diagramName.trim() || file.name.replace(/\.[^.]+$/, "");
    const reader = new FileReader();
    reader.onload = () => {
      const dataUrl = reader.result as string;
      const base64 = dataUrl.split(",")[1] ?? "";
      setArchDiagrams((current) => [...current, { name, image_base64: base64 }]);
      setDiagramName("");
      if (fileRef.current) fileRef.current.value = "";
    };
    reader.readAsDataURL(file);
  };

  const removeDiagram = (index: number) =>
    setArchDiagrams((current) => current.filter((_, currentIndex) => currentIndex !== index));

  const handleToggleSection = (id: ReportSectionId) =>
    setEnabled((current) => ({ ...current, [id]: !current[id] }));

  const openCloneEditor = () => {
    if (!selectedTemplate) return;
    const draftTemplate = cloneTemplate(selectedTemplate);
    draftTemplate.id = makeTemplateId(`${selectedTemplate.name} copy`, templates);
    draftTemplate.name = `${selectedTemplate.name} Copy`;
    draftTemplate.built_in = false;
    setDraftScope("model");
    setDraft(draftTemplate);
  };

  const openEditEditor = () => {
    if (!selectedTemplate || selectedTemplate.built_in) return;
    setDraftScope("model");
    setDraft(cloneTemplate(selectedTemplate));
  };

  const openSharedEditEditor = (template: ReportTemplateDefinition) => {
    setDraftScope("shared");
    setDraft(cloneTemplate(template));
  };

  const updateDraft = (updater: (current: ReportTemplateDefinition) => ReportTemplateDefinition) =>
    setDraft((current) => (current ? updater(current) : current));

  const toggleDraftBuiltInSection = (sectionId: ReportSectionId) => {
    updateDraft((current) => {
      const exists = current.sections.some(
        (section) => section.kind === "built_in" && getSourceSectionId(section) === sectionId
      );
      return {
        ...current,
        sections: exists
          ? current.sections.filter(
              (section) => !(section.kind === "built_in" && getSourceSectionId(section) === sectionId)
            )
          : [
              ...current.sections,
              {
                id: sectionId,
                kind: "built_in",
                source_section_id: sectionId,
                title: BUILT_IN_SECTION_LIBRARY.find((item) => item.id === sectionId)?.label ?? sectionId,
                intro_text: "",
                body: null,
              },
            ],
      };
    });
  };

  const updateDraftSection = (
    sectionId: string,
    patch: Partial<ReportTemplateSection>
  ) => {
    updateDraft((current) => ({
      ...current,
      sections: current.sections.map((section) =>
        section.id === sectionId ? { ...section, ...patch } : section
      ),
    }));
  };

  const moveDraftSection = (sectionId: string, direction: -1 | 1) => {
    updateDraft((current) => {
      const index = current.sections.findIndex((section) => section.id === sectionId);
      if (index < 0) {
        return current;
      }
      const nextIndex = index + direction;
      if (nextIndex < 0 || nextIndex >= current.sections.length) {
        return current;
      }
      const nextSections = [...current.sections];
      const [section] = nextSections.splice(index, 1);
      if (!section) {
        return current;
      }
      nextSections.splice(nextIndex, 0, section);
      return { ...current, sections: nextSections };
    });
  };

  const removeDraftSection = (sectionId: string) => {
    updateDraft((current) => ({
      ...current,
      sections: current.sections.filter((section) => section.id !== sectionId),
    }));
  };

  const addDraftCustomSection = () => {
    if (!draft) return;
    const sectionId = makeSectionId("custom-section", draft.sections);
    updateDraft((current) => ({
      ...current,
      sections: [
        ...current.sections,
        {
          id: sectionId,
          kind: "custom_text",
          title: "Narrative Block",
          intro_text: "",
          body: "Add organization-specific review instructions, approvals, or appendix text here.",
        },
      ],
    }));
  };

  const saveDraftTemplate = async () => {
    if (!draft) return;
    const normalizedName = draft.name.trim();
    const normalizedCoverTitle = draft.cover_title.trim();
    if (!normalizedName || !normalizedCoverTitle) {
      alert("Template name and cover title are required.");
      return;
    }
    if (draft.sections.length === 0) {
      alert("Templates need at least one section.");
      return;
    }

    const normalized = {
      ...draft,
      name: normalizedName,
      description: draft.description.trim(),
      audience: draft.audience.trim() || "custom",
      cover_title: normalizedCoverTitle,
      cover_subtitle: draft.cover_subtitle?.trim() || null,
      built_in: false,
      sections: draft.sections.map((section) => ({
        ...section,
        title: section.title.trim(),
        intro_text: section.intro_text?.trim() || null,
        body: section.kind === "custom_text" ? section.body?.trim() || "" : null,
      })),
    };

    if (normalized.sections.some((section) => !section.title)) {
      alert("Every section needs a title.");
      return;
    }
    if (
      normalized.sections.some(
        (section) => section.kind === "custom_text" && !(section.body || "").trim()
      )
    ) {
      alert("Custom narrative blocks need body text.");
      return;
    }

    if (draftScope === "shared") {
      const exists = sharedTemplates.some((template) => template.id === normalized.id);
      const saved = await persistSharedTemplates(
        exists
          ? sharedTemplates.map((template) =>
              template.id === normalized.id ? normalized : template
            )
          : [...sharedTemplates, normalized]
      );
      if (!saved) {
        return;
      }
    } else {
      setTemplates((current) => {
        const exists = current.some((template) => template.id === normalized.id);
        return exists
          ? current.map((template) => (template.id === normalized.id ? normalized : template))
          : [...current, normalized];
      });
      setSelectedTemplateId(normalized.id);
    }
    setDraft(null);
  };

  const deleteSelectedTemplate = () => {
    if (!selectedTemplate || selectedTemplate.built_in) return;
    if (!window.confirm(`Delete the custom template "${selectedTemplate.name}"?`)) return;
    setTemplates((current) => current.filter((template) => template.id !== selectedTemplate.id));
    setSelectedTemplateId("default");
  };

  const saveSelectedTemplateToShared = async () => {
    if (!selectedTemplate) return;
    const cloned = cloneTemplate(selectedTemplate);
    const nextId = selectedTemplate.built_in
      ? makeTemplateId(`${selectedTemplate.name} library`, sharedTemplates)
      : cloned.id;
    const normalized = { ...cloned, id: nextId, built_in: false };
    const exists = !selectedTemplate.built_in && sharedTemplates.some((template) => template.id === nextId);
    await persistSharedTemplates(
      exists
        ? sharedTemplates.map((template) => (template.id === nextId ? normalized : template))
        : [...sharedTemplates, normalized]
    );
  };

  const copySharedTemplateToModel = (template: ReportTemplateDefinition) => {
    const nextId = templates.some((item) => item.id === template.id)
      ? makeTemplateId(template.name, templates)
      : template.id;
    const copied = { ...cloneTemplate(template), id: nextId, built_in: false };
    setTemplates((current) => [...current, copied]);
    setSelectedTemplateId(copied.id);
  };

  const deleteSharedTemplate = async (template: ReportTemplateDefinition) => {
    if (!window.confirm(`Delete the shared template "${template.name}"?`)) return;
    const saved = await persistSharedTemplates(
      sharedTemplates.filter((item) => item.id !== template.id)
    );
    if (saved && draftScope === "shared" && draft?.id === template.id) {
      setDraft(null);
    }
  };

  const handleExport = () => {
    if (!selectedTemplate) return;
    const sections = buildExportSections(selectedTemplate, enabled);
    onExport(sections, archDiagrams, selectedTemplate.id, customTemplates);
  };

  const exportStageText =
    exportStage === "capturing_dfd"
      ? "Capturing the current DFD image for the PDF."
      : exportStage === "saving_config"
        ? "Saving report format and attached diagrams."
        : exportStage === "generating_pdf"
          ? "Generating the PDF. This is bounded to 90 seconds."
          : exporting
            ? "Preparing the report export."
            : "";

  return (
    <div
      style={overlay}
      onClick={() => {
        if (!exporting) {
          onClose();
        }
      }}
    >
      <div
        style={modal}
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-export-modal-title"
        onClick={(event) => event.stopPropagation()}
      >
        <div style={headerShell}>
          <div style={headerRow}>
            <div>
              <h2
                id="report-export-modal-title"
                style={{ marginTop: 0, color: "#0f274f", marginBottom: 6 }}
              >
                Generate Threat Model Document
              </h2>
              <p style={introText}>
                Use a built-in format, tailor a model-specific template, or save reusable formats into the shared library
                before exporting the PDF.
              </p>
            </div>
            <button onClick={onClose} disabled={exporting} style={closeBtn}>Close</button>
          </div>
        </div>

        <div style={modalBody}>
          <section style={panel}>
            <div style={panelHeader}>
              <div>
                <h3 style={sectionHeading}>Document Format</h3>
                <p style={mutedText}>
                  Pick how much engineer action, compliance evidence, and formal architecture context the export should carry.
                </p>
              </div>
              <select
                value={selectedTemplate?.id ?? ""}
                onChange={(event) => setSelectedTemplateId(event.target.value)}
                style={selectInput}
              >
                {templates.map((template) => (
                  <option key={template.id} value={template.id}>
                    {template.name}{template.built_in ? " · Built-in" : " · This model"}
                  </option>
                ))}
              </select>
            </div>

            {selectedTemplate && (
              <div style={templateCard}>
                <div style={templateMetaRow}>
                  <div>
                    <strong style={{ fontSize: 15 }}>{selectedTemplate.name}</strong>
                    <div style={templateDescription}>{selectedTemplate.description}</div>
                  </div>
                  <span style={templateBadge(selectedTemplate.built_in)}>
                    {selectedTemplate.built_in ? "Built-in" : "This model"}
                  </span>
                </div>
                <div style={chipRow}>
                  {selectedTemplate.sections.map((section) => (
                    <span key={section.id} style={templateChip(section.kind === "custom_text")}>
                      {section.title}
                    </span>
                  ))}
                </div>
                <div style={actionRow}>
                  <button type="button" onClick={openCloneEditor} style={secondaryBtn}>
                    Customize Selected
                  </button>
                  <button
                    type="button"
                    onClick={() => void saveSelectedTemplateToShared()}
                    disabled={savingSharedTemplates}
                    style={secondaryBtn}
                  >
                    Save to Shared Library
                  </button>
                  {!selectedTemplate.built_in && (
                    <>
                      <button type="button" onClick={openEditEditor} style={secondaryBtn}>
                        Edit Model Template
                      </button>
                      <button type="button" onClick={deleteSelectedTemplate} style={dangerBtn}>
                        Delete Model Template
                      </button>
                    </>
                  )}
                </div>
              </div>
            )}
          </section>

          <section style={panel}>
            <div style={panelHeader}>
              <div>
                <h3 style={sectionHeading}>Export Focus</h3>
                <p style={mutedText}>
                  Keep the document oriented around action and evidence. The formal record remains, but it should support the review instead of overwhelming it.
                </p>
              </div>
            </div>
            <div
              style={{
                display: "grid",
                gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))",
                gap: "12px",
                marginBottom: "14px",
              }}
            >
              {EXPORT_FOCUS_GROUPS.map((group) => (
                <div
                  key={group.id}
                  style={{
                    border: "1px solid #dbe5f0",
                    borderRadius: "12px",
                    padding: "12px",
                    background: "#f8fafc",
                  }}
                >
                  <strong style={{ display: "block", marginBottom: "6px", color: "#0f274f" }}>{group.title}</strong>
                  <span style={{ ...smallMuted, display: "block" }}>{group.description}</span>
                </div>
              ))}
            </div>
            <div style={templateCard}>
              <div style={templateMetaRow}>
                <div>
                  <strong style={{ fontSize: 15 }}>{focusSummary.title}</strong>
                  <div style={templateDescription}>{focusSummary.description}</div>
                </div>
                <span style={templateBadge(false)}>{selectedTemplate?.audience ?? "engineering"}</span>
              </div>
              {focusSummary.bullets.length > 0 && (
                <ul style={{ margin: 0, paddingLeft: "18px", color: "#475569", fontSize: "0.9rem", lineHeight: 1.5 }}>
                  {focusSummary.bullets.map((bullet) => (
                    <li key={bullet}>{bullet}</li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <section style={panel}>
            <div style={panelHeader}>
              <div>
                <h3 style={sectionHeading}>Shared Template Library</h3>
                <p style={mutedText}>
                  Save reusable organization templates once, then copy them into any threat model when needed.
                </p>
              </div>
            </div>
            {sharedTemplates.length === 0 ? (
              <p style={{ ...mutedText, marginTop: 0 }}>
                No shared templates saved yet. Save the selected format to start a reusable library.
              </p>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {sharedTemplates.map((template) => (
                  <div key={template.id} style={templateCard}>
                    <div style={templateMetaRow}>
                      <div>
                        <strong style={{ fontSize: 15 }}>{template.name}</strong>
                        <div style={templateDescription}>{template.description}</div>
                      </div>
                      <span style={templateBadge(false)}>Shared</span>
                    </div>
                    <div style={chipRow}>
                      {template.sections.map((section) => (
                        <span key={section.id} style={templateChip(section.kind === "custom_text")}>
                          {section.title}
                        </span>
                      ))}
                    </div>
                    <div style={actionRow}>
                      <button
                        type="button"
                        onClick={() => copySharedTemplateToModel(template)}
                        style={secondaryBtn}
                      >
                        Copy to This Model
                      </button>
                      <button
                        type="button"
                        onClick={() => openSharedEditEditor(template)}
                        disabled={savingSharedTemplates}
                        style={secondaryBtn}
                      >
                        Edit Shared Template
                      </button>
                      <button
                        type="button"
                        onClick={() => void deleteSharedTemplate(template)}
                        disabled={savingSharedTemplates}
                        style={dangerBtn}
                      >
                        Delete from Library
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </section>

          {draft && (
            <section style={editorPanel}>
              <div style={panelHeader}>
                <div>
                  <h3 style={sectionHeading}>
                    {draftScope === "shared" ? "Edit Shared Library Template" : "Edit Model Template"}
                  </h3>
                  <p style={mutedText}>
                    Reorder sections, rename headings, add custom narrative blocks, and tailor the cover copy.
                  </p>
                </div>
              </div>

              <div style={editorGrid}>
                <label style={field}>
                  <span style={fieldLabel}>Template name</span>
                  <input
                    value={draft.name}
                    onChange={(event) => updateDraft((current) => ({ ...current, name: event.target.value }))}
                    style={textInput}
                  />
                </label>
                <label style={field}>
                  <span style={fieldLabel}>Audience</span>
                  <input
                    value={draft.audience}
                    onChange={(event) => updateDraft((current) => ({ ...current, audience: event.target.value }))}
                    style={textInput}
                  />
                </label>
                <label style={{ ...field, gridColumn: "1 / -1" }}>
                  <span style={fieldLabel}>Description</span>
                  <input
                    value={draft.description}
                    onChange={(event) => updateDraft((current) => ({ ...current, description: event.target.value }))}
                    style={textInput}
                  />
                </label>
                <label style={field}>
                  <span style={fieldLabel}>Cover title</span>
                  <input
                    value={draft.cover_title}
                    onChange={(event) => updateDraft((current) => ({ ...current, cover_title: event.target.value }))}
                    style={textInput}
                  />
                </label>
                <label style={field}>
                  <span style={fieldLabel}>Cover subtitle</span>
                  <input
                    value={draft.cover_subtitle ?? ""}
                    onChange={(event) => updateDraft((current) => ({ ...current, cover_subtitle: event.target.value }))}
                    style={textInput}
                  />
                </label>
              </div>

              <h4 style={miniHeading}>Built-in Sections</h4>
              <div style={sectionPickerGrid}>
                {BUILT_IN_SECTION_LIBRARY.map((section) => {
                  const isEnabled = draft.sections.some(
                    (item) => item.kind === "built_in" && getSourceSectionId(item) === section.id
                  );
                  return (
                    <label key={section.id} style={sectionToggleCard}>
                      <input
                        type="checkbox"
                        checked={isEnabled}
                        onChange={() => toggleDraftBuiltInSection(section.id)}
                      />
                      <div>
                        <strong style={{ display: "block", fontSize: 13 }}>{section.label}</strong>
                        <span style={smallMuted}>{section.description}</span>
                      </div>
                    </label>
                  );
                })}
              </div>

              <div style={panelHeader}>
                <h4 style={miniHeading}>Section Order and Copy</h4>
                <button type="button" onClick={addDraftCustomSection} style={secondaryBtn}>
                  Add Custom Narrative Block
                </button>
              </div>

              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {draft.sections.map((section) => (
                  <div key={section.id} style={sectionEditorCard}>
                    <div style={sectionEditorHeader}>
                      <strong>
                        {section.kind === "built_in"
                          ? BUILT_IN_SECTION_LIBRARY.find((item) => item.id === getSourceSectionId(section))?.label ?? section.title
                          : "Custom Narrative"}
                      </strong>
                      <div style={sectionEditorActions}>
                        <button type="button" onClick={() => moveDraftSection(section.id, -1)} style={microBtn}>
                          Up
                        </button>
                        <button type="button" onClick={() => moveDraftSection(section.id, 1)} style={microBtn}>
                          Down
                        </button>
                        {section.kind === "custom_text" && (
                          <button type="button" onClick={() => removeDraftSection(section.id)} style={dangerBtnSmall}>
                            Remove
                          </button>
                        )}
                      </div>
                    </div>
                    <label style={field}>
                      <span style={fieldLabel}>Section title</span>
                      <input
                        value={section.title}
                        onChange={(event) => updateDraftSection(section.id, { title: event.target.value })}
                        style={textInput}
                      />
                    </label>
                    <label style={field}>
                      <span style={fieldLabel}>Intro text</span>
                      <textarea
                        value={section.intro_text ?? ""}
                        onChange={(event) => updateDraftSection(section.id, { intro_text: event.target.value })}
                        style={textarea}
                        rows={2}
                      />
                    </label>
                    {section.kind === "custom_text" && (
                      <label style={field}>
                        <span style={fieldLabel}>Body text</span>
                        <textarea
                          value={section.body ?? ""}
                          onChange={(event) => updateDraftSection(section.id, { body: event.target.value })}
                          style={textarea}
                          rows={4}
                        />
                      </label>
                    )}
                  </div>
                ))}
              </div>

              <div style={actionRow}>
                <button type="button" onClick={() => setDraft(null)} style={secondaryBtn}>
                  Cancel
                </button>
                <button type="button" onClick={() => void saveDraftTemplate()} style={primaryBtn}>
                  {draftScope === "shared" ? "Save to Shared Library" : "Save to This Model"}
                </button>
              </div>
            </section>
          )}

          <section style={panel}>
            <h3 style={sectionHeading}>Engineer and Compliance Sections</h3>
            <p style={mutedText}>
              These toggles affect this export only. Custom narrative blocks in the selected template are always included.
            </p>
            <div style={{ display: "grid", gap: "14px" }}>
              {EXPORT_FOCUS_GROUPS.map((group) => {
                const sections = selectedTemplate?.sections.filter((section) => {
                  const sourceSectionId = getSourceSectionId(section);
                  return sourceSectionId ? group.sections.includes(sourceSectionId) : false;
                }) ?? [];
                if (sections.length === 0) return null;
                return (
                  <div key={group.id}>
                    <div style={{ fontWeight: 700, color: "#0f274f", marginBottom: "6px" }}>{group.title}</div>
                    <div style={toggleGrid}>
                      {sections.map((section) => {
                        const sourceSectionId = getSourceSectionId(section);
                        if (!sourceSectionId) return null;
                        return (
                          <label key={section.id} style={checkboxRow}>
                            <input
                              type="checkbox"
                              checked={enabled[sourceSectionId]}
                              onChange={() => handleToggleSection(sourceSectionId)}
                            />
                            <span>{section.title}</span>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          <section style={{ ...panel, marginBottom: 0 }}>
            <h3 style={sectionHeading}>Architectural Diagrams</h3>
            {archDiagrams.length > 0 && (
              <ul style={{ padding: 0, listStyle: "none", marginBottom: "10px" }}>
                {archDiagrams.map((diagram, index) => (
                  <li key={`${diagram.name}-${index}`} style={diagramItem}>
                    <span style={{ fontSize: "13px" }}>{diagram.name}</span>
                    <button onClick={() => removeDiagram(index)} style={removeBtn}>Remove</button>
                  </li>
                ))}
              </ul>
            )}
            <div style={{ display: "flex", gap: "8px", alignItems: "center", marginBottom: "10px", flexWrap: "wrap" }}>
              <input
                type="text"
                placeholder="Diagram name (optional)"
                value={diagramName}
                onChange={(event) => setDiagramName(event.target.value)}
                style={textInput}
              />
              <label style={uploadBtn}>
                + Add Image
                <input ref={fileRef} type="file" accept="image/*" style={{ display: "none" }} onChange={handleFileAdd} />
              </label>
            </div>
          </section>
        </div>

        <div style={footerBar}>
          {(exporting || exportError) && (
            <div
              role={exportError ? "alert" : "status"}
              aria-live="polite"
              style={exportError ? exportErrorPanel : exportStatusPanel}
            >
              {exportError ? `PDF export failed: ${exportError}` : exportStageText}
            </div>
          )}
          <button onClick={onClose} disabled={exporting} style={secondaryBtn}>Cancel</button>
          <button onClick={handleExport} disabled={exporting || !selectedTemplate} style={primaryBtn}>
            {exporting ? "Generating Document..." : "Generate Document PDF"}
          </button>
        </div>
      </div>
    </div>
  );
}

const overlay: CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "rgba(15, 23, 42, 0.48)",
  display: "flex",
  alignItems: "flex-start",
  justifyContent: "center",
  zIndex: 1000,
  padding: "12px 24px",
  overflowY: "auto",
};

const modal: CSSProperties = {
  background: "#fff",
  borderRadius: "16px",
  maxWidth: "1040px",
  width: "100%",
  height: "min(92vh, calc(100vh - 24px))",
  maxHeight: "calc(100vh - 24px)",
  display: "flex",
  flexDirection: "column",
  overflow: "hidden",
  boxShadow: "0 20px 50px rgba(15, 23, 42, 0.24)",
  margin: "auto 0",
};

const headerShell: CSSProperties = {
  padding: "28px 32px 0",
  borderBottom: "1px solid rgba(148, 163, 184, 0.18)",
  background: "#fff",
  flexShrink: 0,
};

const modalBody: CSSProperties = {
  padding: "24px 32px",
  flex: "1 1 auto",
  overflowY: "auto",
  minHeight: 0,
  paddingBottom: "32px",
};

const footerBar: CSSProperties = {
  display: "flex",
  gap: "10px",
  justifyContent: "flex-end",
  alignItems: "center",
  padding: "16px 32px 24px",
  borderTop: "1px solid rgba(148, 163, 184, 0.18)",
  background: "#fff",
  flexShrink: 0,
};

const exportStatusPanel: CSSProperties = {
  marginRight: "auto",
  maxWidth: "520px",
  color: "#334155",
  background: "#f8fafc",
  border: "1px solid #d8e0ea",
  borderRadius: "8px",
  padding: "8px 10px",
  fontSize: "12px",
  lineHeight: 1.4,
};

const exportErrorPanel: CSSProperties = {
  ...exportStatusPanel,
  color: "#7f1d1d",
  background: "#fff1f2",
  border: "1px solid #fecdd3",
};

const headerRow: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: "16px",
  marginBottom: "18px",
};

const panel: CSSProperties = {
  border: "1px solid #d8e0ea",
  borderRadius: "12px",
  padding: "18px",
  marginBottom: "16px",
  background: "#fcfdff",
};

const editorPanel: CSSProperties = {
  ...panel,
  background: "#f8fbff",
  borderColor: "#bfd3ee",
};

const panelHeader: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: "12px",
  marginBottom: "12px",
};

const sectionHeading: CSSProperties = {
  margin: 0,
  color: "#0f274f",
  fontSize: "15px",
};

const miniHeading: CSSProperties = {
  margin: "0 0 10px 0",
  color: "#0f274f",
  fontSize: "13px",
  textTransform: "uppercase",
  letterSpacing: "0.06em",
};

const introText: CSSProperties = {
  margin: 0,
  color: "#475569",
  fontSize: "14px",
  lineHeight: 1.5,
};

const mutedText: CSSProperties = {
  margin: "4px 0 0 0",
  color: "#5b6476",
  fontSize: "13px",
  lineHeight: 1.45,
};

const textInput: CSSProperties = {
  width: "100%",
  padding: "8px 10px",
  border: "1px solid #cbd5e1",
  borderRadius: "8px",
  fontSize: "13px",
  background: "#fff",
};

const textarea: CSSProperties = {
  ...textInput,
  resize: "vertical",
  minHeight: "72px",
};

const selectInput: CSSProperties = {
  ...textInput,
  maxWidth: "280px",
};

const templateCard: CSSProperties = {
  border: "1px solid #d8e0ea",
  borderRadius: "12px",
  padding: "14px",
  background: "#fff",
};

const templateMetaRow: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  gap: "12px",
};

const templateDescription: CSSProperties = {
  marginTop: "4px",
  color: "#4b5563",
  fontSize: "13px",
  lineHeight: 1.45,
  maxWidth: "44rem",
};

const chipRow: CSSProperties = {
  display: "flex",
  flexWrap: "wrap",
  gap: "6px",
  marginTop: "12px",
};

const actionRow: CSSProperties = {
  display: "flex",
  gap: "10px",
  flexWrap: "wrap",
  marginTop: "14px",
};

const editorGrid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
  gap: "12px",
  marginBottom: "16px",
};

const field: CSSProperties = {
  display: "flex",
  flexDirection: "column",
  gap: "6px",
};

const fieldLabel: CSSProperties = {
  fontSize: "12px",
  fontWeight: 700,
  color: "#334155",
  textTransform: "uppercase",
  letterSpacing: "0.04em",
};

const sectionPickerGrid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
  gap: "10px",
  marginBottom: "16px",
};

const sectionToggleCard: CSSProperties = {
  display: "flex",
  gap: "10px",
  alignItems: "flex-start",
  border: "1px solid #d8e0ea",
  borderRadius: "10px",
  padding: "10px",
  background: "#fff",
  cursor: "pointer",
};

const sectionEditorCard: CSSProperties = {
  border: "1px solid #d8e0ea",
  borderRadius: "10px",
  background: "#fff",
  padding: "12px",
};

const sectionEditorHeader: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  gap: "12px",
  marginBottom: "10px",
};

const sectionEditorActions: CSSProperties = {
  display: "flex",
  gap: "8px",
  alignItems: "center",
};

const toggleGrid: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(240px, 1fr))",
  gap: "10px 18px",
};

const checkboxRow: CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "8px",
  cursor: "pointer",
  minWidth: 0,
};

const diagramItem: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  padding: "6px 8px",
  background: "#f1f5f9",
  borderRadius: "6px",
  marginBottom: "6px",
};

const removeBtn: CSSProperties = {
  fontSize: "11px",
  color: "#b91c1c",
  background: "none",
  border: "none",
  cursor: "pointer",
  padding: "2px 4px",
};

const uploadBtn: CSSProperties = {
  padding: "8px 14px",
  background: "#0f274f",
  color: "#fff",
  borderRadius: "8px",
  cursor: "pointer",
  fontSize: "13px",
  whiteSpace: "nowrap",
};

const primaryBtn: CSSProperties = {
  padding: "9px 16px",
  background: "#0f274f",
  color: "#fff",
  border: "none",
  borderRadius: "8px",
  cursor: "pointer",
  fontSize: "13px",
  fontWeight: 700,
};

const secondaryBtn: CSSProperties = {
  padding: "9px 16px",
  background: "#eef2f7",
  color: "#243040",
  border: "1px solid #cbd5e1",
  borderRadius: "8px",
  cursor: "pointer",
  fontSize: "13px",
  fontWeight: 600,
};

const dangerBtn: CSSProperties = {
  ...secondaryBtn,
  background: "#fff1f2",
  color: "#b91c1c",
  borderColor: "#fecdd3",
};

const dangerBtnSmall: CSSProperties = {
  ...dangerBtn,
  padding: "5px 10px",
  fontSize: "12px",
};

const microBtn: CSSProperties = {
  padding: "5px 10px",
  background: "#eef2f7",
  color: "#243040",
  border: "1px solid #cbd5e1",
  borderRadius: "6px",
  cursor: "pointer",
  fontSize: "12px",
};

const closeBtn: CSSProperties = {
  ...secondaryBtn,
  whiteSpace: "nowrap",
};

const smallMuted: CSSProperties = {
  color: "#64748b",
  fontSize: "12px",
  lineHeight: 1.4,
};

const templateBadge = (builtIn: boolean): CSSProperties => ({
  display: "inline-flex",
  alignItems: "center",
  padding: "4px 10px",
  borderRadius: "999px",
  fontSize: "11px",
  fontWeight: 700,
  background: builtIn ? "#e0f2fe" : "#ede9fe",
  color: builtIn ? "#075985" : "#5b21b6",
});

const templateChip = (custom: boolean): CSSProperties => ({
  display: "inline-flex",
  alignItems: "center",
  padding: "4px 10px",
  borderRadius: "999px",
  fontSize: "11px",
  background: custom ? "#fff7ed" : "#e2e8f0",
  color: custom ? "#9a3412" : "#334155",
});
