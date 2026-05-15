import { useCallback, useEffect, useMemo, useState } from "react";

import { api } from "../api/client";
import type {
  AssistantResponse,
  DFDResponse,
  SecurityReviewAttackPath,
  SecurityReviewDecision,
  ThreatIntelResponse,
  ThreatModelResponse,
  ThreatResponse,
} from "../types/api";

interface ThreatDeepDivePanelProps {
  threatModelId: string;
  model: ThreatModelResponse;
  threats: ThreatResponse[];
  focusedThreatId?: string | null;
}

type Tone = "critical" | "high" | "medium" | "low";

type DeepDiveSignal = {
  title: string;
  value: string;
  tone: Tone;
  note: string;
};

const SEVERITY_ORDER: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

const ACTIVE_STATUSES = new Set(["Open", "In Progress"]);
const HIGH_PRESSURE_STRIDES = new Set([
  "Information Disclosure",
  "Tampering",
  "Repudiation",
  "Elevation of Privilege",
]);

function truncate(text: string, max = 88): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max - 1)}…`;
}

function priorityLabel(
  priority: SecurityReviewAttackPath["composite_priority"],
): string {
  switch (priority) {
    case "p0_blocker":
      return "P0 blocker";
    case "p1_now":
      return "P1 now";
    case "p2_sprint":
      return "P2 sprint";
    case "p3_backlog":
      return "P3 backlog";
    default:
      return "P4 monitor";
  }
}

function priorityChipClass(
  priority: SecurityReviewAttackPath["composite_priority"],
): string {
  switch (priority) {
    case "p0_blocker":
      return "threat-deep-dive-chip-critical";
    case "p1_now":
      return "threat-deep-dive-chip-high";
    case "p2_sprint":
      return "threat-deep-dive-chip-medium";
    default:
      return "threat-deep-dive-chip-neutral";
  }
}

function exploitabilityLabel(
  exploitability: SecurityReviewAttackPath["composite_exploitability"],
): string {
  switch (exploitability) {
    case "proven":
      return "Proven";
    case "high":
      return "High";
    case "medium":
      return "Medium";
    default:
      return "Low";
  }
}

function evidenceSourceLabel(source: string): string {
  switch (source) {
    case "dfd":
      return "DFD";
    case "scan":
      return "Runtime scan";
    case "repository":
      return "Code evidence";
    case "compliance":
      return "Compliance framework";
    case "cloud":
      return "Cloud evidence";
    case "manual":
      return "Manual evidence";
    case "threat_intel":
      return "Threat intel";
    case "iac":
      return "IaC";
    case "sdlc":
      return "SDLC";
    default:
      return source
        .split("_")
        .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
        .join(" ");
  }
}

function chooseDefaultThreat(threats: ThreatResponse[]): ThreatResponse | null {
  if (threats.length === 0) return null;
  const sorted = [...threats].sort((left, right) => {
    const leftActive = ACTIVE_STATUSES.has(left.status) ? 0 : 1;
    const rightActive = ACTIVE_STATUSES.has(right.status) ? 0 : 1;
    if (leftActive !== rightActive) return leftActive - rightActive;

    const leftScan =
      left.scan_status === "confirmed"
        ? 0
        : left.scan_status === "mitigated"
          ? 2
          : 1;
    const rightScan =
      right.scan_status === "confirmed"
        ? 0
        : right.scan_status === "mitigated"
          ? 2
          : 1;
    if (leftScan !== rightScan) return leftScan - rightScan;

    const leftSeverity = SEVERITY_ORDER[left.severity] ?? 99;
    const rightSeverity = SEVERITY_ORDER[right.severity] ?? 99;
    if (leftSeverity !== rightSeverity) return leftSeverity - rightSeverity;

    return left.display_id.localeCompare(right.display_id);
  });
  return sorted[0] ?? null;
}

function toneClass(tone: Tone): string {
  switch (tone) {
    case "critical":
      return "threat-deep-dive-signal-critical";
    case "high":
      return "threat-deep-dive-signal-high";
    case "medium":
      return "threat-deep-dive-signal-medium";
    default:
      return "threat-deep-dive-signal-low";
  }
}

function buildSurfaceMap(dfd: DFDResponse | null) {
  const nodeNames = new Map<string, string>();
  const edgeLabels = new Map<string, string>();
  if (!dfd) {
    return { nodeNames, edgeLabels };
  }

  for (const node of dfd.nodes) {
    nodeNames.set(node.id, node.name);
  }

  for (const edge of dfd.edges) {
    const sourceName = nodeNames.get(edge.source_node_id) ?? "Unknown source";
    const targetName = nodeNames.get(edge.target_node_id) ?? "Unknown target";
    edgeLabels.set(
      edge.id,
      edge.label?.trim() || `${sourceName} -> ${targetName}`,
    );
  }

  return { nodeNames, edgeLabels };
}

function buildUrgencySignal(
  threat: ThreatResponse,
  intel: ThreatIntelResponse | null,
  model: ThreatModelResponse,
): DeepDiveSignal {
  const hasKev = (intel?.kev_entries.length ?? 0) > 0;
  const externalSeverity = intel?.highest_external_severity;
  const confirmed = threat.scan_status === "confirmed";
  const mitigated =
    threat.status === "Mitigated" ||
    threat.status === "Accepted" ||
    threat.scan_status === "mitigated";
  const inScope = model.regulatory_scope.length > 0;

  if (mitigated) {
    return {
      title: "Urgency",
      value: "Contained",
      tone: "low",
      note: "This threat is no longer the first place to spend time unless the mitigation is weak or unverified.",
    };
  }

  if (
    confirmed ||
    hasKev ||
    threat.severity === "Critical" ||
    externalSeverity === "Critical"
  ) {
    return {
      title: "Urgency",
      value: "Immediate",
      tone: "critical",
      note: "Treat this as frontline work. There is either direct validation, active exploitation pressure, or critical impact already attached to it.",
    };
  }

  if (
    threat.severity === "High" ||
    externalSeverity === "High" ||
    (inScope && ACTIVE_STATUSES.has(threat.status))
  ) {
    return {
      title: "Urgency",
      value: "This Sprint",
      tone: "high",
      note: "This is not theoretical backlog work. It should land in the active engineering queue with ownership and evidence.",
    };
  }

  return {
    title: "Urgency",
    value: "Plan Soon",
    tone: "medium",
    note: "This matters, but there is not enough pressure yet to treat it as the top interrupt compared with confirmed or actively exploited paths.",
  };
}

function buildExploitabilitySignal(
  threat: ThreatResponse,
  intel: ThreatIntelResponse | null,
): DeepDiveSignal {
  const exactTechniques =
    intel?.attack_techniques.filter((item) => item.match_type === "exact")
      .length ?? 0;
  const exactPatterns =
    intel?.attack_patterns.filter((item) => item.match_type === "exact")
      .length ?? 0;
  const hasKev = (intel?.kev_entries.length ?? 0) > 0;

  if (threat.scan_status === "confirmed" || hasKev) {
    return {
      title: "Exploitability",
      value: "Proven",
      tone: "critical",
      note: "There is concrete evidence this path is real enough to prioritize as exploitable, not just imaginable.",
    };
  }

  if (exactTechniques > 0 || exactPatterns > 0) {
    return {
      title: "Exploitability",
      value: "Plausible",
      tone: "high",
      note: "The threat lines up with explicit ATT&CK or CAPEC behavior, so it deserves real engineering attention even without scan confirmation.",
    };
  }

  if (
    (intel?.attack_techniques.length ?? 0) > 0 ||
    (intel?.attack_patterns.length ?? 0) > 0
  ) {
    return {
      title: "Exploitability",
      value: "Contextual",
      tone: "medium",
      note: "The current signal is mostly inferred from model context. It is still useful, but it needs evidence or validation to move from plausible to proven.",
    };
  }

  return {
    title: "Exploitability",
    value: "Unproven",
    tone: "low",
    note: "There is not enough external evidence yet. Keep the threat visible, but separate it from the paths already backed by stronger signals.",
  };
}

function buildRegulatorySignal(
  threat: ThreatResponse,
  model: ThreatModelResponse,
): DeepDiveSignal {
  if (model.regulatory_scope.length === 0) {
    return {
      title: "Regulatory Pressure",
      value: "Low",
      tone: "low",
      note: "No explicit regulatory framework is attached to this model, so this stays in engineering risk unless business policy elevates it.",
    };
  }

  if (
    model.data_classification === "Restricted" ||
    model.data_classification === "Confidential" ||
    HIGH_PRESSURE_STRIDES.has(threat.stride_category)
  ) {
    return {
      title: "Regulatory Pressure",
      value: "High",
      tone: "high",
      note: `${model.regulatory_scope.join(", ")} is already in scope, and this threat touches a category that usually matters for audit, confidentiality, integrity, or privileged access.`,
    };
  }

  return {
    title: "Regulatory Pressure",
    value: "Moderate",
    tone: "medium",
    note: `${model.regulatory_scope.join(", ")} is in scope, but the pressure depends more on where this threat lands operationally than on the label alone.`,
  };
}

function buildUrgencySignalFromReview(
  decision: SecurityReviewDecision,
): DeepDiveSignal {
  if (decision.urgency === "immediate") {
    return {
      title: "Urgency",
      value: "Immediate",
      tone: decision.priority === "p0_blocker" ? "critical" : "high",
      note:
        decision.action_bucket === "bright_red_line"
          ? "The deterministic review engine classified this as a bright red line. Treat it as active engineering interruption, not background risk."
          : "The deterministic review engine put this in the current interruption queue based on real evidence, exploitability, and business context.",
    };
  }
  if (decision.urgency === "current_cycle") {
    return {
      title: "Urgency",
      value: "This Sprint",
      tone: "high",
      note: "This belongs in the current engineering cycle, but it is not yet at release-blocker level.",
    };
  }
  if (decision.urgency === "planned") {
    return {
      title: "Urgency",
      value: "Planned",
      tone: "medium",
      note: "This should stay visible in backlog planning rather than stealing attention from proven active paths.",
    };
  }
  return {
    title: "Urgency",
    value: "Monitor",
    tone: "low",
    note: "The current signal does not justify interrupting the team. Keep it visible and promote it only if evidence strengthens.",
  };
}

function buildExploitabilitySignalFromReview(
  decision: SecurityReviewDecision,
): DeepDiveSignal {
  const tone: Tone =
    decision.exploitability === "proven"
      ? "critical"
      : decision.exploitability === "high"
        ? "high"
        : decision.exploitability === "medium"
          ? "medium"
          : "low";

  return {
    title: "Exploitability",
    value:
      decision.exploitability === "proven"
        ? "Proven"
        : decision.exploitability === "high"
          ? "Plausible"
          : decision.exploitability === "medium"
            ? "Contextual"
            : "Unproven",
    tone,
    note:
      decision.exploitability === "proven"
        ? "This path has strong evidence behind it. Treat it as operationally real."
        : decision.exploitability === "high"
          ? "The path is plausible enough to demand engineering action even if a scan has not fully confirmed it."
          : decision.exploitability === "medium"
            ? "The path is contextually credible, but it still needs more validation before it should outrank proven exposure."
            : "The path is not well-supported yet. Keep it in view, but do not let it drown out stronger findings.",
  };
}

function buildRegulatorySignalFromReview(
  decision: SecurityReviewDecision,
): DeepDiveSignal {
  const tone: Tone =
    decision.regulatory_pressure === "red_line"
      ? "critical"
      : decision.regulatory_pressure === "high"
        ? "high"
        : decision.regulatory_pressure === "moderate"
          ? "medium"
          : "low";

  return {
    title: "Regulatory Pressure",
    value:
      decision.regulatory_pressure === "red_line"
        ? "Red Line"
        : decision.regulatory_pressure === "high"
          ? "High"
          : decision.regulatory_pressure === "moderate"
            ? "Moderate"
            : "Low",
    tone,
    note:
      decision.regulatory_pressure === "red_line"
        ? "The review engine classifies this as an in-scope control or evidence problem that should be treated like audit risk, not only engineering debt."
        : decision.regulatory_pressure === "high"
          ? "This is materially compliance-relevant and should not be left as informal tribal knowledge."
          : decision.regulatory_pressure === "moderate"
            ? "There is meaningful compliance context here, but the exact pressure still depends on the operational details and closure evidence."
            : "There is little direct regulatory pressure on this item based on the current model context.",
  };
}

function buildLessonsLearned(threat: ThreatResponse): string[] {
  switch (threat.stride_category) {
    case "Spoofing":
      return [
        "Model identities, tokens, workload roles, and trust crossings explicitly so authentication failures are visible in the diagram instead of implied.",
        "Treat caller identity and service identity as separate design concerns during implementation reviews.",
      ];
    case "Tampering":
      return [
        "Push integrity boundaries closer to where data changes happen, not just where data is stored.",
        "Capture the exact write path in the DFD so engineers can see where unauthorized mutation would occur.",
      ];
    case "Repudiation":
      return [
        "Make auditability a design artifact, not an afterthought. If the DFD cannot show who acted and where evidence is captured, repudiation work is usually under-designed.",
        "Review logging ownership early so accountability does not land in a post-incident scramble.",
      ];
    case "Information Disclosure":
      return [
        "Draw sensitive data paths and storage boundaries explicitly. If secrecy depends on an unstated assumption, the model is not doing enough work.",
        "Use this threat as a prompt to tighten data minimization, read scopes, and export surfaces.",
      ];
    case "Denial of Service":
      return [
        "Availability needs to appear in the architecture as bounded work, throttling, queue control, and graceful degradation, not just as runtime hope.",
        "Treat unbounded fan-out, expensive sync calls, and shared choke points as first-class modeling problems.",
      ];
    case "Elevation of Privilege":
      return [
        "Privilege should be modeled like data. If it can move, be assumed, or be broadened, engineers need to see that path explicitly.",
        "Keep role assumptions, admin paths, and sensitive service hops visible in the DFD so design reviews catch escalation routes earlier.",
      ];
    default:
      return [
        "Turn this threat into a design improvement, not just a ticket. The point is to harden the architecture, not only to close one issue record.",
      ];
  }
}

function buildRealityChecks(
  threat: ThreatResponse,
  intel: ThreatIntelResponse | null,
  surfaceLabels: string[],
): string[] {
  const checks = [
    `Threat status is ${threat.status} with local severity ${threat.severity}.`,
  ];
  if (surfaceLabels.length > 0) {
    checks.push(`This threat currently touches ${surfaceLabels.join(", ")}.`);
  }
  if (threat.scan_status) {
    checks.push(
      `Latest validation scan status: ${threat.scan_status.replace("_", " ")}.`,
    );
  }
  if ((intel?.kev_entries.length ?? 0) > 0) {
    checks.push(
      `CISA KEV context exists for this threat, which is a strong signal that the exploitation pattern is not hypothetical.`,
    );
  }
  if ((intel?.attack_techniques.length ?? 0) > 0) {
    const exact =
      intel?.attack_techniques.filter((item) => item.match_type === "exact")
        .length ?? 0;
    checks.push(
      exact > 0
        ? `${exact} exact MITRE ATT&CK technique match${exact > 1 ? "es" : ""} support the path.`
        : "ATT&CK techniques are currently inferred from surrounding context rather than directly cited.",
    );
  }
  if (
    (intel?.severity_signals.length ?? 0) > 0 &&
    intel?.highest_external_severity
  ) {
    checks.push(
      `External intelligence currently tops out at ${intel.highest_external_severity} severity.`,
    );
  }
  return checks;
}

function buildBrightRedLines(
  threat: ThreatResponse,
  intel: ThreatIntelResponse | null,
  model: ThreatModelResponse,
): string[] {
  const lines: string[] = [];
  if (threat.scan_status === "confirmed") {
    lines.push("There is scan-confirmed evidence behind this threat.");
  }
  if ((intel?.kev_entries.length ?? 0) > 0) {
    lines.push(
      "Known Exploited Vulnerability context is attached. Treat this as adversary-relevant now, not later.",
    );
  }
  if (
    model.data_classification === "Restricted" &&
    HIGH_PRESSURE_STRIDES.has(threat.stride_category)
  ) {
    lines.push(
      "The model is marked Restricted and this threat lands in a category that can become a hard compliance or customer-trust problem quickly.",
    );
  }
  if (
    model.regulatory_scope.length > 0 &&
    HIGH_PRESSURE_STRIDES.has(threat.stride_category)
  ) {
    lines.push(
      `The model is already in ${model.regulatory_scope.join(", ")} scope, so this cannot be treated as a purely local engineering concern.`,
    );
  }
  if (ACTIVE_STATUSES.has(threat.status) && !threat.mitigation_owner) {
    lines.push("There is no mitigation owner attached yet.");
  }
  if (ACTIVE_STATUSES.has(threat.status) && !threat.mitigation_plan) {
    lines.push("There is no mitigation plan recorded yet.");
  }
  return lines;
}

function buildNiceToHaves(
  threat: ThreatResponse,
  intel: ThreatIntelResponse | null,
): string[] {
  const items: string[] = [];
  if (!threat.mitigation_notes?.trim()) {
    items.push(
      "Capture implementation notes or validation evidence so future reviewers know what was actually changed.",
    );
  }
  if (!threat.due_date && ACTIVE_STATUSES.has(threat.status)) {
    items.push(
      "Add a due date once the mitigation is accepted into a sprint or release plan.",
    );
  }
  if (
    !threat.residual_risk_level &&
    (threat.status === "Mitigated" || threat.status === "Accepted")
  ) {
    items.push(
      "Record residual risk explicitly so the team does not confuse partial mitigation with full closure.",
    );
  }
  if (
    (intel?.attack_techniques.length ?? 0) === 0 &&
    threat.scan_status == null
  ) {
    items.push(
      "Add stronger evidence or validation so this threat can be sorted more confidently against the rest of the queue.",
    );
  }
  if (!threat.mitigation_owner?.trim()) {
    items.push(
      "Attach an owner early so this does not become everyone’s problem and no one’s responsibility.",
    );
  }
  return items;
}

function buildThreatPrompt(threat: ThreatResponse): string {
  return [
    `Give an engineer-focused deep dive for threat ${threat.display_id}.`,
    "Use exactly these headings:",
    "Business context",
    "What is real",
    "What is urgent and exploitable",
    "Regulatory and bright red lines",
    "Nice to have hardening",
    "Lessons learned",
    "Ground the answer in the current model and evidence. Be concrete, concise, and avoid generic security boilerplate.",
  ].join(" ");
}

export function ThreatDeepDivePanel({
  threatModelId,
  model,
  threats,
  focusedThreatId = null,
}: ThreatDeepDivePanelProps): JSX.Element {
  const [selectedThreatId, setSelectedThreatId] = useState<string | null>(null);
  const [dfd, setDfd] = useState<DFDResponse | null>(null);
  const [intel, setIntel] = useState<ThreatIntelResponse | null>(null);
  const [intelLoading, setIntelLoading] = useState(false);
  const [intelError, setIntelError] = useState<string | null>(null);
  const [reviewDecision, setReviewDecision] =
    useState<SecurityReviewDecision | null>(null);
  const [reviewLoading, setReviewLoading] = useState(false);
  const [reviewError, setReviewError] = useState<string | null>(null);
  const [aiGuidance, setAiGuidance] = useState<AssistantResponse | null>(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);

  const defaultThreat = useMemo(() => chooseDefaultThreat(threats), [threats]);

  useEffect(() => {
    if (threats.length === 0) {
      setSelectedThreatId(null);
      return;
    }

    if (
      focusedThreatId &&
      threats.some((item) => item.id === focusedThreatId)
    ) {
      setSelectedThreatId(focusedThreatId);
      return;
    }

    setSelectedThreatId((current) => {
      if (current && threats.some((item) => item.id === current)) {
        return current;
      }
      return defaultThreat?.id ?? null;
    });
  }, [defaultThreat?.id, focusedThreatId, threats]);

  const selectedThreat = useMemo(
    () => threats.find((item) => item.id === selectedThreatId) ?? null,
    [selectedThreatId, threats],
  );

  useEffect(() => {
    let cancelled = false;
    api
      .getDFD(threatModelId)
      .then((response) => {
        if (!cancelled) {
          setDfd(response);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setDfd(null);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [threatModelId]);

  useEffect(() => {
    if (!selectedThreat) {
      setIntel(null);
      setIntelError(null);
      setReviewDecision(null);
      setReviewError(null);
      return;
    }

    let cancelled = false;
    setIntelLoading(true);
    setIntelError(null);
    setReviewLoading(true);
    setReviewError(null);
    setAiGuidance(null);
    setAiError(null);

    api
      .getThreatIntel(threatModelId, selectedThreat.id)
      .then((response) => {
        if (!cancelled) {
          setIntel(response);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setIntel(null);
          setIntelError(
            error instanceof Error
              ? error.message
              : "Failed to load threat intel.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setIntelLoading(false);
        }
      });

    api
      .getThreatSecurityReview(threatModelId, selectedThreat.id)
      .then((response) => {
        if (!cancelled) {
          setReviewDecision(response);
        }
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setReviewDecision(null);
          setReviewError(
            error instanceof Error
              ? error.message
              : "Failed to load deterministic review.",
          );
        }
      })
      .finally(() => {
        if (!cancelled) {
          setReviewLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedThreat, threatModelId]);

  const { nodeNames, edgeLabels } = useMemo(() => buildSurfaceMap(dfd), [dfd]);

  const surfaceLabels = useMemo(() => {
    if (!selectedThreat) return [];
    const labels = [
      ...selectedThreat.affected_node_ids.map(
        (nodeId) => nodeNames.get(nodeId) ?? `Node ${nodeId.slice(0, 8)}`,
      ),
      ...selectedThreat.affected_edge_ids.map(
        (edgeId) => edgeLabels.get(edgeId) ?? `Flow ${edgeId.slice(0, 8)}`,
      ),
    ];
    return Array.from(new Set(labels));
  }, [edgeLabels, nodeNames, selectedThreat]);

  const urgencySignal = useMemo(
    () =>
      reviewDecision
        ? buildUrgencySignalFromReview(reviewDecision)
        : selectedThreat
          ? buildUrgencySignal(selectedThreat, intel, model)
          : null,
    [intel, model, reviewDecision, selectedThreat],
  );

  const exploitabilitySignal = useMemo(
    () =>
      reviewDecision
        ? buildExploitabilitySignalFromReview(reviewDecision)
        : selectedThreat
          ? buildExploitabilitySignal(selectedThreat, intel)
          : null,
    [intel, reviewDecision, selectedThreat],
  );

  const regulatorySignal = useMemo(
    () =>
      reviewDecision
        ? buildRegulatorySignalFromReview(reviewDecision)
        : selectedThreat
          ? buildRegulatorySignal(selectedThreat, model)
          : null,
    [model, reviewDecision, selectedThreat],
  );

  const realityChecks = useMemo(
    () =>
      reviewDecision
        ? [
            ...reviewDecision.rationale,
            ...reviewDecision.evidence_adjustments.map(
              (item) =>
                `${item.field_affected.replace(/_/g, " ")} changed from ${item.original_value} to ${item.adjusted_value} because ${item.justification.toLowerCase()}`,
            ),
          ]
        : selectedThreat
          ? buildRealityChecks(selectedThreat, intel, surfaceLabels)
          : [],
    [intel, reviewDecision, selectedThreat, surfaceLabels],
  );

  const brightRedLines = useMemo(() => {
    if (reviewDecision) {
      const lines: string[] = [];
      if (reviewDecision.action_bucket === "bright_red_line") {
        lines.push(
          "The deterministic review engine marked this path as a bright red line.",
        );
      }
      if (reviewDecision.regulatory_pressure === "red_line") {
        lines.push(
          "Regulatory pressure is at red-line level, so closure needs evidence, not just engineering confidence.",
        );
      }
      if (reviewDecision.risk_acceptance?.status === "reopened") {
        lines.push(
          "A previously accepted risk has been reopened because the operating context escalated.",
        );
      }
      if (
        reviewDecision.priority === "p0_blocker" ||
        reviewDecision.priority === "p1_now"
      ) {
        lines.push(...reviewDecision.next_steps.slice(0, 2));
      }
      return lines;
    }
    return selectedThreat
      ? buildBrightRedLines(selectedThreat, intel, model)
      : [];
  }, [intel, model, reviewDecision, selectedThreat]);

  const niceToHaves = useMemo(() => {
    if (reviewDecision && reviewDecision.priority !== "p0_blocker") {
      const carriedSteps = reviewDecision.next_steps.filter(
        (step) =>
          !brightRedLines.includes(step) &&
          !step.toLowerCase().includes("release blocker") &&
          !step.toLowerCase().includes("immediate"),
      );
      if (carriedSteps.length > 0) {
        return carriedSteps;
      }
    }
    return selectedThreat ? buildNiceToHaves(selectedThreat, intel) : [];
  }, [brightRedLines, intel, reviewDecision, selectedThreat]);

  const lessonsLearned = useMemo(
    () => (selectedThreat ? buildLessonsLearned(selectedThreat) : []),
    [selectedThreat],
  );

  const attackTechniqueSummary = useMemo(() => {
    if (!intel) return [];
    return intel.attack_techniques.slice(0, 3);
  }, [intel]);

  const attackPaths = useMemo(
    () => reviewDecision?.related_attack_paths ?? [],
    [reviewDecision],
  );

  const generateAiGuidance = useCallback(async () => {
    if (!selectedThreat) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const response = await api.assistantRespond(threatModelId, {
        message: buildThreatPrompt(selectedThreat),
        mode_hint: "review",
        anchor: {
          kind: "threat",
          id: selectedThreat.id,
        },
      });
      setAiGuidance(response);
    } catch (error: unknown) {
      setAiGuidance(null);
      setAiError(
        error instanceof Error
          ? error.message
          : "Failed to generate AI guidance.",
      );
    } finally {
      setAiLoading(false);
    }
  }, [selectedThreat, threatModelId]);

  if (threats.length === 0) {
    return (
      <div className="threat-deep-dive-empty">
        Generate or add threats first, then use this tab to turn them into
        concrete engineering work.
      </div>
    );
  }

  if (!selectedThreat) {
    return (
      <div className="threat-deep-dive-empty">Select a threat to inspect.</div>
    );
  }

  return (
    <div className="threat-deep-dive-panel">
      <div className="threat-deep-dive-toolbar">
        <label className="threat-deep-dive-picker">
          <span>Threat</span>
          <select
            value={selectedThreat.id}
            onChange={(event) => setSelectedThreatId(event.target.value)}
          >
            {threats.map((threat) => (
              <option key={threat.id} value={threat.id}>
                {`${threat.display_id} · ${threat.severity} · ${truncate(threat.description, 72)}`}
              </option>
            ))}
          </select>
        </label>
        <div className="threat-deep-dive-meta">
          <span
            className={`threat-deep-dive-chip threat-deep-dive-chip-${selectedThreat.severity.toLowerCase()}`}
          >
            {selectedThreat.severity}
          </span>
          <span className="threat-deep-dive-chip threat-deep-dive-chip-neutral">
            {selectedThreat.status}
          </span>
          {selectedThreat.scan_status ? (
            <span className="threat-deep-dive-chip threat-deep-dive-chip-neutral">
              Scan: {selectedThreat.scan_status.replace("_", " ")}
            </span>
          ) : null}
        </div>
      </div>

      <div className="threat-deep-dive-summary-grid">
        {[urgencySignal, exploitabilitySignal, regulatorySignal]
          .filter((item): item is DeepDiveSignal => item !== null)
          .map((signal) => (
            <article
              key={signal.title}
              className={`threat-deep-dive-summary-card ${toneClass(signal.tone)}`}
            >
              <p className="threat-deep-dive-summary-kicker">{signal.title}</p>
              <h4>{signal.value}</h4>
              <p>{signal.note}</p>
            </article>
          ))}
      </div>

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>Business Context</h4>
          <span>{selectedThreat.display_id}</span>
        </div>
        <p className="threat-deep-dive-body">
          {model.system_name} is operating as a{" "}
          {model.data_classification.toLowerCase()}{" "}
          {model.deployment_model ?? "unspecified"} system.
          {model.regulatory_scope.length > 0
            ? ` It is already in ${model.regulatory_scope.join(", ")} scope.`
            : " No explicit regulatory framework is attached to the model."}
        </p>
        <p className="threat-deep-dive-body">
          {selectedThreat.relevance_rationale?.trim()
            ? selectedThreat.relevance_rationale
            : "No explicit rationale is stored yet, so engineers should validate whether the modeled path still exists in the current implementation."}
        </p>
        {surfaceLabels.length > 0 ? (
          <div className="threat-deep-dive-chip-row">
            {surfaceLabels.map((label) => (
              <span
                key={label}
                className="threat-deep-dive-chip threat-deep-dive-chip-neutral"
              >
                {label}
              </span>
            ))}
          </div>
        ) : null}
      </section>

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>What Is Real</h4>
          <span>
            {intelLoading || reviewLoading
              ? "Loading evidence…"
              : "Evidence basis"}
          </span>
        </div>
        {intelError ? (
          <p className="threat-deep-dive-warning">{intelError}</p>
        ) : null}
        {reviewError ? (
          <p className="threat-deep-dive-warning">{reviewError}</p>
        ) : null}
        <ul className="threat-deep-dive-list">
          {realityChecks.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
        {attackTechniqueSummary.length > 0 ? (
          <div className="threat-deep-dive-chip-row">
            {attackTechniqueSummary.map((technique) => (
              <span
                key={technique.technique_id}
                className="threat-deep-dive-chip threat-deep-dive-chip-intel"
              >
                {technique.technique_id} · {technique.tactic}
              </span>
            ))}
          </div>
        ) : null}
        {reviewDecision?.evidence_adjustments.length ? (
          <div className="threat-deep-dive-chip-row">
            {reviewDecision.evidence_adjustments.map((item) => (
              <span
                key={`${item.field_affected}-${item.adjusted_value}`}
                className="threat-deep-dive-chip threat-deep-dive-chip-intel"
              >
                {item.field_affected.replace(/_/g, " ")}: {item.adjusted_value}
              </span>
            ))}
          </div>
        ) : null}
      </section>

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>Related Attack Paths</h4>
          <span>{attackPaths.length}</span>
        </div>
        {attackPaths.length > 0 ? (
          <div className="threat-attack-path-stack">
            {attackPaths.map((path) => {
              const entryPoint = path.entry_point || "Unknown entry";
              const targetAsset = path.target_asset || "Unknown target";
              const visibleFindings = path.finding_titles.slice(0, 3);
              const supportingFindingCount =
                path.support_count ?? path.finding_titles.length;
              const pathNodes =
                path.path_nodes && path.path_nodes.length > 0
                  ? path.path_nodes
                  : [entryPoint, targetAsset];
              const modeledStepCount =
                pathNodes.length > 1 ? pathNodes.length - 1 : path.hop_count;
              const relationshipReasons = path.relationship_reasons ?? [];
              const verificationSteps = path.verification_steps ?? [];
              const evidenceSources = path.evidence_sources ?? [];

              return (
                <article key={path.path_id} className="threat-attack-path-row">
                  <div
                    className="threat-attack-path-chain"
                    aria-label={`Attack path from ${entryPoint} to ${targetAsset}`}
                  >
                    <div>
                      <span>Entry</span>
                      <strong>{truncate(entryPoint, 54)}</strong>
                    </div>
                    <span
                      className="threat-attack-path-arrow"
                      aria-hidden="true"
                    >
                      →
                    </span>
                    <div>
                      <span>Target</span>
                      <strong>{truncate(targetAsset, 54)}</strong>
                    </div>
                  </div>
                  <div className="threat-deep-dive-chip-row">
                    <span className="threat-deep-dive-chip threat-deep-dive-chip-neutral">
                      {modeledStepCount} modeled{" "}
                      {modeledStepCount === 1 ? "step" : "steps"}
                    </span>
                    {supportingFindingCount > 0 ? (
                      <span className="threat-deep-dive-chip threat-deep-dive-chip-neutral">
                        {supportingFindingCount} supporting{" "}
                        {supportingFindingCount === 1 ? "finding" : "findings"}
                      </span>
                    ) : null}
                    <span
                      className={`threat-deep-dive-chip ${priorityChipClass(
                        path.composite_priority,
                      )}`}
                    >
                      {priorityLabel(path.composite_priority)}
                    </span>
                    <span className="threat-deep-dive-chip threat-deep-dive-chip-intel">
                      {exploitabilityLabel(path.composite_exploitability)}{" "}
                      exploitability
                    </span>
                  </div>
                  {pathNodes.length > 2 ? (
                    <div className="threat-attack-path-route">
                      <span>Modeled route</span>
                      <ol>
                        {pathNodes.map((node, index) => (
                          <li key={`${path.path_id}-node-${index}`}>
                            {truncate(node, 42)}
                          </li>
                        ))}
                      </ol>
                    </div>
                  ) : null}
                  {evidenceSources.length > 0 ? (
                    <div className="threat-attack-path-evidence">
                      <span>Evidence</span>
                      <div className="threat-deep-dive-chip-row">
                        {evidenceSources.map((source) => (
                          <span
                            key={source}
                            className="threat-deep-dive-chip threat-deep-dive-chip-intel"
                          >
                            {evidenceSourceLabel(source)}
                          </span>
                        ))}
                      </div>
                    </div>
                  ) : null}
                  {visibleFindings.length > 0 ? (
                    <ul className="threat-attack-path-findings">
                      {visibleFindings.map((title, index) => (
                        <li key={`${path.path_id}-finding-${index}`}>
                          {truncate(title, 132)}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  {relationshipReasons.length > 0 ||
                  verificationSteps.length > 0 ? (
                    <div className="threat-attack-path-explain-grid">
                      {relationshipReasons.length > 0 ? (
                        <div>
                          <strong>Why linked</strong>
                          <ul>
                            {relationshipReasons
                              .slice(0, 3)
                              .map((reason, index) => (
                                <li key={`${path.path_id}-reason-${index}`}>
                                  {reason}
                                </li>
                              ))}
                          </ul>
                        </div>
                      ) : null}
                      {verificationSteps.length > 0 ? (
                        <div>
                          <strong>Verify next</strong>
                          <ul>
                            {verificationSteps
                              .slice(0, 3)
                              .map((step, index) => (
                                <li key={`${path.path_id}-step-${index}`}>
                                  {step}
                                </li>
                              ))}
                          </ul>
                        </div>
                      ) : null}
                    </div>
                  ) : null}
                  {verificationSteps.length === 0 ? (
                    <p className="threat-attack-path-action">
                      <strong>Verify next:</strong> no automated verification
                      guidance is available for this path yet.
                    </p>
                  ) : null}
                </article>
              );
            })}
          </div>
        ) : (
          <p className="threat-deep-dive-body">
            No deterministic multi-finding attack chain is currently attached to
            this threat. That usually means the selected threat is isolated in
            the current model or the DFD still needs more connecting detail.
          </p>
        )}
      </section>

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>Bright Red Lines</h4>
          <span>{brightRedLines.length}</span>
        </div>
        {brightRedLines.length > 0 ? (
          <ul className="threat-deep-dive-list threat-deep-dive-list-alert">
            {brightRedLines.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="threat-deep-dive-body">
            Nothing currently crosses the bright-red threshold. That means the
            threat still matters, not that it can be safely ignored.
          </p>
        )}
      </section>

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>Nice to Have Hardening</h4>
          <span>Queue after the urgent path</span>
        </div>
        {niceToHaves.length > 0 ? (
          <ul className="threat-deep-dive-list">
            {niceToHaves.map((item) => (
              <li key={item}>{item}</li>
            ))}
          </ul>
        ) : (
          <p className="threat-deep-dive-body">
            This record already has the basic planning fields filled in. Focus
            on executing and validating the mitigation.
          </p>
        )}
      </section>

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>Lessons Learned</h4>
          <span>Improve the model and the system</span>
        </div>
        <ul className="threat-deep-dive-list">
          {lessonsLearned.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      </section>

      {reviewDecision?.risk_acceptance || reviewDecision?.review_delta ? (
        <section className="threat-deep-dive-section">
          <div className="threat-deep-dive-section-header">
            <h4>Review Continuity</h4>
            <span>
              {reviewDecision?.review_delta?.disposition?.replace(/_/g, " ") ??
                "continuous review"}
            </span>
          </div>
          {reviewDecision?.risk_acceptance ? (
            <p className="threat-deep-dive-body">
              Risk acceptance is currently{" "}
              <strong>{reviewDecision.risk_acceptance.status}</strong>
              {reviewDecision.risk_acceptance.acceptance_rationale
                ? `: ${reviewDecision.risk_acceptance.acceptance_rationale}`
                : "."}
            </p>
          ) : null}
          {reviewDecision?.review_delta ? (
            <ul className="threat-deep-dive-list">
              <li>
                Review disposition:{" "}
                {reviewDecision.review_delta.disposition.replace(/_/g, " ")}.
              </li>
              {reviewDecision.review_delta.days_since_last_review != null ? (
                <li>
                  Days since last review:{" "}
                  {reviewDecision.review_delta.days_since_last_review}.
                </li>
              ) : null}
              {reviewDecision.review_delta.reopened_count > 0 ? (
                <li>
                  Reopened findings in this run:{" "}
                  {reviewDecision.review_delta.reopened_count}.
                </li>
              ) : null}
              {reviewDecision.review_delta.escalated_count > 0 ? (
                <li>
                  Escalated findings in this run:{" "}
                  {reviewDecision.review_delta.escalated_count}.
                </li>
              ) : null}
            </ul>
          ) : null}
        </section>
      ) : null}

      <section className="threat-deep-dive-section">
        <div className="threat-deep-dive-section-header">
          <h4>AI Guidance</h4>
          <button
            type="button"
            className="tm-inspector-visibility-btn"
            onClick={() => void generateAiGuidance()}
            disabled={aiLoading}
          >
            {aiLoading
              ? "Generating..."
              : aiGuidance
                ? "Refresh AI Guidance"
                : "Generate AI Guidance"}
          </button>
        </div>
        {aiError ? <p className="threat-deep-dive-warning">{aiError}</p> : null}
        {aiGuidance ? (
          <div className="threat-deep-dive-ai">
            <p>{aiGuidance.answer}</p>
            {aiGuidance.degraded_reason ? (
              <p className="threat-deep-dive-warning">
                {aiGuidance.degraded_reason}
              </p>
            ) : null}
          </div>
        ) : (
          <p className="threat-deep-dive-body">
            Use the fixed prompt to get a grounded engineering readout for this
            threat without leaving the model workspace.
          </p>
        )}
      </section>
    </div>
  );
}
