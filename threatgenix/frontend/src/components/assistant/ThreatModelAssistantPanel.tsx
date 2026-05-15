import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "../../api/client";
import type {
  AssistantActionArtifact,
  AssistantGuidedStep,
  AssistantMutationOutcome,
  AssistantProposal,
  AssistantProposalBundle,
  AssistantReference,
  AssistantRequest,
  AssistantResponse,
  NodeProperties,
  SecurityReviewFinding,
  ThreatResponse,
} from "../../types/api";

interface AssistantQueuedRequest {
  nonce: number;
  request: AssistantRequest;
}

interface ThreatModelAssistantPanelProps {
  threatModelId: string;
  queuedRequest: AssistantQueuedRequest | null;
  onReferencesChange?: (references: AssistantReference[]) => void;
  onGraphMutated?: () => Promise<AssistantMutationOutcome | void> | AssistantMutationOutcome | void;
  onThreatUpdated?: (threat: ThreatResponse) => void;
  embedded?: boolean;
  selectedReviewFinding?: SecurityReviewFinding | null;
  onPersistActionArtifacts?: (artifacts: AssistantActionArtifact[]) => Promise<void> | void;
}

type UndoAction =
  | { kind: "delete_node"; nodeId: string }
  | { kind: "delete_edge"; edgeId: string }
  | { kind: "delete_boundary"; boundaryId: string }
  | { kind: "delete_assumption"; assumptionId: string }
  | { kind: "restore_threat"; threat: ThreatResponse }
  | {
      kind: "restore_node";
      nodeId: string;
      name: string;
      properties: Record<string, unknown>;
    };

type ProposalState = {
  status: "idle" | "applying" | "applied" | "dismissed" | "undoing" | "error";
  undoActions?: UndoAction[];
  error?: string;
};

type GuidedStepState = {
  stepId: string;
  status: "applying" | "applied" | "undoing" | "error";
  undoActions?: UndoAction[];
  error?: string;
};

type ThreatMitigationDraft = {
  threatId: string;
  title: string;
  summary: string;
  references: AssistantReference[];
  provenance: string;
  status: "idle" | "applying" | "applied" | "undoing" | "error";
  error?: string;
  undoAction?: UndoAction;
};

type MutationSummary = {
  title: string;
  addedThreats: ThreatResponse[];
  removedThreats: ThreatResponse[];
  mitigationDrafts: ThreatMitigationDraft[];
};

type ThreadMessage = {
  id: string;
  role: "assistant" | "user";
  text: string;
  response?: AssistantResponse;
  proposalState?: ProposalState;
  guidedStepState?: GuidedStepState;
  mutationSummary?: MutationSummary;
};

function createId() {
  return typeof crypto !== "undefined" && "randomUUID" in crypto
    ? crypto.randomUUID()
    : Math.random().toString(36).slice(2);
}

function formatMode(mode: AssistantResponse["mode"]) {
  switch (mode) {
    case "ask":
      return "Ask";
    case "explain":
      return "Explain";
    case "review":
      return "Review";
    case "build":
      return "Build";
    default:
      return "Assistant";
  }
}

function severityLabel(severity: string) {
  switch (severity) {
    case "high":
      return "High";
    case "medium":
      return "Medium";
    case "low":
      return "Low";
    default:
      return "Info";
  }
}

function guidedStepStatusLabel(status: AssistantGuidedStep["status"]) {
  switch (status) {
    case "done":
      return "Done";
    case "current":
      return "Current";
    case "up_next":
      return "Up Next";
    default:
      return status;
  }
}

function mergeReferences(references: AssistantReference[]): AssistantReference[] {
  const unique = new Map<string, AssistantReference>();
  for (const reference of references) {
    unique.set(`${reference.kind}:${reference.id}`, reference);
  }
  return Array.from(unique.values());
}

function buildThreatFocusReferences(threat: ThreatResponse): AssistantReference[] {
  return mergeReferences([
    ...threat.affected_node_ids.map((nodeId) => ({
      kind: "node" as const,
      id: nodeId,
      label: threat.display_id,
    })),
    ...threat.affected_edge_ids.map((edgeId) => ({
      kind: "edge" as const,
      id: edgeId,
      label: threat.display_id,
    })),
  ]);
}

function buildMitigationDraft(threat: ThreatResponse): ThreatMitigationDraft {
  const affectedSurface =
    threat.affected_edge_ids.length > 0
      ? "the affected flow"
      : threat.affected_node_ids.length > 0
        ? "the affected component"
        : "the affected surface";

  let summary: string;
  switch (threat.stride_category) {
    case "Spoofing":
      summary =
        `Draft identity checks at ${affectedSurface}, record where authentication is enforced, and verify unauthenticated requests fail closed.`;
      break;
    case "Tampering":
      summary =
        `Draft integrity and input-validation controls around ${affectedSurface}, then define a negative test that proves unauthorized changes are rejected.`;
      break;
    case "Repudiation":
      summary =
        `Draft audit logging for ${affectedSurface}, include actor and outcome fields, and decide who reviews those records.`;
      break;
    case "Information Disclosure":
      summary =
        `Draft confidentiality controls for ${affectedSurface}, including encryption, data minimization, and access checks, then identify the evidence needed to verify them.`;
      break;
    case "Denial of Service":
      summary =
        `Draft resilience controls for ${affectedSurface}, such as throttling, bounded work, and graceful degradation, and capture the load or abuse case you will test.`;
      break;
    case "Elevation of Privilege":
      summary =
        `Draft least-privilege and authorization controls for ${affectedSurface}, then define the escalation path you expect to block in review or test.`;
      break;
    default:
      summary =
        `Draft the first concrete mitigation for ${affectedSurface}, assign an owner, and state what evidence would prove the control really exists.`;
      break;
  }

  return {
    threatId: threat.id,
    title: `Draft mitigation for ${threat.display_id}`,
    summary,
    references: buildThreatFocusReferences(threat),
    provenance: `Suggested because ${threat.display_id} was introduced by the most recent accepted modeling pass.`,
    status: "idle",
  };
}

function buildMutationSummary(
  title: string,
  outcome: AssistantMutationOutcome | void,
): MutationSummary | null {
  if (!outcome) {
    return null;
  }
  const addedThreats = outcome.addedThreats ?? [];
  const removedThreats = outcome.removedThreats ?? [];
  if (addedThreats.length === 0 && removedThreats.length === 0) {
    return null;
  }
  return {
    title,
    addedThreats,
    removedThreats,
    mitigationDrafts: addedThreats.map(buildMitigationDraft),
  };
}

function buildMutationText(title: string, summary: MutationSummary | null): string {
  if (summary == null) {
    return `${title} applied. No immediate rules-based threat delta showed up from this pass.`;
  }

  const parts = [`${title} applied.`];
  if (summary.addedThreats.length > 0) {
    parts.push(
      `The updated model introduced ${summary.addedThreats.length} new rule-based threat${summary.addedThreats.length === 1 ? "" : "s"}.`,
    );
  }
  if (summary.removedThreats.length > 0) {
    parts.push(
      `${summary.removedThreats.length} stale threat${summary.removedThreats.length === 1 ? "" : "s"} dropped out of the model.`,
    );
  }
  if (summary.mitigationDrafts.length > 0) {
    parts.push("Draft mitigations are ready below before you move to the next build step.");
  }
  return parts.join(" ");
}

function advanceGuidedSteps(
  steps: AssistantGuidedStep[],
  completedStepId: string,
): AssistantGuidedStep[] {
  const nextSteps = steps.map((step) => ({
    ...step,
    status: step.id === completedStepId ? ("done" as const) : step.status,
  }));
  const currentIndex = nextSteps.findIndex((step) => step.status !== "done");
  return nextSteps.map((step, index) => ({
    ...step,
    status:
      step.status === "done"
        ? "done"
        : index === currentIndex
          ? "current"
          : "up_next",
  }));
}

function buildThreatRestorePayload(threat: ThreatResponse) {
  return {
    status: threat.status as "Open" | "In Progress" | "Mitigated" | "Accepted" | "Dismissed",
    dismiss_reason: threat.dismiss_reason,
    mitigation_plan: threat.mitigation_plan,
    mitigation_owner: threat.mitigation_owner,
    due_date: threat.due_date,
    mitigation_notes: threat.mitigation_notes,
    control_effectiveness: threat.control_effectiveness,
    residual_risk_level: threat.residual_risk_level,
  };
}

export function ThreatModelAssistantPanel({
  threatModelId,
  queuedRequest,
  onReferencesChange,
  onGraphMutated,
  onThreatUpdated,
  embedded = false,
  selectedReviewFinding = null,
  onPersistActionArtifacts,
}: ThreatModelAssistantPanelProps) {
  const [collapsed, setCollapsed] = useState(false);
  const [input, setInput] = useState("");
  const [sending, setSending] = useState(false);
  const processedQueuedRequestNonceRef = useRef<number | null>(null);
  const [messages, setMessages] = useState<ThreadMessage[]>([
    {
      id: createId(),
      role: "assistant",
      text:
        embedded
          ? "Ask why a finding is real, what makes it urgent, what evidence would move it to Verify, or draft the next remediation note. I stay grounded in the current review queue, findings, evidence gaps, and model context."
          : "Ask about threats, mitigations, model quality, or DFD changes. I can guide a threat-model build, explain a threat, review the current model, or apply small modeling passes while showing the immediate threat delta.",
    },
  ]);

  const sendAssistantRequest = useCallback(async (
    request: AssistantRequest,
    userText?: string | null,
    options?: { syncReferences?: boolean },
  ) => {
    const trimmed = request.message.trim();
    if (!trimmed || sending) return;

    if (userText !== null) {
      const userMessage: ThreadMessage = {
        id: createId(),
        role: "user",
        text: userText ?? trimmed,
      };
      setMessages((current) => [...current, userMessage]);
    }
    setSending(true);

    try {
      const response = await api.assistantRespond(threatModelId, {
        ...request,
        review_finding_id:
          request.review_finding_id ??
          (embedded ? selectedReviewFinding?.id ?? null : null),
      });
      const actionArtifacts = response.action_artifacts ?? [];
      const assistantMessage: ThreadMessage = {
        id: createId(),
        role: "assistant",
        text: response.answer,
        response: {
          ...response,
          action_artifacts: actionArtifacts,
        },
        proposalState: response.proposal ? { status: "idle" } : undefined,
      };
      setMessages((current) => [...current, assistantMessage]);
      if (embedded && actionArtifacts.length > 0) {
        await onPersistActionArtifacts?.(actionArtifacts);
      }
      if ((options?.syncReferences ?? true) && response.references.length > 0) {
        onReferencesChange?.(response.references);
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Assistant request failed.";
      setMessages((current) => [
        ...current,
        {
          id: createId(),
          role: "assistant",
          text: `Assistant request failed. ${message}`,
        },
      ]);
    } finally {
      setSending(false);
    }
  }, [
    embedded,
    onPersistActionArtifacts,
    onReferencesChange,
    selectedReviewFinding?.id,
    sending,
    threatModelId,
  ]);

  async function handleRunGuidedStep(messageId: string, step: AssistantGuidedStep) {
    if (sending) return;
    setInput("");
    if (step.proposal_bundle) {
      await handleApplyGuidedStep(messageId, step);
      return;
    }
    await sendAssistantRequest(
      {
        message: step.prompt,
        mode_hint: "build",
        anchor: step.anchor ?? undefined,
      },
      step.title,
    );
  }

  useEffect(() => {
    if (!queuedRequest) {
      processedQueuedRequestNonceRef.current = null;
      return;
    }
    if (processedQueuedRequestNonceRef.current === queuedRequest.nonce) {
      return;
    }
    if (!embedded) {
      setCollapsed(false);
    }
    if (sending) {
      setInput(queuedRequest.request.message);
      return;
    }
    processedQueuedRequestNonceRef.current = queuedRequest.nonce;
    void sendAssistantRequest(queuedRequest.request);
  }, [embedded, queuedRequest, sendAssistantRequest, sending]);

  async function applyProposal(proposal: AssistantProposal): Promise<{
    undoAction: UndoAction;
    references: AssistantReference[];
  }> {
    switch (proposal.proposal_type) {
      case "create_connected_node": {
        if (
          !proposal.anchor_node_id ||
          !proposal.anchor_handle ||
          !proposal.node_type ||
          !proposal.node_name
        ) {
          throw new Error("Assistant proposal is missing anchor node details.");
        }
        const result = await api.quickAddNode(threatModelId, {
          origin_node_id: proposal.anchor_node_id,
          origin_handle: proposal.anchor_handle,
          node: {
            node_type: proposal.node_type,
            name: proposal.node_name,
            position_x: proposal.position_x ?? 0,
            position_y: proposal.position_y ?? 0,
          },
          edge: {
            label: proposal.edge_label ?? "",
            properties: proposal.edge_properties ?? {},
          },
        });
        return {
          undoAction: { kind: "delete_node", nodeId: result.node.id },
          references: [
            { kind: "node", id: result.node.id, label: result.node.name },
            {
              kind: "edge",
              id: result.edge.id,
              label: result.edge.label || `${result.edge.source_node_id} -> ${result.edge.target_node_id}`,
            },
          ],
        };
      }
      case "create_node": {
        if (!proposal.node_type || !proposal.node_name) {
          throw new Error("Assistant proposal is missing node details.");
        }
        const result = await api.createNode(threatModelId, {
          node_type: proposal.node_type,
          name: proposal.node_name,
          position_x: proposal.position_x ?? 120,
          position_y: proposal.position_y ?? 120,
        });
        return {
          undoAction: { kind: "delete_node", nodeId: result.id },
          references: [{ kind: "node", id: result.id, label: result.name }],
        };
      }
      case "create_edge": {
        if (!proposal.source_node_id || !proposal.target_node_id) {
          throw new Error("Assistant proposal is missing edge endpoints.");
        }
        const result = await api.createEdge(threatModelId, {
          source_node_id: proposal.source_node_id,
          target_node_id: proposal.target_node_id,
          label: proposal.edge_label ?? "",
          properties: proposal.edge_properties ?? {},
        });
        return {
          undoAction: { kind: "delete_edge", edgeId: result.id },
          references: [
            {
              kind: "edge",
              id: result.id,
              label: result.label || `${result.source_node_id} -> ${result.target_node_id}`,
            },
          ],
        };
      }
      case "create_boundary": {
        const result = await api.createBoundary(threatModelId, {
          name: proposal.boundary_name ?? "Trust Boundary",
          node_ids: proposal.boundary_node_ids ?? [],
        });
        return {
          undoAction: { kind: "delete_boundary", boundaryId: result.id },
          references: [{ kind: "boundary", id: result.id, label: result.name }],
        };
      }
      case "update_node": {
        if (!proposal.node_id) {
          throw new Error("Assistant proposal is missing the target node.");
        }
        const dfd = await api.getDFD(threatModelId);
        const existing = dfd.nodes.find((node) => node.id === proposal.node_id);
        if (!existing) {
          throw new Error("The target node no longer exists.");
        }

        const mergedProperties = {
          ...(existing.properties ?? {}),
          ...(proposal.properties_patch ?? {}),
        } as NodeProperties;

        const updated = await api.updateNode(threatModelId, proposal.node_id, {
          ...(proposal.name_patch ? { name: proposal.name_patch } : {}),
          ...(Object.keys(proposal.properties_patch ?? {}).length > 0
            ? { properties: mergedProperties }
            : {}),
        });

        return {
          undoAction: {
            kind: "restore_node",
            nodeId: existing.id,
            name: existing.name,
            properties: existing.properties ?? {},
          },
          references: [{ kind: "node", id: updated.id, label: updated.name }],
        };
      }
      case "create_assumption": {
        if (
          !proposal.assumption_title ||
          !proposal.assumption_anchor_kind ||
          !proposal.assumption_anchor_id ||
          !proposal.assumption_anchor_label
        ) {
          throw new Error("Assistant proposal is missing assumption details.");
        }
        const created = await api.createAssumption(threatModelId, {
          title: proposal.assumption_title,
          description: proposal.assumption_description ?? "",
          status: proposal.assumption_status ?? "open",
          anchor_kind: proposal.assumption_anchor_kind,
          anchor_id: proposal.assumption_anchor_id,
          anchor_label: proposal.assumption_anchor_label,
        });
        return {
          undoAction: { kind: "delete_assumption", assumptionId: created.id },
          references: [
            {
              kind: proposal.assumption_anchor_kind,
              id: proposal.assumption_anchor_id,
              label: proposal.assumption_anchor_label,
            },
          ],
        };
      }
      default:
        throw new Error("Unsupported assistant proposal.");
    }
  }

  async function executeUndo(action: UndoAction) {
    switch (action.kind) {
      case "delete_node":
        await api.deleteNode(threatModelId, action.nodeId);
        break;
      case "delete_edge":
        await api.deleteEdge(threatModelId, action.edgeId);
        break;
      case "delete_boundary":
        await api.deleteBoundary(threatModelId, action.boundaryId);
        break;
      case "delete_assumption":
        await api.deleteAssumption(threatModelId, action.assumptionId);
        break;
      case "restore_threat":
        await api.triageThreat(
          threatModelId,
          action.threat.id,
          buildThreatRestorePayload(action.threat),
        );
        break;
      case "restore_node":
        await api.updateNode(threatModelId, action.nodeId, {
          name: action.name,
          properties: action.properties as NodeProperties,
        });
        break;
      default:
        break;
    }
  }

  async function executeUndoActions(actions: UndoAction[]) {
    for (const action of actions) {
      await executeUndo(action);
    }
  }

  async function applyProposalBundle(bundle: AssistantProposalBundle): Promise<{
    undoActions: UndoAction[];
    references: AssistantReference[];
  }> {
    const undoActions: UndoAction[] = [];
    const references: AssistantReference[] = [];
    try {
      for (const proposal of bundle.proposals) {
        const result = await applyProposal(proposal);
        undoActions.unshift(result.undoAction);
        references.push(...result.references);
      }
      return {
        undoActions,
        references: mergeReferences(references),
      };
    } catch (error) {
      if (undoActions.length > 0) {
        try {
          await executeUndoActions(undoActions);
        } catch {
          // Best-effort rollback for partially-applied passes.
        }
      }
      throw error;
    }
  }

  async function handleApply(messageId: string, proposal: AssistantProposal) {
    setMessages((current) =>
      current.map((message) =>
        message.id === messageId
          ? {
              ...message,
              proposalState: { status: "applying" },
            }
          : message
      )
    );

    try {
      const result = await applyProposal(proposal);
      const outcome = await onGraphMutated?.();
      onReferencesChange?.(result.references);
      const mutationSummary = buildMutationSummary(proposal.title, outcome);
      setMessages((current) => {
        const nextMessages: ThreadMessage[] = [
          ...current.map((message): ThreadMessage =>
            message.id === messageId
              ? {
                  ...message,
                  proposalState: {
                    status: "applied",
                    undoActions: [result.undoAction],
                  },
                }
              : message,
          ),
          {
            id: createId(),
            role: "assistant",
            text: buildMutationText(proposal.title, mutationSummary),
            mutationSummary: mutationSummary ?? undefined,
          },
        ];
        return nextMessages;
      });
      if (mutationSummary?.addedThreats[0]) {
        onReferencesChange?.(buildThreatFocusReferences(mutationSummary.addedThreats[0]));
      }
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to apply proposal.";
      setMessages((current) =>
        current.map((item) =>
          item.id === messageId
            ? {
                ...item,
                proposalState: {
                  status: "error",
                  error: message,
                },
              }
            : item
        )
      );
    }
  }

  async function handleUndo(messageId: string, actions: UndoAction[] | undefined) {
    if (!actions || actions.length === 0) return;
    setMessages((current) =>
      current.map((message) =>
        message.id === messageId
          ? {
              ...message,
              proposalState: {
                ...message.proposalState,
                status: "undoing",
                undoActions: actions,
              },
            }
          : message
      )
    );

    try {
      await executeUndoActions(actions);
      await onGraphMutated?.();
      setMessages((current) =>
        current.map((message) =>
          message.id === messageId
            ? {
                ...message,
                proposalState: { status: "idle" },
              }
            : message
        )
      );
      onReferencesChange?.([]);
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to undo assistant change.";
      setMessages((current) =>
        current.map((item) =>
          item.id === messageId
            ? {
                ...item,
                proposalState: {
                ...item.proposalState,
                  status: "error",
                  error: message,
                  undoActions: actions,
                },
              }
            : item
        )
      );
    }
  }

  async function handleApplyGuidedStep(messageId: string, step: AssistantGuidedStep) {
    const proposalBundle = step.proposal_bundle;
    if (!proposalBundle) return;

    setMessages((current) =>
      current.map((message) =>
        message.id === messageId
          ? {
              ...message,
              guidedStepState: {
                stepId: step.id,
                status: "applying",
              },
            }
          : message,
      ),
    );

    try {
      const result = await applyProposalBundle(proposalBundle);
      const outcome = await onGraphMutated?.();
      const mutationSummary = buildMutationSummary(proposalBundle.title, outcome);
      onReferencesChange?.(result.references);
      setMessages((current) => {
        const nextMessages: ThreadMessage[] = [
          ...current.map((message): ThreadMessage =>
            message.id === messageId
              ? {
                  ...message,
                  response: message.response
                    ? {
                        ...message.response,
                        guided_steps: advanceGuidedSteps(message.response.guided_steps, step.id),
                      }
                    : message.response,
                  guidedStepState: {
                    stepId: step.id,
                    status: "applied",
                    undoActions: result.undoActions,
                  },
                }
              : message,
          ),
          {
            id: createId(),
            role: "assistant",
            text: buildMutationText(proposalBundle.title, mutationSummary),
            mutationSummary: mutationSummary ?? undefined,
          },
        ];
        return nextMessages;
      });
      if (mutationSummary?.addedThreats[0]) {
        onReferencesChange?.(buildThreatFocusReferences(mutationSummary.addedThreats[0]));
      }
      await sendAssistantRequest(
        {
          message: "/build guide me through building this threat model",
          mode_hint: "build",
        },
        null,
        { syncReferences: false },
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to apply guided step.";
      setMessages((current) =>
        current.map((item) =>
          item.id === messageId
            ? {
                ...item,
                guidedStepState: {
                  stepId: step.id,
                  status: "error",
                  error: message,
                },
              }
            : item,
        ),
      );
    }
  }

  async function handleUndoGuidedStep(messageId: string, stepId: string, actions: UndoAction[] | undefined) {
    if (!actions || actions.length === 0) return;

    setMessages((current) =>
      current.map((message) =>
        message.id === messageId
          ? {
              ...message,
              guidedStepState: {
                stepId,
                status: "undoing",
                undoActions: actions,
              },
            }
          : message,
      ),
    );

    try {
      await executeUndoActions(actions);
      await onGraphMutated?.();
      setMessages((current) =>
        current.map((message) =>
          message.id === messageId
            ? {
                ...message,
                guidedStepState: undefined,
              }
            : message,
        ),
      );
      onReferencesChange?.([]);
      await sendAssistantRequest(
        {
          message: "/build guide me through building this threat model",
          mode_hint: "build",
        },
        null,
        { syncReferences: false },
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : "Failed to undo guided step.";
      setMessages((current) =>
        current.map((item) =>
          item.id === messageId
            ? {
                ...item,
                guidedStepState: {
                  stepId,
                  status: "error",
                  error: message,
                  undoActions: actions,
                },
              }
            : item,
        ),
      );
    }
  }

  async function handleApplyMitigationDraft(messageId: string, threatId: string) {
    const message = messages.find((entry) => entry.id === messageId);
    const previousThreat = message?.mutationSummary?.addedThreats.find((threat) => threat.id === threatId);
    const draft = message?.mutationSummary?.mitigationDrafts.find((item) => item.threatId === threatId);
    if (!previousThreat || !draft) return;

    setMessages((current) =>
      current.map((entry) =>
        entry.id === messageId && entry.mutationSummary
          ? {
              ...entry,
              mutationSummary: {
                ...entry.mutationSummary,
                mitigationDrafts: entry.mutationSummary.mitigationDrafts.map((item) =>
                  item.threatId === threatId
                    ? { ...item, status: "applying", error: undefined }
                    : item,
                ),
              },
            }
          : entry,
      ),
    );

    try {
      const notes = [previousThreat.mitigation_notes, "Assistant mitigation draft applied from the latest modeling pass."]
        .filter(Boolean)
        .join("\n\n");
      const updated = await api.triageThreat(threatModelId, threatId, {
        status: "In Progress",
        dismiss_reason: previousThreat.dismiss_reason,
        mitigation_plan: draft.summary,
        mitigation_owner: previousThreat.mitigation_owner,
        due_date: previousThreat.due_date,
        mitigation_notes: notes || null,
        control_effectiveness: previousThreat.control_effectiveness,
        residual_risk_level: previousThreat.residual_risk_level,
      });
      onThreatUpdated?.(updated);
      onReferencesChange?.(draft.references);
      setMessages((current) =>
        current.map((entry) =>
          entry.id === messageId && entry.mutationSummary
            ? {
                ...entry,
                mutationSummary: {
                  ...entry.mutationSummary,
                  addedThreats: entry.mutationSummary.addedThreats.map((threat) =>
                    threat.id === threatId ? updated : threat,
                  ),
                  mitigationDrafts: entry.mutationSummary.mitigationDrafts.map((item) =>
                    item.threatId === threatId
                      ? {
                          ...item,
                          status: "applied",
                          undoAction: { kind: "restore_threat", threat: previousThreat },
                          error: undefined,
                        }
                      : item,
                  ),
                },
              }
            : entry,
        ),
      );
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : "Failed to apply mitigation draft.";
      setMessages((current) =>
        current.map((entry) =>
          entry.id === messageId && entry.mutationSummary
            ? {
                ...entry,
                mutationSummary: {
                  ...entry.mutationSummary,
                  mitigationDrafts: entry.mutationSummary.mitigationDrafts.map((item) =>
                    item.threatId === threatId
                      ? { ...item, status: "error", error: messageText }
                      : item,
                  ),
                },
              }
            : entry,
        ),
      );
    }
  }

  async function handleUndoMitigationDraft(messageId: string, threatId: string, action: UndoAction | undefined) {
    if (!action || action.kind !== "restore_threat") return;

    setMessages((current) =>
      current.map((entry) =>
        entry.id === messageId && entry.mutationSummary
          ? {
              ...entry,
              mutationSummary: {
                ...entry.mutationSummary,
                mitigationDrafts: entry.mutationSummary.mitigationDrafts.map((item) =>
                  item.threatId === threatId
                    ? { ...item, status: "undoing", error: undefined }
                    : item,
                ),
              },
            }
          : entry,
      ),
    );

    try {
      const restored = await api.triageThreat(
        threatModelId,
        threatId,
        buildThreatRestorePayload(action.threat),
      );
      onThreatUpdated?.(restored);
      setMessages((current) =>
        current.map((entry) =>
          entry.id === messageId && entry.mutationSummary
            ? {
                ...entry,
                mutationSummary: {
                  ...entry.mutationSummary,
                  addedThreats: entry.mutationSummary.addedThreats.map((threat) =>
                    threat.id === threatId ? restored : threat,
                  ),
                  mitigationDrafts: entry.mutationSummary.mitigationDrafts.map((item) =>
                    item.threatId === threatId
                      ? { ...item, status: "idle", undoAction: undefined, error: undefined }
                      : item,
                  ),
                },
              }
            : entry,
        ),
      );
    } catch (error) {
      const messageText =
        error instanceof Error ? error.message : "Failed to undo mitigation draft.";
      setMessages((current) =>
        current.map((entry) =>
          entry.id === messageId && entry.mutationSummary
            ? {
                ...entry,
                mutationSummary: {
                  ...entry.mutationSummary,
                  mitigationDrafts: entry.mutationSummary.mitigationDrafts.map((item) =>
                    item.threatId === threatId
                      ? { ...item, status: "error", error: messageText, undoAction: action }
                      : item,
                  ),
                },
              }
            : entry,
        ),
      );
    }
  }

  function handleDismiss(messageId: string) {
    setMessages((current) =>
      current.map((message) =>
        message.id === messageId
          ? {
              ...message,
              proposalState: { status: "dismissed" },
            }
          : message
      )
    );
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || sending) return;
    setInput("");
    await sendAssistantRequest({ message: trimmed });
  }

  if (!embedded && collapsed) {
    return (
      <aside className="assistant-panel assistant-panel-collapsed">
        <button
          type="button"
          className="assistant-panel-toggle"
          onClick={() => setCollapsed(false)}
          title="Open the assistant panel"
        >
          Open Assistant
        </button>
      </aside>
    );
  }

  return (
    <aside className={`assistant-panel${embedded ? " assistant-panel-embedded" : ""}`}>
      <div className="assistant-panel-header">
        <div>
          <h3>{embedded ? "Security Copilot" : "AI Assistant"}</h3>
          <p>
            {embedded
              ? "Grounded in the live review queue, findings, and evidence."
              : "Grounded in the live model, threats, and evidence."}
          </p>
        </div>
        {!embedded ? (
          <button
            type="button"
            className="assistant-panel-icon"
            onClick={() => setCollapsed(true)}
            aria-label="Collapse assistant"
            title="Collapse the assistant panel"
          >
            ×
          </button>
        ) : null}
      </div>

      <div className="assistant-quick-actions">
        {embedded ? (
          <>
            <button
              type="button"
              className="assistant-quick-action"
              onClick={() => {
                void sendAssistantRequest(
                  {
                    message: "/review explain why this finding matters now and what makes it real",
                  },
                  selectedReviewFinding
                    ? `Why does ${selectedReviewFinding.title} matter now?`
                    : "Why does the current top finding matter now?",
                );
              }}
              disabled={sending}
            >
              Why This Matters
            </button>
            <button
              type="button"
              className="assistant-quick-action"
              onClick={() => {
                void sendAssistantRequest(
                  {
                    message: "/ask what evidence would move this finding toward verify or closure?",
                  },
                  selectedReviewFinding
                    ? `What evidence closes ${selectedReviewFinding.title}?`
                    : "What evidence would move this finding?",
                );
              }}
              disabled={sending}
            >
              Evidence To Verify
            </button>
            <button
              type="button"
              className="assistant-quick-action"
              onClick={() => {
                void sendAssistantRequest(
                  {
                    message: "/ask draft the remediation or verification note for this finding",
                  },
                  selectedReviewFinding
                    ? `Draft the next note for ${selectedReviewFinding.title}`
                    : "Draft the next remediation note",
                );
              }}
              disabled={sending}
            >
              Draft Next Step
            </button>
          </>
        ) : (
          <>
            <button
              type="button"
              className="assistant-quick-action"
              onClick={() => {
                void sendAssistantRequest({
                  message: "/build guide me through building this threat model",
                }, "Guide me through building this threat model.");
              }}
              disabled={sending}
            >
              Build Model
            </button>
            <button
              type="button"
              className="assistant-quick-action"
              onClick={() => {
                void sendAssistantRequest({
                  message: "/review review this threat model and tell me what to fix first",
                }, "Review the current model and tell me what to fix first.");
              }}
              disabled={sending}
            >
              Review Model
            </button>
            <button
              type="button"
              className="assistant-quick-action"
              onClick={() => {
                void sendAssistantRequest({
                  message: "/ask what should I do next?",
                }, "What should I do next?");
              }}
              disabled={sending}
            >
              What Next?
            </button>
          </>
        )}
      </div>

      <div className="assistant-thread">
        {messages.map((message) => (
          <div
            key={message.id}
            className={`assistant-message assistant-message-${message.role}`}
          >
            {message.response && (
              <span className={`assistant-mode-badge assistant-mode-${message.response.mode}`}>
                {formatMode(message.response.mode)}
              </span>
            )}
            <p>{message.text}</p>
            {message.response?.degraded_reason && (
              <div className="assistant-degraded-note">{message.response.degraded_reason}</div>
            )}
            {message.response?.references.length ? (
              <div className="assistant-reference-list">
                {message.response.references.map((reference) => (
                  <button
                    key={`${reference.kind}-${reference.id}`}
                    type="button"
                    className="assistant-reference-chip"
                    onClick={() => onReferencesChange?.([reference])}
                    title={`Focus ${reference.label} in the current workspace`}
                  >
                    {reference.label}
                  </button>
                ))}
              </div>
            ) : null}
            {message.response?.findings.length ? (
              <div className="assistant-findings">
                {message.response.findings.map((finding, index) => (
                  <div key={`${message.id}-finding-${index}`} className="assistant-finding-card">
                    <div className="assistant-finding-header">
                      <span className={`assistant-finding-severity assistant-finding-${finding.severity}`}>
                        {severityLabel(finding.severity)}
                      </span>
                      <strong>{finding.title}</strong>
                    </div>
                    <p>{finding.description}</p>
                    {finding.references.length > 0 && (
                      <div className="assistant-reference-list">
                        {finding.references.map((reference) => (
                          <button
                            key={`${reference.kind}-${reference.id}`}
                            type="button"
                            className="assistant-reference-chip"
                            onClick={() => onReferencesChange?.([reference])}
                            title={`Focus ${reference.label} in the current workspace`}
                          >
                            {reference.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : null}
            {message.response?.action_artifacts?.length ? (
              <div className="assistant-findings">
                {message.response.action_artifacts.map((artifact, index) => (
                  <div key={`${message.id}-artifact-${index}`} className="assistant-finding-card assistant-artifact-card">
                    <div className="assistant-finding-header">
                      <span className="assistant-finding-severity assistant-finding-medium">
                        {artifact.kind === "verification_note"
                          ? "Verify"
                          : artifact.kind === "evidence_request"
                            ? "Evidence"
                            : "Fix"}
                      </span>
                      <strong>{artifact.title}</strong>
                    </div>
                    <p>{artifact.summary}</p>
                    <pre className="assistant-artifact-body">{artifact.body}</pre>
                    {artifact.references.length > 0 && (
                      <div className="assistant-reference-list">
                        {artifact.references.map((reference) => (
                          <button
                            key={`${reference.kind}-${reference.id}`}
                            type="button"
                            className="assistant-reference-chip"
                            onClick={() => onReferencesChange?.([reference])}
                            title={`Focus ${reference.label} in the current workspace`}
                          >
                            {reference.label}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            ) : null}
            {message.response?.guided_steps.length ? (
              <div className="assistant-guided-steps">
                <div className="assistant-guided-header">
                  <strong>Guided Build Plan</strong>
                  <span>{message.response.guided_steps.length} steps</span>
                </div>
                {message.response.guided_steps.map((step) => {
                  const currentGuidedState =
                    message.guidedStepState?.stepId === step.id ? message.guidedStepState : undefined;
                  const hasAutoApply = Boolean(step.proposal_bundle);

                  return (
                    <div key={`${message.id}-step-${step.id}`} className={`assistant-guided-step assistant-guided-step-${step.status}`}>
                      <div className="assistant-guided-step-head">
                        <div>
                          <strong>{step.title}</strong>
                          <p>{step.description}</p>
                        </div>
                        <span className={`assistant-guided-step-status assistant-guided-step-status-${step.status}`}>
                          {guidedStepStatusLabel(step.status)}
                        </span>
                      </div>
                      {step.proposal_bundle ? (
                        <div className="assistant-guided-note">
                          <strong>{step.proposal_bundle.title}</strong>
                          <span>{step.proposal_bundle.summary}</span>
                        </div>
                      ) : null}
                      {step.provenance.length > 0 ? (
                        <div className="assistant-guided-provenance">
                          <strong>Why this step</strong>
                          {step.provenance.map((detail, index) => (
                            <p key={`${message.id}-${step.id}-provenance-${index}`}>{detail}</p>
                          ))}
                        </div>
                      ) : null}
                      {step.references.length > 0 ? (
                        <div className="assistant-reference-list">
                          {step.references.map((reference) => (
                            <button
                              key={`${message.id}-${step.id}-${reference.kind}-${reference.id}`}
                              type="button"
                              className="assistant-reference-chip"
                              onClick={() => onReferencesChange?.([reference])}
                              title={`Focus ${reference.label} in the current workspace`}
                            >
                              {reference.label}
                            </button>
                          ))}
                        </div>
                      ) : null}
                      {currentGuidedState?.error ? (
                        <div className="assistant-proposal-error">{currentGuidedState.error}</div>
                      ) : null}
                      {step.status !== "done" || currentGuidedState != null ? (
                        <div className="assistant-guided-step-actions">
                          {currentGuidedState?.status === "applied" ? (
                            <>
                              <span>Applied</span>
                              <button
                                type="button"
                                className="assistant-dismiss-button"
                                onClick={() => {
                                  void handleUndoGuidedStep(
                                    message.id,
                                    step.id,
                                    currentGuidedState.undoActions,
                                  );
                                }}
                                title="Undo the applied guided step"
                              >
                                Undo
                              </button>
                            </>
                          ) : currentGuidedState?.status === "applying" ? (
                            <span>Applying…</span>
                          ) : currentGuidedState?.status === "undoing" ? (
                            <span>Undoing…</span>
                          ) : (
                          <button
                            type="button"
                            className="assistant-apply-button"
                            onClick={() => {
                              void handleRunGuidedStep(message.id, step);
                            }}
                            disabled={sending}
                            title={hasAutoApply ? "Apply this guided step directly to the live model" : "Run this guided step with assistant support"}
                          >
                            {hasAutoApply ? "Apply Step" : "Run Step"}
                          </button>
                          )}
                        </div>
                      ) : null}
                    </div>
                  );
                })}
              </div>
            ) : null}
            {message.mutationSummary ? (
              <div className="assistant-delta-card">
                <div className="assistant-delta-header">
                  <strong>Threat Delta</strong>
                  <span>Rules-only feedback</span>
                </div>
                {message.mutationSummary.addedThreats.length > 0 ? (
                  <div className="assistant-delta-group">
                    <strong>New threats</strong>
                    {message.mutationSummary.addedThreats.map((threat) => (
                      <div key={`${message.id}-added-${threat.id}`} className="assistant-delta-threat">
                        <div className="assistant-delta-threat-head">
                          <strong>{threat.display_id}</strong>
                          <span>{threat.stride_category} · {threat.severity}</span>
                        </div>
                        <p>{threat.description}</p>
                        <div className="assistant-reference-list">
                          <button
                            type="button"
                            className="assistant-reference-chip"
                            onClick={() => onReferencesChange?.(buildThreatFocusReferences(threat))}
                            title="Highlight the affected graph objects for this threat"
                          >
                            Focus Affected Objects
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
                {message.mutationSummary.mitigationDrafts.length > 0 ? (
                  <div className="assistant-delta-group">
                    <strong>Draft mitigations</strong>
                    {message.mutationSummary.mitigationDrafts.map((draft) => (
                      <div key={`${message.id}-draft-${draft.threatId}`} className="assistant-delta-draft">
                        <strong>{draft.title}</strong>
                        <p>{draft.summary}</p>
                        <div className="assistant-guided-footnote">{draft.provenance}</div>
                        {draft.error ? (
                          <div className="assistant-proposal-error">{draft.error}</div>
                        ) : null}
                        <div className="assistant-reference-list">
                          <button
                            type="button"
                            className="assistant-reference-chip"
                            onClick={() => onReferencesChange?.(draft.references)}
                            title="Highlight the threat surface referenced by this draft"
                          >
                            Focus Threat Surface
                          </button>
                          {draft.status === "idle" || draft.status === "error" ? (
                            <button
                              type="button"
                              className="assistant-apply-button"
                              onClick={() => {
                                void handleApplyMitigationDraft(message.id, draft.threatId);
                              }}
                              title="Apply this mitigation draft to the threat"
                            >
                              Apply Draft
                            </button>
                          ) : null}
                          {draft.status === "applying" ? <span>Applying…</span> : null}
                          {draft.status === "undoing" ? <span>Undoing…</span> : null}
                          {draft.status === "applied" ? (
                            <>
                              <span>Applied</span>
                              <button
                                type="button"
                                className="assistant-dismiss-button"
                                onClick={() => {
                                  void handleUndoMitigationDraft(
                                    message.id,
                                    draft.threatId,
                                    draft.undoAction,
                                  );
                                }}
                                title="Undo the applied mitigation draft"
                              >
                                Undo Draft
                              </button>
                            </>
                          ) : null}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
                {message.mutationSummary.removedThreats.length > 0 ? (
                  <div className="assistant-delta-group">
                    <strong>Removed threats</strong>
                    <p>
                      {message.mutationSummary.removedThreats.map((threat) => threat.display_id).join(", ")}
                    </p>
                  </div>
                ) : null}
                <div className="assistant-guided-footnote">
                  Immediate deltas use the fast rules pass. Run full analysis later if you want AI-enriched threats.
                </div>
              </div>
            ) : null}
            {message.response?.proposal && message.proposalState && (
              <div className="assistant-proposal-card">
                <div className="assistant-proposal-header">
                  <strong>{message.response.proposal.title}</strong>
                  <span className="assistant-proposal-type">
                    {message.response.proposal.proposal_type}
                  </span>
                </div>
                <p>{message.response.proposal.summary}</p>
                {message.proposalState.error && (
                  <div className="assistant-proposal-error">{message.proposalState.error}</div>
                )}
                <div className="assistant-proposal-actions">
                  {message.proposalState.status === "idle" && (
                    <>
                      <button
                        type="button"
                        className="assistant-apply-button"
                        onClick={() => {
                          void handleApply(message.id, message.response!.proposal!);
                        }}
                        title="Apply this assistant proposal to the live model"
                      >
                        Apply
                      </button>
                      <button
                        type="button"
                        className="assistant-dismiss-button"
                        onClick={() => handleDismiss(message.id)}
                        title="Dismiss this assistant proposal"
                      >
                        Dismiss
                      </button>
                    </>
                  )}
                  {message.proposalState.status === "applying" && <span>Applying…</span>}
                  {message.proposalState.status === "dismissed" && <span>Dismissed</span>}
                  {message.proposalState.status === "applied" && (
                    <>
                      <span>Applied</span>
                      <button
                        type="button"
                        className="assistant-dismiss-button"
                        onClick={() => {
                          void handleUndo(message.id, message.proposalState?.undoActions);
                        }}
                        title="Undo the applied assistant proposal"
                      >
                        Undo
                      </button>
                    </>
                  )}
                  {message.proposalState.status === "undoing" && <span>Undoing…</span>}
                  {message.proposalState.status === "error" && (
                    <button
                      type="button"
                      className="assistant-apply-button"
                      onClick={() => {
                        void handleApply(message.id, message.response!.proposal!);
                      }}
                      title="Retry applying this assistant proposal"
                    >
                      Retry Apply
                    </button>
                  )}
                </div>
              </div>
            )}
          </div>
        ))}
        {sending && <div className="assistant-message assistant-message-assistant">Thinking…</div>}
      </div>

      <form className="assistant-input-form" onSubmit={handleSubmit}>
        <textarea
          value={input}
          onChange={(event) => setInput(event.target.value)}
          placeholder={
            embedded
              ? "Ask why this is in Fix Now, what evidence is missing, or draft the next remediation note…"
              : "Ask about this threat model, explain a threat, or propose a DFD change…"
          }
          rows={3}
          disabled={sending}
        />
        <div className="assistant-input-actions">
          <span className="assistant-input-hint">
            {embedded
              ? "Use `/review`, `/ask`, or `/explain`."
              : "Use `/review`, `/ask`, `/build`, or `/explain`."}
          </span>
          <button type="submit" className="assistant-send-button" disabled={sending || !input.trim()}>
            Send
          </button>
        </div>
      </form>
    </aside>
  );
}
