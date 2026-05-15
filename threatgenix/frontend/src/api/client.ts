import type {
  BYOKKeyRequest,
  BYOKKeyResponse,
  BYOKTestResult,
  OrchestrationJob,
  AttackPathResponse,
  ThreatModelCreate,
  ThreatModelCollaboratorCreate,
  ThreatModelCollaboratorResponse,
  ThreatModelCollaboratorUpdate,
  ThreatModelAssignmentCreate,
  ThreatModelAssignmentResponse,
  ThreatModelAssignmentUpdate,
  ThreatModelNotificationResponse,
  ThreatModelAssumptionCreate,
  ThreatModelAssumptionResponse,
  ThreatModelAssumptionUpdate,
  ThreatModelVersionCreate,
  ThreatModelVersionResponse,
  ThreatModelVersionDiffRequest,
  ThreatModelVersionDiffResponse,
  ThreatModelReviewCreate,
  ThreatModelReviewResponse,
  ThreatModelReviewUpdate,
  ThreatModelControlCreate,
  ThreatModelControlResponse,
  ThreatModelControlUpdate,
  ArchitectureValidationSummary,
  ThreatModelResponse,
  ThreatModelListItem,
  EvidenceStatusResponse,
  TMACFormat,
  TMACImportRequest,
  TMACImportResponse,
  TMACValidationResponse,
  TMACDiffResponse,
  DFDResponse,
  DFDBulkSave,
  DFDNodeCreate,
  DFDNodeResponse,
  DFDNodeUpdate,
  DFDEdgeCreate,
  DFDEdgeUpdate,
  DFDEdgeResponse,
  DFDQuickAddRequest,
  DFDQuickAddResponse,
  DFDIacImportRequest,
  DFDIacImportResponse,
  DFDRepositorySeedApplyRequest,
  DFDRepositorySeedApplyResponse,
  DFDRepositorySeedPreviewResponse,
  DFDDecompositionViewCreate,
  DFDWorkspaceViewCreate,
  DFDViewResponse,
  DFDViewUpdate,
  DFDQualityGateSummary,
  DFDComponentTemplateDraft,
  DFDComponentTemplateResponse,
  DFDComponentTemplateSuggestRequest,
  DFDComponentTemplateSuggestResponse,
  DFDPropertyOptionDraft,
  DFDPropertyOptionResponse,
  DFDPropertyOptionSuggestRequest,
  DFDPropertyOptionSuggestResponse,
  TrustBoundaryCreate,
  TrustBoundaryResponse,
  DocumentUploadResponse,
  ThreatResponse,
  FixAgentType,
  ThreatRemediationEvidenceRequest,
  ThreatRemediationHandoffConfirmRequest,
  ThreatRemediationRun,
  ThreatRemediationRunCreate,
  ThreatValidationRun,
  ThreatValidationRunCreate,
  ThreatScanPlanApproveRequest,
  ThreatScanPlanCreate,
  ThreatScanPlanRejectRequest,
  ThreatTriageRequest,
  ThreatQualifyRequest,
  ThreatClusterResponse,
  QualificationProgressResponse,
  BulkTriageRequest,
  ResidualRiskSummary,
  ThreatSummary,
  AnalyzeResponse,
  PortfolioSummary,
  PortfolioTrendResponse,
  ThreatAuditEntry,
  ThreatDiffResponse,
  ThreatCatalogEntry,
  ThreatIntelContextualAssessment,
  ThreatIntelResponse,
  AgentSecurityReviewResponse,
  AgentRemediationEvidenceWebhookRequest,
  AgentRemediationEvidenceWebhookResponse,
  AgentRemediationProviderWebhookTestRequest,
  AgentRemediationProviderWebhookTestResponse,
  AgentRemediationConnectorTicketCreateRequest,
  AgentRemediationConnectorTicketCreateResponse,
  AgentRemediationPlanApplyResponse,
  AgentRemediationPlanResponse,
  AgentRemediationTicketCreateRequest,
  AgentRemediationTicketCreateResponse,
  CustomerSecurityPacketResponse,
  SecurityReviewApplicationSummary,
  SecurityReviewDecision,
  ReviewArtifactKind,
  SecurityReviewFinding,
  SecurityReviewFindingListResponse,
  SecurityReviewRiskAcceptanceRequest,
  SecurityReviewStateUpdate,
  ManualThreatCreate,
  EnvironmentEvidenceResponse,
  GitHubRepositoryImportRequest,
  GitHubRepositoryRefreshRequest,
  EvidenceIngestRequest,
  ValidationRunRequest,
  ScanJob,
  ScanJobDetail,
  ScanCorrelationSummaryResponse,
  ThreatScanCorrelationResponse,
  ValidationRunbookResponse,
  ValidationToolInventoryResponse,
  ValidationEvidenceBindingRequest,
  ValidationEvidenceBindingResponse,
  ProductSecurityValidationCase,
  ValidationLabSummary,
  ValidationTargetBundle,
  ValidationArtifactBundle,
  ValidationArtifactBundleImportResponse,
  ValidationCaseStateUpdateRequest,
  ValidationSchedule,
  ValidationScheduleCreateRequest,
  ValidationScheduleUpdateRequest,
  AssistantRequest,
  AssistantResponse,
  ThreatModelScorecardResponse,
  ReportTemplateDefinition,
  LLMProviderHealth,
  UserResponse,
  ApplicationReview,
  ApplicationReviewAIExplanation,
  ApplicationReviewArtifact,
  ApplicationReviewContextPacket,
  ApplicationReviewContextSearchResponse,
  ApplicationReviewDecision,
  AgentReviewStatus,
  AgentToolCapability,
} from "../types/api";

const BASE = "/api";

function withViewId(path: string, viewId?: string | null): string {
  if (!viewId) {
    return path;
  }
  const separator = path.includes("?") ? "&" : "?";
  return `${path}${separator}view_id=${encodeURIComponent(viewId)}`;
}

function getAuthHeaders(): Record<string, string> {
  const token = localStorage.getItem("tg_token");
  return token ? { Authorization: `Bearer ${token}` } : {};
}

function formatApiError(status: number, body: string): string {
  let detail = body.trim();
  try {
    const parsed = JSON.parse(body) as { detail?: unknown };
    if (typeof parsed.detail === "string") {
      detail = parsed.detail;
    } else if (Array.isArray(parsed.detail)) {
      const messages = parsed.detail
        .map((item) => {
          if (item && typeof item === "object" && "msg" in item) {
            const msg = (item as { msg?: unknown }).msg;
            return typeof msg === "string" ? msg : null;
          }
          return null;
        })
        .filter((message): message is string => Boolean(message));
      if (messages.length > 0) {
        detail = messages.join("; ");
      }
    }
  } catch {
    // Preserve the original response body.
  }
  if (status === 403 && /plan|entitlement|billing/i.test(detail)) {
    return `Upgrade required: ${detail}. Ask an organization admin to enable this entitlement or use the available pilot workflow.`;
  }
  return detail ? `${status}: ${detail}` : `${status}: Request failed`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const { headers: initHeaders, ...restInit } = init ?? {};
  const res = await fetch(`${BASE}${path}`, {
    ...restInit,
    headers: { "Content-Type": "application/json", ...getAuthHeaders(), ...initHeaders },
  });
  if (res.status === 401) {
    localStorage.removeItem("tg_token");
    window.location.href = "/";
    throw new Error("Session expired. Please log in again.");
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(formatApiError(res.status, body));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

async function requestForm<T>(path: string, form: FormData, init?: RequestInit): Promise<T> {
  const { headers: initHeaders, ...restInit } = init ?? {};
  const res = await fetch(`${BASE}${path}`, {
    ...restInit,
    method: restInit.method ?? "POST",
    body: form,
    headers: { ...getAuthHeaders(), ...initHeaders },
  });
  if (res.status === 401) {
    localStorage.removeItem("tg_token");
    window.location.href = "/";
    throw new Error("Session expired. Please log in again.");
  }
  if (!res.ok) {
    const body = await res.text();
    throw new Error(formatApiError(res.status, body));
  }
  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

const EMPTY_THREAT_INTEL_CONTEXTUAL_ASSESSMENT: ThreatIntelContextualAssessment = {
  threat_classes: [],
  confidence: "Low",
  ssvc_decision: "Track",
  why_applicable: [],
  what_to_verify: [],
  decision_rationale: [],
};

function normalizeThreatIntelResponse(
  payload: Partial<ThreatIntelResponse>
): ThreatIntelResponse {
  const contextualAssessment = payload.contextual_assessment;

  return {
    local_severity: payload.local_severity ?? "Unknown",
    highest_external_severity: payload.highest_external_severity ?? null,
    semantic_matches_inferred: payload.semantic_matches_inferred ?? false,
    unavailable_reason: payload.unavailable_reason ?? null,
    scan_cve_ids: payload.scan_cve_ids ?? [],
    severity_signals: payload.severity_signals ?? [],
    epss_entries: payload.epss_entries ?? [],
    attack_techniques: payload.attack_techniques ?? [],
    attack_patterns: payload.attack_patterns ?? [],
    weaknesses: payload.weaknesses ?? [],
    advisories: payload.advisories ?? [],
    kev_entries: payload.kev_entries ?? [],
    dependency_matches: payload.dependency_matches ?? [],
    cri_controls: payload.cri_controls ?? [],
    contextual_assessment: {
      ...EMPTY_THREAT_INTEL_CONTEXTUAL_ASSESSMENT,
      ...contextualAssessment,
      threat_classes: contextualAssessment?.threat_classes ?? [],
      why_applicable: contextualAssessment?.why_applicable ?? [],
      what_to_verify: contextualAssessment?.what_to_verify ?? [],
      decision_rationale: contextualAssessment?.decision_rationale ?? [],
    },
  };
}

export const api = {
  baseUrl: BASE,
  getCurrentUser: () => request<UserResponse>("/auth/me"),

  updateReportTemplateLibrary: (reportTemplateLibrary: ReportTemplateDefinition[]) =>
    request<UserResponse>("/auth/report-template-library", {
      method: "PUT",
      body: JSON.stringify({ report_template_library: reportTemplateLibrary }),
    }),

  // Security review workspaces
  createThreatModel: (data: ThreatModelCreate) =>
    request<ThreatModelResponse>("/threat-models", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getThreatModels: () => request<ThreatModelListItem[]>("/threat-models"),

  getThreatModel: (id: string) => request<ThreatModelResponse>(`/threat-models/${id}`),

  archiveThreatModel: (id: string) =>
    request<ThreatModelResponse>(`/threat-models/${id}/archive`, {
      method: "PATCH",
    }),

  getApplicationReview: (reviewId: string) =>
    request<ApplicationReview>(`/reviews/${reviewId}`),

  getApplicationReviewArtifact: (reviewId: string) =>
    request<ApplicationReviewArtifact>(`/reviews/${reviewId}/artifact`),

  getAgentReviewStatus: (reviewId: string) =>
    request<AgentReviewStatus>(`/agent/reviews/${reviewId}/status`),

  rebuildApplicationReviewContextIndex: (reviewId: string) =>
    request<{ review_id: string; entry_count: number }>(
      `/reviews/${reviewId}/context-index/rebuild`,
      { method: "POST" },
    ),

  searchApplicationReviewContext: (reviewId: string, q = "", limit = 20) => {
    const params = new URLSearchParams({ q, limit: String(limit) });
    return request<ApplicationReviewContextSearchResponse>(
      `/reviews/${reviewId}/context-index/search?${params.toString()}`,
    );
  },

  getApplicationReviewContextPacket: (reviewId: string, q = "", limit = 20) => {
    const params = new URLSearchParams({ q, limit: String(limit) });
    return request<ApplicationReviewContextPacket>(
      `/reviews/${reviewId}/context-packet?${params.toString()}`,
    );
  },

  getApplicationReviewAIExplanation: (reviewId: string, q = "", limit = 20) => {
    const params = new URLSearchParams({ q, limit: String(limit) });
    return request<ApplicationReviewAIExplanation>(
      `/reviews/${reviewId}/ai-explanation?${params.toString()}`,
    );
  },

  evaluateApplicationReviewDecision: (reviewId: string) =>
    request<ApplicationReviewDecision>(`/reviews/${reviewId}/decision/evaluate`, {
      method: "POST",
    }),

  getEvidenceStatus: (threatModelId: string) =>
    request<EvidenceStatusResponse>(`/threat-models/${threatModelId}/evidence/status`),

  rebuildEvidenceGraph: (threatModelId: string) =>
    request<EvidenceStatusResponse>(`/threat-models/${threatModelId}/evidence/rebuild`, {
      method: "POST",
    }),

  exportTMAC: async (
    threatModelId: string,
    format: TMACFormat = "yaml",
    options?: {
      include_operational_state?: boolean;
      include_binary_assets?: boolean;
    }
  ): Promise<Blob> => {
    const params = new URLSearchParams({
      format,
      include_operational_state: String(Boolean(options?.include_operational_state)),
      include_binary_assets: String(Boolean(options?.include_binary_assets)),
    });
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/tmac?${params.toString()}`, {
      headers: { ...getAuthHeaders() },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.blob();
  },

  getTMACScaffold: async (): Promise<Blob> => {
    const res = await fetch(`${BASE}/threat-models/tmac/scaffold`, {
      headers: { ...getAuthHeaders() },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.blob();
  },

  validateTMAC: (content: string) =>
    request<TMACValidationResponse>("/threat-models/tmac/validate", {
      method: "POST",
      body: JSON.stringify({ content }),
    }),

  importTMAC: (data: TMACImportRequest) =>
    request<TMACImportResponse>("/threat-models/tmac/import", {
      method: "POST",
      body: JSON.stringify(data),
    }),

  diffTMAC: (threatModelId: string, content: string) =>
    request<TMACDiffResponse>(`/threat-models/${threatModelId}/tmac/diff`, {
      method: "POST",
      body: JSON.stringify({ content }),
    }),

  getThreatModelScorecard: (threatModelId: string) =>
    request<ThreatModelScorecardResponse>(`/threat-models/${threatModelId}/scorecard`),

  getAssumptions: (threatModelId: string) =>
    request<ThreatModelAssumptionResponse[]>(`/threat-models/${threatModelId}/assumptions`),

  createAssumption: (threatModelId: string, data: ThreatModelAssumptionCreate) =>
    request<ThreatModelAssumptionResponse>(`/threat-models/${threatModelId}/assumptions`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateAssumption: (
    threatModelId: string,
    assumptionId: string,
    data: ThreatModelAssumptionUpdate
  ) =>
    request<ThreatModelAssumptionResponse>(
      `/threat-models/${threatModelId}/assumptions/${assumptionId}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      }
    ),

  deleteAssumption: (threatModelId: string, assumptionId: string) =>
    request<void>(`/threat-models/${threatModelId}/assumptions/${assumptionId}`, {
      method: "DELETE",
    }),

  getModelVersions: (threatModelId: string) =>
    request<ThreatModelVersionResponse[]>(`/threat-models/${threatModelId}/versions`),

  createModelVersion: (threatModelId: string, data: ThreatModelVersionCreate) =>
    request<ThreatModelVersionResponse>(`/threat-models/${threatModelId}/versions`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  diffModelVersions: (threatModelId: string, data: ThreatModelVersionDiffRequest) =>
    request<ThreatModelVersionDiffResponse>(`/threat-models/${threatModelId}/versions/diff`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getModelReviews: (threatModelId: string) =>
    request<ThreatModelReviewResponse[]>(`/threat-models/${threatModelId}/reviews`),

  createModelReview: (threatModelId: string, data: ThreatModelReviewCreate) =>
    request<ThreatModelReviewResponse>(`/threat-models/${threatModelId}/reviews`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateModelReview: (threatModelId: string, reviewId: string, data: ThreatModelReviewUpdate) =>
    request<ThreatModelReviewResponse>(`/threat-models/${threatModelId}/reviews/${reviewId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  getControlLibrary: (threatModelId: string) =>
    request<ThreatModelControlResponse[]>(`/threat-models/${threatModelId}/controls`),

  createControlLibraryEntry: (threatModelId: string, data: ThreatModelControlCreate) =>
    request<ThreatModelControlResponse>(`/threat-models/${threatModelId}/controls`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateControlLibraryEntry: (
    threatModelId: string,
    controlId: string,
    data: ThreatModelControlUpdate
  ) =>
    request<ThreatModelControlResponse>(`/threat-models/${threatModelId}/controls/${controlId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  deleteControlLibraryEntry: (threatModelId: string, controlId: string) =>
    request<void>(`/threat-models/${threatModelId}/controls/${controlId}`, {
      method: "DELETE",
    }),

  getValidationSummary: (threatModelId: string) =>
    request<ArchitectureValidationSummary>(`/threat-models/${threatModelId}/validation-summary`),

  // Environment evidence
  getEnvironmentEvidence: (threatModelId: string) =>
    request<EnvironmentEvidenceResponse>(`/threat-models/${threatModelId}/environment`),

  uploadRepositoryEvidence: async (
    threatModelId: string,
    file: File,
    reference?: string
  ): Promise<EnvironmentEvidenceResponse> => {
    const formData = new FormData();
    formData.append("file", file);
    if (reference?.trim()) {
      formData.append("reference", reference.trim());
    }
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/environment/repository`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
      body: formData,
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.json() as Promise<EnvironmentEvidenceResponse>;
  },

  importRepositoryEvidenceFromGitHub: (
    threatModelId: string,
    data: GitHubRepositoryImportRequest,
    githubToken?: string
  ) =>
    request<EnvironmentEvidenceResponse>(
      `/threat-models/${threatModelId}/environment/repository/github`,
      {
        method: "POST",
        headers: githubToken ? { "X-GitHub-Token": githubToken } : undefined,
        body: JSON.stringify(data),
      }
    ),

  refreshRepositoryEvidenceFromGitHub: (
    threatModelId: string,
    data: GitHubRepositoryRefreshRequest = {},
    githubToken?: string
  ) =>
    request<EnvironmentEvidenceResponse>(
      `/threat-models/${threatModelId}/environment/repository/github/refresh`,
      {
        method: "POST",
        headers: githubToken ? { "X-GitHub-Token": githubToken } : undefined,
        body: JSON.stringify(data),
      }
    ),

  clearRepositoryEvidence: (threatModelId: string) =>
    request<EnvironmentEvidenceResponse>(
      `/threat-models/${threatModelId}/environment/repository`,
      { method: "DELETE" }
    ),

  uploadCloudScanEvidence: async (
    threatModelId: string,
    file: File
  ): Promise<EnvironmentEvidenceResponse> => {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/environment/cloud-scan`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
      body: formData,
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.json() as Promise<EnvironmentEvidenceResponse>;
  },

  clearCloudScanEvidence: (threatModelId: string) =>
    request<EnvironmentEvidenceResponse>(
      `/threat-models/${threatModelId}/environment/cloud-scan`,
      { method: "DELETE" }
    ),

  uploadIacEvidence: async (
    threatModelId: string,
    file: File,
    reference?: string
  ): Promise<EnvironmentEvidenceResponse> => {
    const formData = new FormData();
    formData.append("file", file);
    if (reference?.trim()) {
      formData.append("reference", reference.trim());
    }
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/environment/iac`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
      body: formData,
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.json() as Promise<EnvironmentEvidenceResponse>;
  },

  clearIacEvidence: (threatModelId: string) =>
    request<EnvironmentEvidenceResponse>(`/threat-models/${threatModelId}/environment/iac`, {
      method: "DELETE",
    }),

  // Documents
  uploadDocument: async (threatModelId: string, file: File): Promise<DocumentUploadResponse> => {
    const formData = new FormData();
    formData.append("file", file);
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/documents`, {
      method: "POST",
      headers: { ...getAuthHeaders() },
      body: formData,
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.json() as Promise<DocumentUploadResponse>;
  },

  // DFD
  getDFD: (threatModelId: string, viewId?: string | null) =>
    request<DFDResponse>(withViewId(`/threat-models/${threatModelId}/dfd`, viewId)),

  getDFDComponentTemplates: (threatModelId: string) =>
    request<DFDComponentTemplateResponse[]>(`/threat-models/${threatModelId}/dfd/component-templates`),

  createDFDComponentTemplate: (threatModelId: string, data: DFDComponentTemplateDraft) =>
    request<DFDComponentTemplateResponse>(`/threat-models/${threatModelId}/dfd/component-templates`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  suggestDFDComponentTemplate: (
    threatModelId: string,
    data: DFDComponentTemplateSuggestRequest
  ) =>
    request<DFDComponentTemplateSuggestResponse>(
      `/threat-models/${threatModelId}/dfd/component-templates/suggest`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),

  deleteDFDComponentTemplate: (threatModelId: string, templateId: string) =>
    request<void>(`/threat-models/${threatModelId}/dfd/component-templates/${encodeURIComponent(templateId)}`, {
      method: "DELETE",
    }),

  getDFDPropertyOptions: (threatModelId: string) =>
    request<DFDPropertyOptionResponse[]>(`/threat-models/${threatModelId}/dfd/property-options`),

  createDFDPropertyOption: (threatModelId: string, data: DFDPropertyOptionDraft) =>
    request<DFDPropertyOptionResponse>(`/threat-models/${threatModelId}/dfd/property-options`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  suggestDFDPropertyOption: (
    threatModelId: string,
    data: DFDPropertyOptionSuggestRequest
  ) =>
    request<DFDPropertyOptionSuggestResponse>(
      `/threat-models/${threatModelId}/dfd/property-options/suggest`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),

  deleteDFDPropertyOption: (threatModelId: string, optionId: string) =>
    request<void>(`/threat-models/${threatModelId}/dfd/property-options/${encodeURIComponent(optionId)}`, {
      method: "DELETE",
    }),

  saveDFD: (threatModelId: string, data: DFDBulkSave, viewId?: string | null) =>
    request<DFDResponse>(withViewId(`/threat-models/${threatModelId}/dfd`, viewId), {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  createNode: (threatModelId: string, data: DFDNodeCreate, viewId?: string | null) =>
    request<DFDNodeResponse>(withViewId(`/threat-models/${threatModelId}/dfd/nodes`, viewId), {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateNode: (threatModelId: string, nodeId: string, data: DFDNodeUpdate, viewId?: string | null) =>
    request<DFDNodeResponse>(withViewId(`/threat-models/${threatModelId}/dfd/nodes/${nodeId}`, viewId), {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  deleteNode: (threatModelId: string, nodeId: string, viewId?: string | null) =>
    request<void>(withViewId(`/threat-models/${threatModelId}/dfd/nodes/${nodeId}`, viewId), {
      method: "DELETE",
    }),

  createEdge: (threatModelId: string, data: DFDEdgeCreate, viewId?: string | null) =>
    request<DFDEdgeResponse>(withViewId(`/threat-models/${threatModelId}/dfd/edges`, viewId), {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateEdge: (threatModelId: string, edgeId: string, data: DFDEdgeUpdate, viewId?: string | null) =>
    request<DFDEdgeResponse>(withViewId(`/threat-models/${threatModelId}/dfd/edges/${edgeId}`, viewId), {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  quickAddNode: (threatModelId: string, data: DFDQuickAddRequest, viewId?: string | null) =>
    request<DFDQuickAddResponse>(withViewId(`/threat-models/${threatModelId}/dfd/quick-add`, viewId), {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getDFDViews: (threatModelId: string) =>
    request<DFDViewResponse[]>(`/threat-models/${threatModelId}/dfd/views`),

  regenerateDFDViews: (threatModelId: string) =>
    request<DFDViewResponse[]>(`/threat-models/${threatModelId}/dfd/views/regenerate`, {
      method: "POST",
    }),

  updateDFDView: (threatModelId: string, viewId: string, data: DFDViewUpdate) =>
    request<DFDViewResponse>(`/threat-models/${threatModelId}/dfd/views/${viewId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  createDFDDecompositionView: (threatModelId: string, data: DFDDecompositionViewCreate) =>
    request<DFDViewResponse>(`/threat-models/${threatModelId}/dfd/views/decompositions`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  createDFDWorkspaceView: (threatModelId: string, data: DFDWorkspaceViewCreate) =>
    request<DFDViewResponse>(`/threat-models/${threatModelId}/dfd/views/workspaces`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getDFDQualityGates: (threatModelId: string) =>
    request<DFDQualityGateSummary>(`/threat-models/${threatModelId}/dfd/quality-gates`),

  importIacIntoDfd: (threatModelId: string, data: DFDIacImportRequest = {}) =>
    request<DFDIacImportResponse>(`/threat-models/${threatModelId}/dfd/import-iac`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  previewRepositoryDfdSeeds: (threatModelId: string) =>
    request<DFDRepositorySeedPreviewResponse>(
      `/threat-models/${threatModelId}/dfd/repository-suggestions`
    ),

  applyRepositoryDfdSeeds: (
    threatModelId: string,
    data: DFDRepositorySeedApplyRequest
  ) =>
    request<DFDRepositorySeedApplyResponse>(
      `/threat-models/${threatModelId}/dfd/repository-suggestions/apply`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),
  deleteEdge: (threatModelId: string, edgeId: string, viewId?: string | null) =>
    request<void>(withViewId(`/threat-models/${threatModelId}/dfd/edges/${edgeId}`, viewId), {
      method: "DELETE",
    }),

  createBoundary: (threatModelId: string, data: TrustBoundaryCreate, viewId?: string | null) =>
    request<TrustBoundaryResponse>(withViewId(`/threat-models/${threatModelId}/dfd/boundaries`, viewId), {
      method: "POST",
      body: JSON.stringify(data),
    }),

  deleteBoundary: (threatModelId: string, boundaryId: string, viewId?: string | null) =>
    request<void>(withViewId(`/threat-models/${threatModelId}/dfd/boundaries/${boundaryId}`, viewId), {
      method: "DELETE",
    }),

  // Threats
  getThreat: (threatModelId: string, threatId: string) =>
    request<ThreatResponse>(`/threat-models/${threatModelId}/threats/${threatId}`),

  startThreatValidationRun: (
    threatModelId: string,
    threatId: string,
    data: ThreatValidationRunCreate = {}
  ) =>
    request<ThreatValidationRun>(
      `/threat-models/${threatModelId}/threats/${threatId}/validation-runs`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  getAgentToolCatalog: () => request<AgentToolCapability[]>("/agent-tools/catalog"),

  proposeThreatScanPlan: (
    threatModelId: string,
    threatId: string,
    data: ThreatScanPlanCreate = {}
  ) =>
    request<ThreatValidationRun>(
      `/threat-models/${threatModelId}/threats/${threatId}/scan-plans`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  getThreatScanPlan: (scanPlanId: string) =>
    request<ThreatValidationRun>(`/scan-plans/${scanPlanId}`),

  approveThreatScanPlan: (scanPlanId: string, data: ThreatScanPlanApproveRequest) =>
    request<ThreatValidationRun>(`/scan-plans/${scanPlanId}/approve`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  rejectThreatScanPlan: (scanPlanId: string, data: ThreatScanPlanRejectRequest) =>
    request<ThreatValidationRun>(`/scan-plans/${scanPlanId}/reject`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  listThreatValidationRuns: (threatModelId: string, threatId: string) =>
    request<ThreatValidationRun[]>(
      `/threat-models/${threatModelId}/threats/${threatId}/validation-runs`
    ),

  getThreatValidationRun: (runId: string) =>
    request<ThreatValidationRun>(`/threat-validations/${runId}`),

  rerunThreatValidationRun: (runId: string) =>
    request<ThreatValidationRun>(`/threat-validations/${runId}/rerun`, {
      method: "POST",
      body: JSON.stringify({}),
    }),

  startThreatRemediationRun: (
    validationRunId: string,
    agentType: FixAgentType
  ) =>
    request<ThreatRemediationRun>(
      `/threat-validations/${validationRunId}/remediation-runs`,
      {
        method: "POST",
        body: JSON.stringify({ agent_type: agentType } satisfies ThreatRemediationRunCreate),
      }
    ),

  confirmThreatRemediationHandoff: (
    remediationRunId: string,
    data: ThreatRemediationHandoffConfirmRequest
  ) =>
    request<ThreatRemediationRun>(
      `/threat-remediations/${remediationRunId}/confirm-handoff`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  attachThreatRemediationEvidence: (
    remediationRunId: string,
    data: ThreatRemediationEvidenceRequest
  ) =>
    request<ThreatRemediationRun>(
      `/threat-remediations/${remediationRunId}/evidence`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  getThreatIntel: (threatModelId: string, threatId: string) =>
    request<Partial<ThreatIntelResponse>>(
      `/threat-models/${threatModelId}/threats/${threatId}/intel`
    ).then(normalizeThreatIntelResponse),

  getThreatSecurityReview: (threatModelId: string, threatId: string) =>
    request<SecurityReviewDecision>(
      `/threat-models/${threatModelId}/threats/${threatId}/review`
    ),

  getThreatModelSecurityReview: (threatModelId: string) =>
    request<SecurityReviewApplicationSummary>(
      `/threat-models/${threatModelId}/review`
    ),

  getThreatModelReviewFindings: (threatModelId: string) =>
    request<SecurityReviewFindingListResponse>(
      `/threat-models/${threatModelId}/review-findings`
    ),

  getThreatModelAgentReleaseDecision: (threatModelId: string) =>
    request<AgentSecurityReviewResponse>(
      `/threat-models/${threatModelId}/agent/release-decision`
    ),

  getThreatModelAgentRemediationPlan: (threatModelId: string) =>
    request<AgentRemediationPlanResponse>(
      `/threat-models/${threatModelId}/agent/remediation-plan`
    ),

  applyThreatModelAgentRemediationPlan: (threatModelId: string) =>
    request<AgentRemediationPlanApplyResponse>(
      `/threat-models/${threatModelId}/agent/remediation-plan/apply`,
      { method: "POST", body: JSON.stringify({}) }
    ),

  createThreatModelAgentRemediationTicket: (
    threatModelId: string,
    data: AgentRemediationTicketCreateRequest
  ) =>
    request<AgentRemediationTicketCreateResponse>(
      `/threat-models/${threatModelId}/agent/remediation-plan/tickets`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  createThreatModelAgentRemediationConnectorTicket: (
    threatModelId: string,
    data: AgentRemediationConnectorTicketCreateRequest
  ) =>
    request<AgentRemediationConnectorTicketCreateResponse>(
      `/threat-models/${threatModelId}/agent/remediation-plan/tickets/connectors`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  ingestThreatModelAgentRemediationEvidence: (
    threatModelId: string,
    data: AgentRemediationEvidenceWebhookRequest
  ) =>
    request<AgentRemediationEvidenceWebhookResponse>(
      `/threat-models/${threatModelId}/agent/remediation-plan/webhooks/evidence`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  testThreatModelAgentRemediationProviderWebhook: (
    threatModelId: string,
    provider: AgentRemediationProviderWebhookTestRequest["provider"],
    data: AgentRemediationProviderWebhookTestRequest
  ) =>
    request<AgentRemediationProviderWebhookTestResponse>(
      `/threat-models/${threatModelId}/agent/remediation-plan/webhooks/providers/${provider}/test`,
      { method: "POST", body: JSON.stringify(data) }
    ),

  getThreatModelCustomerPacket: (threatModelId: string) =>
    request<CustomerSecurityPacketResponse>(
      `/threat-models/${threatModelId}/customer-packet`
    ),

  exportThreatModelCustomerPacketCSV: async (
    threatModelId: string,
    options: { includeSourceLabels?: boolean } = {}
  ): Promise<Blob> => {
    const params = new URLSearchParams();
    if (options.includeSourceLabels) {
      params.set("include_source_labels", "true");
      params.set("approved_sensitive_labels", "true");
    }
    const qs = params.toString();
    const res = await fetch(
      `${BASE}/threat-models/${threatModelId}/customer-packet/export.csv${qs ? `?${qs}` : ""}`,
      { headers: { ...getAuthHeaders() } }
    );
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.blob();
  },

  exportThreatModelCustomerPacketPDF: async (
    threatModelId: string,
    options: { includeSourceLabels?: boolean } = {}
  ): Promise<Blob> => {
    const params = new URLSearchParams();
    if (options.includeSourceLabels) {
      params.set("include_source_labels", "true");
      params.set("approved_sensitive_labels", "true");
    }
    const qs = params.toString();
    const res = await fetch(
      `${BASE}/threat-models/${threatModelId}/customer-packet/export.pdf${qs ? `?${qs}` : ""}`,
      { headers: { ...getAuthHeaders() } }
    );
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.blob();
  },

  updateThreatModelReviewFinding: (
    threatModelId: string,
    sourceObjectType: SecurityReviewFinding["source_object_type"],
    sourceObjectId: string,
    data: SecurityReviewStateUpdate
  ) =>
    request<SecurityReviewFinding>(
      `/threat-models/${threatModelId}/review-findings/${encodeURIComponent(sourceObjectType)}/${encodeURIComponent(sourceObjectId)}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      }
    ),

  acceptThreatModelReviewFindingRisk: (
    threatModelId: string,
    sourceObjectType: SecurityReviewFinding["source_object_type"],
    sourceObjectId: string,
    data: SecurityReviewRiskAcceptanceRequest
  ) =>
    request<SecurityReviewFinding>(
      `/threat-models/${threatModelId}/review-findings/${encodeURIComponent(sourceObjectType)}/${encodeURIComponent(sourceObjectId)}/risk-acceptance`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),

  createThreatModelReviewArtifact: (
    threatModelId: string,
    sourceObjectType: SecurityReviewFinding["source_object_type"],
    sourceObjectId: string,
    data: { kind: ReviewArtifactKind }
  ) =>
    request<SecurityReviewFinding>(
      `/threat-models/${threatModelId}/review-findings/${encodeURIComponent(sourceObjectType)}/${encodeURIComponent(sourceObjectId)}/artifacts`,
      {
        method: "POST",
        body: JSON.stringify(data),
      }
    ),

  getThreats: (threatModelId: string, strideFilter?: string) => {
    const params = strideFilter ? `?stride_category=${encodeURIComponent(strideFilter)}` : "";
    return request<ThreatResponse[]>(`/threat-models/${threatModelId}/threats${params}`);
  },

  triageThreat: (threatModelId: string, threatId: string, data: ThreatTriageRequest) =>
    request<ThreatResponse>(`/threat-models/${threatModelId}/threats/${threatId}/triage`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  bulkTriageThreats: (threatModelId: string, data: BulkTriageRequest) =>
    request<ThreatResponse[]>(`/threat-models/${threatModelId}/threats/bulk-triage`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getThreatHistory: (threatModelId: string, threatId: string) =>
    request<ThreatAuditEntry[]>(`/threat-models/${threatModelId}/threats/${threatId}/history`),

  getAttackPaths: (threatModelId: string) =>
    request<AttackPathResponse[]>(`/threat-models/${threatModelId}/attack-paths`),

  getLatestScanCorrelation: (threatModelId: string) =>
    request<ScanCorrelationSummaryResponse>(
      `/threat-models/${threatModelId}/scans/latest/threat-correlation`
    ),

  getLatestThreatScanCorrelation: (threatModelId: string, threatId: string) =>
    request<ThreatScanCorrelationResponse>(
      `/threat-models/${threatModelId}/scans/latest/threat-correlation/${threatId}`
    ),

  getScan: (threatModelId: string, scanId: string) =>
    request<ScanJobDetail>(`/threat-models/${threatModelId}/scans/${scanId}`),

  getScanRunbook: (threatModelId: string, scanId: string) =>
    request<ValidationRunbookResponse>(`/threat-models/${threatModelId}/scans/${scanId}/runbook`),

  getLatestScanRunbook: (threatModelId: string) =>
    request<ValidationRunbookResponse | null>(`/threat-models/${threatModelId}/scans/latest/runbook`),

  ingestScanEvidence: (threatModelId: string, data: EvidenceIngestRequest) =>
    request<ScanJobDetail>(`/threat-models/${threatModelId}/scans/ingest-evidence`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  uploadValidationArtifactBundle: (
    threatModelId: string,
    data: {
      file: File;
      tool_name?: string;
      target_type?: string;
      target?: string;
      target_node_id?: string | null;
    },
  ) => {
    const form = new FormData();
    form.append("file", data.file);
    if (data.tool_name) form.append("tool_name", data.tool_name);
    if (data.target_type) form.append("target_type", data.target_type);
    if (data.target) form.append("target", data.target);
    if (data.target_node_id) form.append("target_node_id", data.target_node_id);
    return requestForm<ValidationArtifactBundleImportResponse>(
      `/threat-models/${threatModelId}/scans/artifact-bundles`,
      form,
    );
  },

  getValidationArtifactBundles: (threatModelId: string) =>
    request<ValidationArtifactBundle[]>(`/threat-models/${threatModelId}/scans/artifact-bundles`),

  runValidationTool: (threatModelId: string, data: ValidationRunRequest) =>
    request<ScanJob>(`/threat-models/${threatModelId}/scans/validation-run`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  getValidationTools: () =>
    request<ValidationToolInventoryResponse>("/validation-tools"),

  getValidationLab: (threatModelId: string) =>
    request<ValidationLabSummary>(`/threat-models/${threatModelId}/validation-lab`),

  getValidationTargetBundles: (threatModelId: string) =>
    request<ValidationTargetBundle[]>(`/threat-models/${threatModelId}/validation-lab/target-bundles`),

  uploadValidationTargetBundle: (
    threatModelId: string,
    data: {
      file: File;
      name?: string;
      authorization_acknowledged: boolean;
    },
  ) => {
    const form = new FormData();
    form.append("file", data.file);
    if (data.name) form.append("name", data.name);
    form.append("authorization_acknowledged", String(data.authorization_acknowledged));
    return requestForm<ValidationTargetBundle>(
      `/threat-models/${threatModelId}/validation-lab/target-bundles`,
      form,
    );
  },

  getOrchestrationJobs: (threatModelId: string) =>
    request<OrchestrationJob[]>(`/threat-models/${threatModelId}/orchestration/jobs`),

  runOrchestrationJob: (threatModelId: string, jobId: string, maxTasks = 10) =>
    request<OrchestrationJob>(
      `/threat-models/${threatModelId}/orchestration/jobs/${jobId}/run?max_tasks=${maxTasks}`,
      { method: "POST" },
    ),

  updateValidationCaseState: (
    threatModelId: string,
    caseKey: string,
    data: ValidationCaseStateUpdateRequest,
  ) =>
    request<ProductSecurityValidationCase>(
      `/threat-models/${threatModelId}/validation-lab/cases/${encodeURIComponent(caseKey)}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      },
    ),

  bindValidationEvidence: (
    threatModelId: string,
    findingId: string,
    data: ValidationEvidenceBindingRequest,
  ) =>
    request<ValidationEvidenceBindingResponse>(
      `/threat-models/${threatModelId}/validation-lab/evidence/${encodeURIComponent(findingId)}/bind`,
      {
        method: "POST",
        body: JSON.stringify(data),
      },
    ),

  runValidationTrySandbox: (threatModelId: string) =>
    request<ScanJob>(`/threat-models/${threatModelId}/validation-lab/try-sandbox`, {
      method: "POST",
    }),

  createValidationSchedule: (threatModelId: string, data: ValidationScheduleCreateRequest) =>
    request<ValidationSchedule>(`/threat-models/${threatModelId}/validation-lab/schedules`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateValidationSchedule: (
    threatModelId: string,
    scheduleId: string,
    data: ValidationScheduleUpdateRequest,
  ) =>
    request<ValidationSchedule>(`/threat-models/${threatModelId}/validation-lab/schedules/${scheduleId}`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  runValidationSchedule: (threatModelId: string, scheduleId: string, authorization_acknowledged: boolean) =>
    request<ScanJob>(`/threat-models/${threatModelId}/validation-lab/schedules/${scheduleId}/run`, {
      method: "POST",
      body: JSON.stringify({ authorization_acknowledged }),
    }),

  deleteValidationSchedule: (threatModelId: string, scheduleId: string) =>
    request<void>(`/threat-models/${threatModelId}/validation-lab/schedules/${scheduleId}`, {
      method: "DELETE",
    }),

  // Threat Summary
  getThreatsSummary: (threatModelId: string) =>
    request<ThreatSummary>(`/threat-models/${threatModelId}/threats/summary`),

  getResidualRiskSummary: (threatModelId: string) =>
    request<ResidualRiskSummary>(`/threat-models/${threatModelId}/threats/residual-summary`),

  // Analyze
  analyze: (threatModelId: string, rulesOnly = false) =>
    request<AnalyzeResponse>(
      `/threat-models/${threatModelId}/analyze${rulesOnly ? "?rules_only=true" : ""}`,
      { method: "POST" }
    ),

  // LLM Providers
  getLLMProviders: () =>
    request<{
      available: { name: string; display_name: string; default_model: string }[];
      active: { provider: string; model: string };
    }>("/llm/providers"),

  getLLMProviderModels: (provider: string) =>
    request<{ provider: string; models: string[]; source: "default" | "live" }>(
      `/llm/providers/${encodeURIComponent(provider)}/models`
    ),

  getLLMProviderHealth: () => request<LLMProviderHealth>("/llm/health"),

  switchLLMProvider: (provider: string, model?: string) =>
    request<{ provider: string; model: string }>("/llm/provider", {
      method: "POST",
      body: JSON.stringify({ provider, model: model || undefined }),
    }),

  // CSV Export
  exportThreatsCSV: async (threatModelId: string): Promise<Blob> => {
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/threats/export.csv`, {
      headers: { ...getAuthHeaders() },
    });
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.blob();
  },

  // Threat Diff
  getThreatDiff: (threatModelId: string, signal?: AbortSignal) =>
    request<ThreatDiffResponse>(`/threat-models/${threatModelId}/threat-diff`, { method: "POST", signal }),

  // Assistant
  assistantRespond: (threatModelId: string, data: AssistantRequest) =>
    request<AssistantResponse>(`/threat-models/${threatModelId}/assistant/respond`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // Threat Catalog
  getThreatCatalog: (q?: string, stride?: string) => {
    const params = new URLSearchParams();
    if (q) params.set("q", q);
    if (stride) params.set("stride", stride);
    const qs = params.toString();
    return request<ThreatCatalogEntry[]>(`/threat-catalog${qs ? `?${qs}` : ""}`);
  },

  createManualThreat: (threatModelId: string, data: ManualThreatCreate) =>
    request<ThreatResponse>(`/threat-models/${threatModelId}/threats/manual`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  // BYOK Keys
  getBYOKKeys: () => request<BYOKKeyResponse[]>("/llm/keys"),

  upsertBYOKKey: (provider: string, data: BYOKKeyRequest) =>
    request<BYOKKeyResponse>(`/llm/keys/${encodeURIComponent(provider)}`, {
      method: "PUT",
      body: JSON.stringify(data),
    }),

  deleteBYOKKey: (provider: string) =>
    request<void>(`/llm/keys/${encodeURIComponent(provider)}`, {
      method: "DELETE",
    }),

  testBYOKKey: (provider: string) =>
    request<BYOKTestResult>(`/llm/keys/${encodeURIComponent(provider)}/test`, {
      method: "POST",
    }),

  // Dashboard
  getPortfolioSummary: () => request<PortfolioSummary>("/dashboard/summary"),
  getPortfolioTrends: () => request<PortfolioTrendResponse>("/dashboard/trends"),

  // Collaboration
  getCollaborators: (threatModelId: string) =>
    request<ThreatModelCollaboratorResponse[]>(`/threat-models/${threatModelId}/collaborators`),

  createCollaborator: (threatModelId: string, data: ThreatModelCollaboratorCreate) =>
    request<ThreatModelCollaboratorResponse>(`/threat-models/${threatModelId}/collaborators`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateCollaborator: (
    threatModelId: string,
    collaboratorId: string,
    data: ThreatModelCollaboratorUpdate,
  ) =>
    request<ThreatModelCollaboratorResponse>(
      `/threat-models/${threatModelId}/collaborators/${collaboratorId}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      }
    ),

  getAssignments: (threatModelId: string) =>
    request<ThreatModelAssignmentResponse[]>(`/threat-models/${threatModelId}/assignments`),

  createAssignment: (threatModelId: string, data: ThreatModelAssignmentCreate) =>
    request<ThreatModelAssignmentResponse>(`/threat-models/${threatModelId}/assignments`, {
      method: "POST",
      body: JSON.stringify(data),
    }),

  updateAssignment: (threatModelId: string, assignmentId: string, data: ThreatModelAssignmentUpdate) =>
    request<ThreatModelAssignmentResponse>(
      `/threat-models/${threatModelId}/assignments/${assignmentId}`,
      {
        method: "PATCH",
        body: JSON.stringify(data),
      }
    ),

  getNotifications: (threatModelId: string) =>
    request<ThreatModelNotificationResponse[]>(`/threat-models/${threatModelId}/notifications`),

  updateNotification: (
    threatModelId: string,
    notificationId: string,
    status: "unread" | "read",
  ) =>
    request<ThreatModelNotificationResponse>(
      `/threat-models/${threatModelId}/notifications/${notificationId}`,
      {
        method: "PATCH",
        body: JSON.stringify({ status }),
      }
    ),

  // Report config
  updateReportConfig: (
    threatModelId: string,
    config: {
      report_template?: string;
      report_templates?: ReportTemplateDefinition[];
      report_watermark_text?: string;
      report_logo_base64?: string;
      arch_diagrams?: { name: string; image_base64: string }[];
    },
  ) =>
    request<ThreatModelResponse>(`/threat-models/${threatModelId}/report-config`, {
      method: "PUT",
      body: JSON.stringify(config),
    }),

  // Qualification workflow
  qualifyThreat: (threatModelId: string, threatId: string, data: ThreatQualifyRequest) =>
    request<ThreatResponse>(`/threat-models/${threatModelId}/threats/${threatId}/qualify`, {
      method: "PATCH",
      body: JSON.stringify(data),
    }),

  listClusters: (threatModelId: string) =>
    request<ThreatClusterResponse[]>(`/threat-models/${threatModelId}/clusters`),

  recomputeClusters: (threatModelId: string) =>
    request<ThreatClusterResponse[]>(`/threat-models/${threatModelId}/clusters/compute`, {
      method: "POST",
    }),

  getQualificationProgress: (threatModelId: string) =>
    request<QualificationProgressResponse>(`/threat-models/${threatModelId}/qualification/progress`),

  getQualificationNext: (threatModelId: string) =>
    request<ThreatResponse | null>(`/threat-models/${threatModelId}/qualification/next`),

  // Report
  generateReport: async (
    threatModelId: string,
    dfdImageBase64 = "",
    sections?: string[],
    signal?: AbortSignal,
  ): Promise<Blob> => {
    const res = await fetch(`${BASE}/threat-models/${threatModelId}/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...getAuthHeaders() },
      signal,
      body: JSON.stringify({
        threat_model_id: threatModelId,
        dfd_image_base64: dfdImageBase64,
        ...(sections ? { sections } : {}),
      }),
    });
    if (res.status === 401) {
      localStorage.removeItem("tg_token");
      window.location.href = "/";
      throw new Error("Session expired");
    }
    if (!res.ok) {
      const body = await res.text();
      throw new Error(formatApiError(res.status, body));
    }
    return res.blob();
  },
};
