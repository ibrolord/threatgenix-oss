import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DocumentUpload } from "./DocumentUpload";

const { uploadDocument } = vi.hoisted(() => ({
  uploadDocument: vi.fn(),
}));

vi.mock("../api/client", () => ({
  api: {
    uploadDocument,
  },
}));

describe("DocumentUpload", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("guides users toward architecture evidence and shows extraction results", async () => {
    const user = userEvent.setup();
    const onUploadComplete = vi.fn();

    uploadDocument.mockResolvedValue({
      document_id: "doc-1",
      filename: "system-design.pdf",
      page_count: 8,
      parse_result: {
        components: [],
        flows: [],
        boundaries: [],
        raw_text_excerpt: "Architecture overview",
      },
      extraction_status: "partial",
      warnings: ["No trust boundaries were modeled."],
      evidence: {
        component_count: 7,
        flow_count: 5,
        boundary_count: 1,
        diagram_pages: [2, 5],
        diagram_artifacts: ["page 2", "page 5"],
        extraction_sources: ["heuristic", "diagram", "llm"],
        low_confidence_areas: ["Some extracted data flows were inferred with low confidence."],
        raw_text_excerpt: "Architecture overview",
        detected_doc_type: "architecture_design",
      },
    });

    render(
      <DocumentUpload threatModelId="tm-1" onUploadComplete={onUploadComplete} />
    );

    expect(screen.getByText("Upload Threat-Modeling Documents")).toBeInTheDocument();
    expect(screen.getByText(/System design docs and technical specs/i)).toBeInTheDocument();
    expect(screen.getByText(/architecture, deployment, or sequence diagrams in pdf, docx, or image form/i)).toBeInTheDocument();

    const input = screen.getByLabelText("Select threat modeling document");
    await user.upload(input, new File(["pdf"], "system-design.pdf", { type: "application/pdf" }));
    await user.click(screen.getByRole("button", { name: "Upload and Extract" }));

    await waitFor(() => {
      expect(uploadDocument).toHaveBeenCalledWith(
        "tm-1",
        expect.objectContaining({ name: "system-design.pdf" })
      );
    });

    expect(await screen.findByText("Document analyzed")).toBeInTheDocument();
    expect(screen.getByText("Components")).toBeInTheDocument();
    expect(screen.getByText("Flows")).toBeInTheDocument();
    expect(screen.getByText("Trust Boundaries")).toBeInTheDocument();
    expect(screen.getByText(/Detected doc type: Architecture Design/)).toBeInTheDocument();
    expect(screen.getByText(/Diagram pages: 2, 5/)).toBeInTheDocument();
    expect(screen.getByText(/Diagram sources: page 2, page 5/)).toBeInTheDocument();
    expect(screen.getByText(/Sources: Heuristic, Diagram, LLM/)).toBeInTheDocument();
    expect(screen.getByText(/No trust boundaries were modeled/)).toBeInTheDocument();
    expect(onUploadComplete).toHaveBeenCalledTimes(1);
  });
});
