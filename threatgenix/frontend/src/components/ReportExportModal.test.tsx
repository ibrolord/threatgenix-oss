import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ReportExportModal } from "./ReportExportModal";

describe("ReportExportModal", () => {
  it("surfaces the formal document wording and exports the enabled sections", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    const onExport = vi.fn();

    render(
      <ReportExportModal
        onClose={onClose}
        onExport={onExport}
        exporting={false}
      />
    );

    expect(screen.getByRole("heading", { name: "Generate Threat Model Document" })).toBeInTheDocument();
    expect(
      screen.getByText(/Use a built-in format, tailor a model-specific template/i)
    ).toBeInTheDocument();
    expect(screen.getByText("Export Focus")).toBeInTheDocument();
    expect(screen.getByText("Engineer and Compliance Sections")).toBeInTheDocument();
    expect(screen.getByText(/Default export favors engineer action, compliance evidence/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Generate Document PDF" }));

    expect(onExport).toHaveBeenCalledWith(
      [
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
      ],
      [],
      "default",
      []
    );
  });

  it("copies a shared library template into the model export set", async () => {
    const user = userEvent.setup();
    const onExport = vi.fn();

    render(
      <ReportExportModal
        onClose={vi.fn()}
        onExport={onExport}
        exporting={false}
        sharedReportTemplates={[
          {
            id: "org-banking-pack",
            name: "Org Banking Pack",
            description: "Reusable organization template.",
            audience: "financial_services",
            cover_title: "Org Banking Pack",
            cover_subtitle: "Shared template",
            built_in: false,
            sections: [
              {
                id: "scope",
                kind: "built_in",
                source_section_id: "scope",
                title: "Scope",
                intro_text: null,
                body: null,
              },
            ],
          },
        ]}
      />
    );

    await user.click(screen.getByRole("button", { name: "Copy to This Model" }));
    await user.click(screen.getByRole("button", { name: "Generate Document PDF" }));

    expect(onExport).toHaveBeenCalledWith(
      ["scope"],
      [],
      "org-banking-pack",
      [
        expect.objectContaining({
          id: "org-banking-pack",
          name: "Org Banking Pack",
        }),
      ]
    );
  });

  it("saves built-in formats into the shared library with a non-reserved id", async () => {
    const user = userEvent.setup();
    const onUpdateSharedReportTemplates = vi.fn().mockResolvedValue(undefined);

    render(
      <ReportExportModal
        onClose={vi.fn()}
        onExport={vi.fn()}
        exporting={false}
        onUpdateSharedReportTemplates={onUpdateSharedReportTemplates}
      />
    );

    await user.click(screen.getByRole("button", { name: "Save to Shared Library" }));

    await waitFor(() => {
      expect(onUpdateSharedReportTemplates).toHaveBeenCalledWith([
        expect.objectContaining({
          id: "default-library",
          name: "Default",
        }),
      ]);
    });
  });

  it("shows bounded PDF export progress and failures", () => {
    const { rerender } = render(
      <ReportExportModal
        onClose={vi.fn()}
        onExport={vi.fn()}
        exporting={true}
        exportStage="generating_pdf"
      />
    );

    expect(screen.getByRole("status")).toHaveTextContent("Generating the PDF. This is bounded to 90 seconds.");

    rerender(
      <ReportExportModal
        onClose={vi.fn()}
        onExport={vi.fn()}
        exporting={false}
        exportStage="failed"
        exportError="PDF generation exceeded the 90 second safety limit."
      />
    );

    expect(screen.getByRole("alert")).toHaveTextContent(
      "PDF export failed: PDF generation exceeded the 90 second safety limit.",
    );
  });
});
