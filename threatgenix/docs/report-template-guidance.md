# Threat Model Document Guidance

## Why this exists

Public examples of internal bank threat model documents are scarce for obvious reasons. The built-in `financial_services` report template in ThreatGenix is therefore based on regulator and industry deliverables that banks and other regulated financial institutions are expected to produce or support during cyber-risk review.

## What makes a quality threat model document

A useful threat model document should make it easy for a reviewer to answer five questions quickly:

1. What system and business function are in scope?
2. What architecture, data flows, trust boundaries, and dependencies matter?
3. What threat scenarios were identified and how severe are they?
4. What controls exist, what gaps remain, and who owns treatment?
5. What residual risk, assumptions, and validation evidence should governance rely on?

That leads to a practical document structure:

- Executive summary
- Scope and review context
- System context and critical dependencies
- DFD and supporting architecture views
- Threat scenarios and findings
- Control and compliance mapping
- Assumptions and external dependencies
- Validation and testing evidence
- Shared responsibility or third-party coverage
- Methodology and caveats

## Financial-services format basis

The financial-services template uses the patterns below:

- **FFIEC Information Security Booklet**
  - Emphasizes risk assessments, layered controls, governance, and evidence suitable for management oversight.
  - Source: [FFIEC Information Security Booklet](https://www.ffiec.gov/press/pdf/ffiec_it_handbook_information_security_booklet.pdf)

- **OSFI cyber-resilience expectations**
  - Pushes federally regulated financial institutions toward stronger resilience testing and scenario-driven evidence, including intelligence-led exercises.
  - Sources:
    - [OSFI cyber resilience self-assessment tool](https://www.osfi-bsif.gc.ca/en/guidance/guidance-library/technology-cyber-risk-management/technology-cyber-risk-management-self-assessment-tool)
    - [OSFI i-CRT announcement](https://www.osfi-bsif.gc.ca/en/news/osfi-releases-new-framework-strengthen-financial-institutions-resilience-cyber-attacks)

- **ECB TIBER-EU templates**
  - Use formal scoping, critical functions, systems in scope, dependencies, and scenario-oriented testing packages that map well to regulated threat-model documentation.
  - Sources:
    - [TIBER-EU scope specification template](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_scoping_specification_template_July_2020~85ea7a4e33.en.pdf)
    - [TIBER-EU threat intelligence report template](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_threat_intelligence_report_template_July_2020~0ef2842d64.en.pdf)

- **NIST threat-modeling guidance**
  - Reinforces structured system understanding, threat sources, vulnerabilities, and traceable analysis.
  - Source: [NIST SP 800-154](https://csrc.nist.gov/pubs/sp/800/154/ipd)

- **OWASP Threat Model Library**
  - Provides a portable schema with scope, levels, threats, controls, and metadata, which supports template-driven interchange instead of one-off documents.
  - Source: [OWASP Threat Model Library](https://owasp.org/www-project-threat-model-library/)

- **Microsoft / Azure architecture diagram guidance**
  - Useful reminder that diagrams should be layered, audience-aware, and annotated enough for engineering and governance review.
  - Source: [Azure Well-Architected - design diagrams](https://learn.microsoft.com/en-us/azure/well-architected/architect-role/design-diagrams)

## Product implications

ThreatGenix now supports:

- Built-in report formats including a `financial_services` format
- Custom structured report templates stored on the threat model
- Editing template order, titles, section intros, and custom narrative blocks
- Selecting a template during export
- TMAC portability for report-template definitions

## Non-goals

ThreatGenix does **not** currently support arbitrary user-supplied HTML or Jinja report templates. That was avoided intentionally so report export remains safe, constrained, and supportable.
