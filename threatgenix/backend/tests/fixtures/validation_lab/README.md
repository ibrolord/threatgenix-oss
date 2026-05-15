# Validation Lab Fixture

Small deterministic fixture for validation-tool parser and optional live-tool smoke tests.

Scenario: a bank payment API repository with a JWT verification bug, a vulnerable dependency, a root-running container image, a public-storage IaC mistake, and a safe HTTP-control finding. The checked-in tool outputs are the CI-stable source of truth; running local tools against the sample files is optional.

The fixture intentionally supports two validation modes:

- unbound repository evidence, where findings are retained as deterministic evidence but should not confirm semantic threats without a DFD node binding;
- node-bound evidence, where the same target is tied to a modeled component and can validate matching STRIDE threats.
