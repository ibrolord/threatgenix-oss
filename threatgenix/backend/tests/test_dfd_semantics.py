from app.services.dfd_semantics import (
    infer_handles_sensitive_data,
    infer_internet_facing_exposure,
    infer_select_presence,
    infer_trusted_boundary,
    is_deprecated_tls_value,
    is_no_tls_value,
    is_sensitive_classification,
    is_tls_1_0_value,
    is_tls_1_1_value,
)


def test_infer_select_presence_treats_custom_value_as_enabled():
    assert infer_select_presence("fido2") is True
    assert infer_select_presence("none") is False
    assert infer_select_presence("") is None


def test_infer_internet_facing_exposure_handles_custom_labels():
    assert infer_internet_facing_exposure("public edge partner") is True
    assert infer_internet_facing_exposure("private service mesh") is False
    assert infer_internet_facing_exposure("partner vpn") is None


def test_infer_trusted_boundary_handles_custom_labels():
    assert infer_trusted_boundary("first-party privileged broker") is True
    assert infer_trusted_boundary("partner enclave") is False


def test_sensitive_classification_helpers_accept_custom_values():
    assert is_sensitive_classification("Highly Restricted") is True
    assert infer_handles_sensitive_data({"data_classification": "PCI Restricted"}) is True
    assert infer_handles_sensitive_data({"data_classification": "Internal"}) is None


def test_tls_helpers_accept_human_friendly_custom_values():
    assert is_deprecated_tls_value("TLS 1.1") is True
    assert is_deprecated_tls_value("tls-1.0") is True
    assert is_tls_1_0_value("TLS 1.0") is True
    assert is_tls_1_1_value("TLS 1.1") is True
    assert is_no_tls_value("plaintext") is True
    assert is_no_tls_value("TLS 1.3") is False
