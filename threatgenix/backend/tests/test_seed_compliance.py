from __future__ import annotations

from app.seed import normalized_compliance_seed_data


def test_osfi_b13_seed_ids_are_internal_alignment_labels_not_fake_clause_numbers():
    osfi_entries = [
        entry for entry in normalized_compliance_seed_data() if entry[2] == "OSFI B-13"
    ]

    assert osfi_entries
    assert all(not control_id.startswith("B13-") for *_, control_id, _ in osfi_entries)
    assert all("ThreatGenix internal OSFI B-13 alignment" in name for *_, name in osfi_entries)


def test_compliance_seed_data_has_unique_upsert_keys():
    entries = normalized_compliance_seed_data()
    keys = [(entry[0], entry[1], entry[2], entry[3]) for entry in entries]

    assert len(keys) == len(set(keys))
