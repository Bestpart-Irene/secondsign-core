# Copyright 2026 SecondSign contributors
# SPDX-License-Identifier: Apache-2.0
"""A ratchet on the AuditReceipt surface (spec §3.6.1).

A receipt is an exact scalar allow-list: adding a field is how a raw value would
eventually be smuggled into the audit trail. The frozen field set is asserted
here, so a new field cannot land without this test being changed deliberately.
"""

from secondsign.audit import AuditReceipt

FROZEN_FIELDS = {
    "sequence": True,
    "prev_hash": True,
    "digest": True,
    "verdict": True,
    "reasons": False,
    "outcome_status": False,
    "approval_id": False,
    # Added by CORE-S019, deliberately and through this ratchet. A trail that
    # cannot say *which workload* asked cannot answer the question an incident
    # starts with. It is admitted only in its already-redacted form: the type is
    # `Fingerprint`, so a raw URI SAN is not representable in it, and the key
    # that produced it is control plane.
    "principal_ref": False,
    "receipt_hash": True,
}


def test_receipt_field_set_is_frozen():
    live = {name: field.is_required() for name, field in AuditReceipt.model_fields.items()}
    assert live == FROZEN_FIELDS


def test_receipt_forbids_unknown_fields():
    assert AuditReceipt.model_config.get("extra") == "forbid"
    assert AuditReceipt.model_config.get("frozen") is True
