#!/bin/zsh
set -euo pipefail

SCRIPT_DIR="${0:A:h}"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROOF_DIR="${AEGIS_SECRET_LOCAL_PROOF_DIR:-$ROOT_DIR/dist/local-broker-proof}"
PROOF_PATH="$PROOF_DIR/aegis-broker-local-proof.json"

mkdir -p "$PROOF_DIR"

"$ROOT_DIR/scripts/ci_local.sh"

python3 - "$ROOT_DIR" "$PROOF_PATH" <<'PY'
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

root = Path(sys.argv[1])
proof_path = Path(sys.argv[2])
commit = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()

proof = {
    "schema_version": "aegis.local_broker_proof.v1",
    "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "source_repo": "mithran-hq/aegis-secret",
    "source_ref": f"git:{commit}",
    "hosted_infrastructure_required": False,
    "proof_label": "local_aegis_broker_proof",
    "not_hosted_d72_github_app_grant_proof": True,
    "raw_credential_material_present": False,
    "broker_mcp_raw_secret_crud_available": False,
    "assertions": [
        {
            "name": "ordinary_commands_are_not_brokered_by_default",
            "evidence": "AegisSecretCoreTests.testShellGuardAllowsUnrelatedCommand"
        },
        {
            "name": "protected_github_mutations_are_bruno_gated",
            "evidence": "AegisSecretCoreTests.testShellGuardDeniesProtectedGhMutationWhenBrunoDenies"
        },
        {
            "name": "privileged_terraform_apply_reroutes_to_broker_mcp",
            "evidence": "AegisSecretCoreTests.testShellGuardBlocksTerraformApplyThroughBrokerMCP"
        },
        {
            "name": "keychain_secret_references_are_injected_without_receipt_leakage",
            "evidence": "AegisSecretCoreTests.testRunnerInjectsReferencedSecretWithoutReceiptLeakage"
        },
        {
            "name": "tool_decision_receipts_include_policy_output_hashes_and_redaction",
            "evidence": "AegisSecretCoreTests.testRunnerIncludesToolDecisionReceipt"
        },
        {
            "name": "receipt_jsonl_handoff_is_daemon_consumable",
            "evidence": "AegisSecretCoreTests.testReceiptRecorderWritesJSONL"
        }
    ],
    "receipt_schema": "aegis.tool_decision_receipt.v1",
    "receipt_examples": "docs/tool-decision-receipts.md",
    "boundary_doc": "docs/local-broker-proof.md"
}

proof_path.write_text(json.dumps(proof, indent=2, sort_keys=True) + "\n")
print(f"Wrote local broker proof: {proof_path}")
print("raw_credential_material_present=false")
print("hosted_infrastructure_required=false")
PY
