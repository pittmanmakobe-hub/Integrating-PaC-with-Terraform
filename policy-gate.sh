#!/usr/bin/env bash
# scripts/policy-gate.sh
# Wraps conftest for all four AWS+GCP namespaces.
# Usage: ./scripts/policy-gate.sh --workspace <path/to/tf/workspace>
#
# Called by CI in Lab 4.3. Exits 0 on full pass, 1 on any failure.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/lab-3-4"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --policy)    POLICY_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" ]] && {
  echo "Usage: $0 --workspace <path>" >&2
  exit 2
}

mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )

EXIT=0
{
  echo "["
  FIRST=1
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6 ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","

    # || true so one failure doesn't abort remaining namespaces
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json" || true)

    if echo "$OUT" | python3 -c \
      'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)'
    then
      : # namespace passed
    else
      EXIT=1
    fi

    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  echo "See $EVIDENCE_DIR/conftest-results.json"
fi

exit $EXIT
