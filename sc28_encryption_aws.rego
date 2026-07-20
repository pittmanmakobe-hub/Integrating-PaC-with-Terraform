cp -r ../lab-3-3/policies ./policies
opa test -v policies/    # 8/8 PASS

cd ../lab-2-3
eval "$(aws configure export-credentials --profile <your-sandbox> --format env)"
terraform init
terraform plan -out=tfplan
terraform show -json tfplan > plan.json

conftest test --policy policies --namespace compliance.sc28 plan.json
conftest test --policy policies --namespace compliance.ac3  plan.json
conftest test --policy policies --namespace compliance.cm6  plan.json

# policies/sc28_encryption_aws.rego
# METADATA
# title: SC-28 - Encryption at Rest (AWS S3)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_server_side_encryption_configuration that references it."
# custom:
#   control_id: SC-28
#   framework: nist-800-53
#   severity: high
#   remediation: "Add aws_s3_bucket_server_side_encryption_configuration { bucket = aws_s3_bucket.<name>.id ... } for the bucket."
package compliance.sc28_aws

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_encryption(bucket)
	msg := sprintf(
		"[SC-28] %s: aws_s3_bucket has no matching aws_s3_bucket_server_side_encryption_configuration. Remediation: add one referencing this bucket.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

# policies/ac3_no_public_aws.rego
# METADATA
# title: AC-3 - Access Enforcement (AWS S3 public access block)
# description: "Every aws_s3_bucket must have an aws_s3_bucket_public_access_block referencing it, with all four flags true."
# custom:
#   control_id: AC-3
#   framework: nist-800-53
#   severity: critical
package compliance.ac3_aws

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_complete_pab(bucket)
	msg := sprintf(
		"[AC-3] %s: missing or incomplete aws_s3_bucket_public_access_block. All four flags must be true.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_complete_pab(bucket_addr) if {
	pab := pab_for(bucket_addr)
	planned := pab_planned_values(pab.address)
	planned.block_public_acls == true
	planned.block_public_policy == true
	planned.ignore_public_acls == true
	planned.restrict_public_buckets == true
}

pab_for(bucket_addr) := pab if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_public_access_block"
	some ref in r.expressions.bucket.references
	pab_references_bucket(ref, bucket_addr)
	pab := {"address": sprintf("aws_s3_bucket_public_access_block.%s", [r.name])}
}

pab_references_bucket(ref, bucket_addr) if ref == bucket_addr
pab_references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])

pab_planned_values(addr) := values if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	values := r.values
}

# policies/cm6_required_tags_aws.rego
# METADATA
# title: CM-6 - Configuration Settings (AWS required tags)
# custom:
#   control_id: CM-6
#   framework: nist-800-53
#   severity: medium
package compliance.cm6_aws

import rego.v1

required := {"Project", "Environment", "ManagedBy", "ComplianceScope"}

labelable_type(t) if t == "aws_s3_bucket"
labelable_type(t) if t == "aws_dynamodb_table"
labelable_type(t) if t == "aws_lambda_function"
labelable_type(t) if t == "aws_kms_key"
labelable_type(t) if t == "aws_cloudtrail"

deny contains msg if {
	resource := all_resources[_]
	labelable_type(resource.type)
	provided := tag_keys(resource)
	missing := required - provided
	count(missing) > 0
	msg := sprintf(
		"[CM-6] %s: missing required tags %v. Remediation: add the missing tags or use provider default_tags.",
		[resource.address, sort_array(missing)],
	)
}

all_resources contains r if { some r in input.planned_values.root_module.resources }
all_resources contains r if {
	some child in input.planned_values.root_module.child_modules
	some r in child.resources
}

tag_keys(resource) := keys if {
	resource.values.tags_all
	keys := {k | resource.values.tags_all[k]}
}

tag_keys(resource) := keys if {
	not resource.values.tags_all
	resource.values.tags
	keys := {k | resource.values.tags[k]}
}

tag_keys(resource) := set() if {
	not resource.values.tags_all
	not resource.values.tags
}

sort_array(s) := sorted if { sorted := sort([x | some x in s]) }

for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws ; do
  echo "=== $ns ==="
  conftest test --policy policies --namespace $ns plan.json
done

=== compliance.sc28_aws ===
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
=== compliance.ac3_aws ===
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions
=== compliance.cm6_aws ===
1 test, 1 passed, 0 warnings, 0 failures, 0 exceptions

mkdir broken && cp ../lab-2-3/*.tf broken/
# Edit broken/main.tf: delete the aws_s3_bucket_server_side_encryption_configuration.primary resource
( cd broken && terraform init && terraform plan -out=tfplan && terraform show -json tfplan > plan.json )

conftest test --policy policies --namespace compliance.sc28_aws broken/plan.json

#!/usr/bin/env bash
# scripts/policy-gate.sh
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

[[ -z "$WORKSPACE" ]] && { echo "Usage: $0 --workspace <path>" >&2; exit 2; }
mkdir -p "$EVIDENCE_DIR"

( cd "$WORKSPACE" && terraform show -json tfplan > "$WORKSPACE/plan.json" )

EXIT=0
{
  echo "["
  FIRST=1
  for ns in compliance.sc28_aws compliance.ac3_aws compliance.cm6_aws compliance.cm6 ; do
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    OUT=$(conftest test --policy "$POLICY_DIR" --namespace "$ns" --output=json "$WORKSPACE/plan.json" || true)
    if echo "$OUT" | python3 -c 'import sys,json; d=json.load(sys.stdin); sys.exit(0 if all(len(r.get("failures") or [])==0 for r in d) else 1)'; then : ; else EXIT=1 ; fi
    echo "$OUT"
  done
  echo "]"
} > "$EVIDENCE_DIR/conftest-results.json"

if [[ $EXIT -eq 0 ]]; then echo "policy-gate: PASS"
else echo "policy-gate: FAIL"; echo "See $EVIDENCE_DIR/conftest-results.json"
fi
exit $EXIT

