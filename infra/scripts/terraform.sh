#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Plans or applies one environment's Terraform (infra/terraform) against its
# state in R2, refusing destructive changes to stateful resources unless
# ALLOW_REPLACE=true (tf-guard.sh). An apply first imports what the plan would
# create but already exists (tf-adopt.sh). After an apply, writes the outputs as JSON
# to $TF_OUTPUTS (default: a new private temporary file, whose path it prints).
# The outputs and the plan hold every generated secret in clear: both are
# written 0600, and the plan is removed however the script ends.
#
#   infra/scripts/terraform.sh <environment> plan|apply
#
# Needs DIGITALOCEAN_TOKEN, CLOUDFLARE_API_TOKEN, R2_ACCESS_KEY_ID,
# R2_SECRET_ACCESS_KEY, and TF_VAR_image_url / TF_VAR_image_name.
set -euo pipefail

ENVIRONMENT="${1:?usage: terraform.sh <environment> plan|apply}"
action="${2:?usage: terraform.sh <environment> plan|apply}"
# shellcheck source=lib.sh
source "$(dirname "$0")/lib.sh"
cd "$root/infra/terraform"
umask 077
trap 'rm -f tfplan tfplan.json' EXIT

export AWS_ACCESS_KEY_ID="${R2_ACCESS_KEY_ID:?}" AWS_SECRET_ACCESS_KEY="${R2_SECRET_ACCESS_KEY:?}"
export TF_VAR_environment="$ENVIRONMENT" TF_IN_AUTOMATION=1

terraform init -input=false -reconfigure \
  -backend-config="bucket=$(env_get "$ENVIRONMENT" .stateBucket)" \
  -backend-config="key=$ENVIRONMENT/terraform.tfstate" \
  -backend-config="region=auto" \
  -backend-config="endpoints={s3=\"https://$(env_get "$ENVIRONMENT" .cloudflare.accountId).r2.cloudflarestorage.com\"}" \
  -backend-config="use_lockfile=true" \
  -backend-config="skip_credentials_validation=true" \
  -backend-config="skip_metadata_api_check=true" \
  -backend-config="skip_region_validation=true" \
  -backend-config="skip_requesting_account_id=true" \
  -backend-config="skip_s3_checksum=true" \
  -backend-config="use_path_style=true"

plan() {
  terraform plan -input=false -lock-timeout=5m -out=tfplan
  terraform show -json tfplan >tfplan.json
}
plan
# Before an apply, what the plan would create but already exists is imported,
# then planned again (tf-adopt.sh), so the guard judges the plan that will run.
if [[ "$action" == apply ]]; then
  adopted="$("$root/infra/scripts/tf-adopt.sh" tfplan.json)"
  if ((adopted > 0)); then plan; fi
fi
"$root/infra/scripts/tf-guard.sh" tfplan.json

if [[ "$action" == apply ]]; then
  terraform apply -input=false -lock-timeout=5m tfplan
  outputs="${TF_OUTPUTS:-$(mktemp)}"
  terraform output -json >"$outputs"
  [[ -n "${TF_OUTPUTS:-}" ]] || echo "outputs (secrets included) in $outputs: TF_OUTPUTS=$outputs for publish-secrets.sh, then delete it" >&2
fi
