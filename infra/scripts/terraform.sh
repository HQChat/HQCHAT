#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Plans or applies one environment's Terraform (infra/terraform) against its
# state in R2, refusing destructive changes to stateful resources unless
# ALLOW_REPLACE=true (tf-guard.sh). After an apply, writes the outputs as JSON
# to $TF_OUTPUTS (default /tmp/tf-outputs.json).
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

terraform plan -input=false -lock-timeout=5m -out=tfplan
terraform show -json tfplan >tfplan.json
"$root/infra/scripts/tf-guard.sh" tfplan.json

if [[ "$action" == apply ]]; then
  terraform apply -input=false -lock-timeout=5m tfplan
  terraform output -json >"${TF_OUTPUTS:-/tmp/tf-outputs.json}"
fi
rm -f tfplan tfplan.json
