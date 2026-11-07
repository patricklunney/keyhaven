#!/usr/bin/env bash
# Generate an ES256 signing key and store it directly in Secrets Manager.
# The key is piped from `keyhaven genkey` to the AWS CLI: it is never written
# to disk, printed, or stored in Terraform state. Only metadata is read back.
#   usage: scripts/signing-key.sh          (only if the secret has no value yet)
#          FORCE=1 scripts/signing-key.sh  (rotate: invalidates all issued tokens)
set -euo pipefail
cd "$(dirname "$0")/.."
SECRET=$(cd deploy/terraform && terraform output -raw signing_key_secret_arn)
REGION=$(aws configure get region || echo us-east-1)

versions=$(aws secretsmanager describe-secret --region "$REGION" --secret-id "$SECRET" \
  --query 'length(keys(VersionIdsToStages || `{}`))' --output text)
if [ "$versions" != "0" ] && [ "${FORCE:-}" != "1" ]; then
  echo "Signing key already set ($versions version(s)). Use FORCE=1 to rotate (signs out every app)." >&2
  exit 1
fi

go run ./cmd/keyhaven genkey | aws secretsmanager put-secret-value --region "$REGION" \
  --secret-id "$SECRET" --secret-string file:///dev/stdin --query 'VersionId' --output text >/dev/null
echo "Signing key stored in $SECRET"
