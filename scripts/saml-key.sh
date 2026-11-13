#!/usr/bin/env bash
# Generate the SAML RSA key + certificate bundle and store it directly in Secrets Manager.
# The key is piped from `keyhaven saml-keygen` to the AWS CLI: it is never written
# to disk, printed, or stored in Terraform state. Only metadata is read back.
#   usage: scripts/saml-key.sh          (only if the secret has no value yet)
#          FORCE=1 scripts/saml-key.sh  (rotate: every SAML app must re-import the metadata)
set -euo pipefail
cd "$(dirname "$0")/.."
SECRET=$(cd deploy/terraform && terraform output -raw saml_key_secret_arn)
if [ -z "$SECRET" ]; then
  echo "SAML is not enabled: set enable_saml = true, then run terraform apply -target=aws_secretsmanager_secret.saml_key" >&2
  exit 1
fi
REGION=$(aws configure get region || echo us-east-1)

versions=$(aws secretsmanager describe-secret --region "$REGION" --secret-id "$SECRET" \
  --query 'length(keys(VersionIdsToStages || `{}`))' --output text)
if [ "$versions" != "0" ] && [ "${FORCE:-}" != "1" ]; then
  echo "SAML key already set ($versions version(s)). Use FORCE=1 to rotate (every SAML app must re-import the metadata)." >&2
  exit 1
fi

go run ./cmd/keyhaven saml-keygen | aws secretsmanager put-secret-value --region "$REGION" \
  --secret-id "$SECRET" --secret-string file:///dev/stdin --query 'VersionId' --output text >/dev/null
echo "SAML key stored in $SECRET"
