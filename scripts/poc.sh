#!/usr/bin/env bash
# Pause or resume a Keyhaven deployment to save money between demos.
#   pause:  scale the ECS service to 0 tasks and stop the RDS instance
#   resume: start RDS, then bring the tasks back
# While paused you pay roughly for database storage, secrets and DNS (~$4/month).
# Note: AWS automatically restarts a stopped RDS instance after 7 days.
set -euo pipefail
cd "$(dirname "$0")/../deploy/terraform"

out() { terraform output -raw "$1"; }
CLUSTER=$(out cluster_name)
SERVICE=$(out service_name)
DB=$(out db_instance_id)
REGION=$(aws configure get region || echo us-east-1)
RES="service/${CLUSTER}/${SERVICE}"

scale_limits() {
  aws application-autoscaling register-scalable-target --region "$REGION" \
    --service-namespace ecs --resource-id "$RES" --scalable-dimension ecs:service:DesiredCount \
    --min-capacity "$1" --max-capacity "$2" >/dev/null
}

db_status() {
  aws rds describe-db-instances --region "$REGION" --db-instance-identifier "$DB" \
    --query 'DBInstances[0].DBInstanceStatus' --output text
}

case "${1:-}" in
  pause)
    echo "Scaling ${SERVICE} to 0 tasks..."
    scale_limits 0 0
    aws ecs update-service --region "$REGION" --cluster "$CLUSTER" --service "$SERVICE" --desired-count 0 >/dev/null
    aws ecs wait services-stable --region "$REGION" --cluster "$CLUSTER" --services "$SERVICE"
    if [ "$(db_status)" = "available" ]; then
      echo "Stopping database ${DB}..."
      aws rds stop-db-instance --region "$REGION" --db-instance-identifier "$DB" >/dev/null
    fi
    echo "Paused. Run 'make poc-resume' to start again (the database restarts by itself after 7 days)."
    ;;
  resume)
    if [ "$(db_status)" = "stopped" ]; then
      echo "Starting database ${DB} (takes a few minutes)..."
      aws rds start-db-instance --region "$REGION" --db-instance-identifier "$DB" >/dev/null
    fi
    aws rds wait db-instance-available --region "$REGION" --db-instance-identifier "$DB"
    DESIRED=$(out desired_count)
    echo "Starting ${DESIRED} task(s)..."
    scale_limits "$DESIRED" "$(out max_count)"
    aws ecs update-service --region "$REGION" --cluster "$CLUSTER" --service "$SERVICE" --desired-count "$DESIRED" >/dev/null
    aws ecs wait services-stable --region "$REGION" --cluster "$CLUSTER" --services "$SERVICE"
    echo "Running: $(out issuer)"
    ;;
  status)
    RUNNING=$(aws ecs describe-services --region "$REGION" --cluster "$CLUSTER" --services "$SERVICE" \
      --query 'services[0].runningCount' --output text)
    echo "tasks running: ${RUNNING}, database: $(db_status)"
    ;;
  *)
    echo "usage: $0 pause|resume|status" >&2
    exit 2
    ;;
esac
