#!/bin/bash
# Setup VT Incremental Import CronJob
# This script creates necessary secrets and deploys the CronJob to Kubernetes

set -e

NAMESPACE="phoenix"
TIDB_HOST="tidb-stg-ap-tokyo-1.cybereason.net"
TIDB_USER="root"

echo "=== VT Incremental Import CronJob Setup ==="
echo ""

# Check if namespace exists
if ! kubectl get namespace $NAMESPACE &>/dev/null; then
    echo "❌ Namespace '$NAMESPACE' does not exist"
    echo "Create it with: kubectl create namespace $NAMESPACE"
    exit 1
fi

echo "✓ Namespace '$NAMESPACE' exists"

# 1. Create TiDB credentials secret
echo ""
echo "[1/3] Creating TiDB credentials secret..."
read -sp "Enter TiDB password: " TIDB_PASSWORD
echo ""

kubectl create secret generic tidb-credentials \
  --from-literal=host=$TIDB_HOST \
  --from-literal=user=$TIDB_USER \
  --from-literal=password=$TIDB_PASSWORD \
  --namespace=$NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✓ TiDB credentials secret created"

# 2. Create OCI credentials secret
echo ""
echo "[2/3] Creating OCI credentials secret..."

OCI_CONFIG_FILE="$HOME/.oci/config"
OCI_KEY_FILE="$HOME/.oci/sessions/dev/oci_api_key.pem"

if [ ! -f "$OCI_CONFIG_FILE" ]; then
    echo "❌ OCI config not found: $OCI_CONFIG_FILE"
    exit 1
fi

if [ ! -f "$OCI_KEY_FILE" ]; then
    echo "❌ OCI key not found: $OCI_KEY_FILE"
    exit 1
fi

kubectl create secret generic oci-credentials \
  --from-file=config=$OCI_CONFIG_FILE \
  --from-file=oci_api_key.pem=$OCI_KEY_FILE \
  --namespace=$NAMESPACE \
  --dry-run=client -o yaml | kubectl apply -f -

echo "✓ OCI credentials secret created"

# 3. Deploy CronJob
echo ""
echo "[3/3] Deploying CronJob..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kubectl apply -f "$SCRIPT_DIR/vt-incremental-import-cronjob.yaml"

echo "✓ CronJob deployed"

# Summary
echo ""
echo "=== Setup Complete ==="
echo ""
echo "CronJob: vt-incremental-import"
echo "  Schedule: Daily at 02:00 UTC (10:00 JST)"
echo "  Namespace: $NAMESPACE"
echo ""
echo "Useful commands:"
echo "  # Check CronJob status"
echo "  kubectl get cronjob vt-incremental-import -n $NAMESPACE"
echo ""
echo "  # View recent jobs"
echo "  kubectl get jobs -n $NAMESPACE -l app=vt-incremental-import"
echo ""
echo "  # View logs of latest job"
echo "  kubectl logs -f -n $NAMESPACE \$(kubectl get pods -n $NAMESPACE -l app=vt-incremental-import --sort-by=.metadata.creationTimestamp -o name | tail -1)"
echo ""
echo "  # Trigger manual run"
echo "  kubectl create job --from=cronjob/vt-incremental-import vt-manual-\$(date +%s) -n $NAMESPACE"
echo ""
echo "  # Delete CronJob"
echo "  kubectl delete cronjob vt-incremental-import -n $NAMESPACE"
