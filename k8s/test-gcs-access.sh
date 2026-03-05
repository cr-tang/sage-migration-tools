#!/bin/bash
# Run GCS access test in K8s cluster
# This verifies that pods can connect to and download from GCS

set -e

NAMESPACE="stgbusybox"
JOB_NAME="test-gcs-access"

echo "=== Testing GCS Access from K8s ==="
echo ""

# Check if namespace exists
if ! kubectl get namespace $NAMESPACE &>/dev/null; then
    echo "❌ Namespace '$NAMESPACE' does not exist"
    echo "Available namespaces:"
    kubectl get namespaces
    echo ""
    read -p "Enter namespace to use: " NAMESPACE
fi

echo "Using namespace: $NAMESPACE"
echo ""

# Delete old job if exists
if kubectl get job $JOB_NAME -n $NAMESPACE &>/dev/null; then
    echo "Deleting old job..."
    kubectl delete job $JOB_NAME -n $NAMESPACE
    sleep 2
fi

# Deploy test job
echo "Deploying test job..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
kubectl apply -f "$SCRIPT_DIR/test-gcs-access-job.yaml"

echo ""
echo "Waiting for pod to start..."
sleep 5

# Get pod name
POD_NAME=$(kubectl get pods -n $NAMESPACE -l app=test-gcs-access -o name | head -1)

if [ -z "$POD_NAME" ]; then
    echo "❌ Pod not found"
    echo "Check job status:"
    kubectl get jobs -n $NAMESPACE
    exit 1
fi

echo "Pod: $POD_NAME"
echo ""

# Wait for pod to be ready
echo "Waiting for pod to be ready..."
kubectl wait --for=condition=Ready $POD_NAME -n $NAMESPACE --timeout=60s 2>/dev/null || true

# Stream logs
echo ""
echo "=== Test Output ==="
echo ""
kubectl logs -f $POD_NAME -n $NAMESPACE

# Check result
echo ""
echo "=== Test Result ==="
if kubectl get $POD_NAME -n $NAMESPACE -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null | grep -q "^0$"; then
    echo "✅ Test passed!"
    echo ""
    echo "GCS is accessible from K8s cluster"
    echo "You can now deploy the VT incremental import CronJob:"
    echo "  cd $(dirname "$SCRIPT_DIR")/k8s"
    echo "  ./setup-cronjob.sh"
else
    echo "❌ Test failed"
    echo ""
    echo "Check the logs above for details"
    echo "Common issues:"
    echo "  - No GCP service account configured"
    echo "  - Network policies blocking GCS access"
    echo "  - Bucket permissions"
fi

echo ""
echo "Cleanup:"
echo "  kubectl delete job $JOB_NAME -n $NAMESPACE"
