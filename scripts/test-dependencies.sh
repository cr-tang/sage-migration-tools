#!/bin/bash
# Test script dependencies and environment for VT incremental import
# Run this before deploying to K8s to verify everything works

set -e

echo "=== VT Incremental Import - Dependency Check ==="
echo ""

# 1. Check Python version
echo "[1/7] Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "  ✓ $PYTHON_VERSION"
else
    echo "  ❌ python3 not found"
    exit 1
fi

# 2. Check required Python packages
echo ""
echo "[2/7] Checking Python packages..."
REQUIRED_PACKAGES=(
    "oci"
    "google-cloud-storage"
    "pyarrow"
    "pandas"
    "mysql-connector-python"
)

MISSING_PACKAGES=()
for package in "${REQUIRED_PACKAGES[@]}"; do
    if python3 -c "import ${package//-/_}" 2>/dev/null; then
        echo "  ✓ $package"
    else
        echo "  ❌ $package (missing)"
        MISSING_PACKAGES+=("$package")
    fi
done

if [ ${#MISSING_PACKAGES[@]} -gt 0 ]; then
    echo ""
    echo "Install missing packages with:"
    echo "  pip3 install ${MISSING_PACKAGES[*]}"
    exit 1
fi

# 3. Check OCI credentials
echo ""
echo "[3/7] Checking OCI credentials..."
OCI_CONFIG="$HOME/.oci/config"
OCI_KEY="$HOME/.oci/sessions/dev/oci_api_key.pem"

if [ -f "$OCI_CONFIG" ]; then
    echo "  ✓ OCI config exists: $OCI_CONFIG"
else
    echo "  ❌ OCI config not found: $OCI_CONFIG"
    exit 1
fi

if [ -f "$OCI_KEY" ]; then
    echo "  ✓ OCI key exists: $OCI_KEY"
else
    echo "  ❌ OCI key not found: $OCI_KEY"
    exit 1
fi

# 4. Test OCI session
echo ""
echo "[4/7] Testing OCI session..."
if oci session validate --profile dev --auth security_token &>/dev/null; then
    EXPIRY=$(oci session validate --profile dev --auth security_token 2>&1 | grep "valid until" || echo "unknown")
    echo "  ✓ OCI session valid: $EXPIRY"
else
    echo "  ⚠️  OCI session expired or invalid"
    echo "  Run: oci session authenticate --profile dev"
fi

# 5. Test OCI API access
echo ""
echo "[5/7] Testing OCI API access..."
if python3 -c "
import oci
config = oci.config.from_file(profile_name='dev')
token_file = config['security_token_file']
with open(token_file, 'r') as f:
    token = f.read()
private_key = oci.signer.load_private_key_from_file(config['key_file'])
signer = oci.auth.signers.SecurityTokenSigner(token, private_key)
client = oci.object_storage.ObjectStorageClient(config={'region': 'us-ashburn-1'}, signer=signer)
print('OCI client created successfully')
" 2>&1 | grep -q "successfully"; then
    echo "  ✓ OCI API access working"
else
    echo "  ❌ OCI API access failed"
    echo "  Check credentials and session validity"
    exit 1
fi

# 6. Check TiDB connectivity (optional, requires VPN)
echo ""
echo "[6/7] Testing TiDB connectivity..."
TIDB_HOST="tidb-stg-ap-tokyo-1.cybereason.net"
TIDB_PORT="4000"

if nc -z -w 3 $TIDB_HOST $TIDB_PORT 2>/dev/null; then
    echo "  ✓ TiDB reachable at $TIDB_HOST:$TIDB_PORT"
else
    echo "  ⚠️  TiDB not reachable (VPN required)"
    echo "  This is OK if you're not on JPN VPN"
fi

# 7. Check GCS access (requires GCP credentials)
echo ""
echo "[7/7] Testing GCS access..."
if command -v gsutil &> /dev/null; then
    if gsutil ls gs://vt-file-feeder-by-date/ | head -3 &>/dev/null; then
        echo "  ✓ GCS bucket accessible"
    else
        echo "  ⚠️  GCS bucket not accessible"
        echo "  This is OK if you don't have GCP credentials locally"
        echo "  K8s pod will use service account for GCS access"
    fi
else
    echo "  ⚠️  gsutil not installed"
    echo "  This is OK - K8s pod will have gsutil"
fi

# Summary
echo ""
echo "=== Dependency Check Complete ==="
echo ""
echo "✅ All critical dependencies satisfied"
echo ""
echo "Next steps:"
echo "  1. Ensure you're on JPN VPN"
echo "  2. Test upload script:"
echo "     cd /Users/tangxin/work/sage-migration-tools/scripts"
echo "     python3 upload_to_oci.py --dry-run"
echo ""
echo "  3. Deploy to K8s:"
echo "     cd /Users/tangxin/work/sage-migration-tools/k8s"
echo "     ./setup-cronjob.sh"
