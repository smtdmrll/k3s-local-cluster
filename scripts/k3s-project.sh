#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# ============================================
# SYSTEM CHECKS
# ============================================

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Please run as root or with sudo"
        exit 1
    fi
}

check_ubuntu() {
    if [ ! -f /etc/os-release ]; then
        log_error "Cannot detect OS"
        exit 1
    fi
    source /etc/os-release
    if [ "$ID" != "ubuntu" ]; then
        log_error "This script requires Ubuntu"
        exit 1
    fi
    log_info "Detected: $PRETTY_NAME"
}

# ============================================
# CORE INSTALLATIONS
# ============================================

install_dependencies() {
    log_info "Installing system dependencies..."
    apt-get update -qq
    apt-get install -y -qq curl wget apt-transport-https ca-certificates \
        software-properties-common jq postgresql-client redis-tools
}

install_k3s() {
    log_info "Installing K3s..."
    if command -v k3s &> /dev/null; then
        log_warn "K3s already installed, skipping..."
        return
    fi
    curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
    sleep 10
    mkdir -p /root/.kube
    cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
    chmod 600 /root/.kube/config
    log_info "Waiting for K3s to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
    log_info "K3s installed successfully"
}

install_helm() {
    log_info "Installing Helm..."
    if command -v helm &> /dev/null; then
        log_warn "Helm already installed, skipping..."
        return
    fi
    curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    log_info "Helm installed successfully"
}

# ============================================
# SEALED SECRETS
# ============================================

install_sealed_secrets_controller() {
    log_info "Installing Sealed Secrets controller..."
    helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets 2>/dev/null || true
    helm repo update
    helm upgrade --install sealed-secrets sealed-secrets/sealed-secrets \
        --namespace kube-system \
        --wait
    log_info "Sealed Secrets controller installed in kube-system namespace"
}

install_kubeseal_cli() {
    log_info "Installing kubeseal CLI..."
    if command -v kubeseal &> /dev/null; then
        log_warn "kubeseal already installed: $(kubeseal --version)"
        return
    fi

    KUBESEAL_VERSION="0.27.3"
    ARCH="amd64"

    cd /tmp
    curl -sL -o kubeseal.tar.gz \
        "https://github.com/bitnami-labs/sealed-secrets/releases/download/v${KUBESEAL_VERSION}/kubeseal-${KUBESEAL_VERSION}-linux-${ARCH}.tar.gz"
    tar xzf kubeseal.tar.gz kubeseal
    mv kubeseal /usr/local/bin/
    chmod +x /usr/local/bin/kubeseal
    rm -f kubeseal.tar.gz
    cd - > /dev/null

    log_info "kubeseal installed: $(kubeseal --version)"
}

fetch_sealed_secrets_cert() {
    log_info "Fetching Sealed Secrets public certificate..."

    CERT_DIR="$PROJECT_DIR/sealed-secrets"
    mkdir -p "$CERT_DIR"

    kubeseal --fetch-cert \
        --controller-name=sealed-secrets \
        --controller-namespace=kube-system \
        > "$CERT_DIR/pub-cert.pem"

    log_info "Public certificate saved to $CERT_DIR/pub-cert.pem"
}

create_sealed_secret() {
    # Usage: create_sealed_secret <name> <namespace> <key1=val1> <key2=val2> ...
    local SECRET_NAME="$1"
    local NAMESPACE="$2"
    shift 2

    CERT_FILE="$PROJECT_DIR/sealed-secrets/pub-cert.pem"
    if [ ! -f "$CERT_FILE" ]; then
        log_error "Public certificate not found at $CERT_FILE"
        log_error "Run fetch_sealed_secrets_cert first"
        exit 1
    fi

    # Build --from-literal arguments
    local LITERALS=""
    for entry in "$@"; do
        LITERALS="$LITERALS --from-literal=$entry"
    done

    log_info "Creating SealedSecret: $SECRET_NAME in namespace $NAMESPACE"

    # Pipeline: create plain secret (dry-run) -> encrypt with kubeseal -> apply
    kubectl create secret generic "$SECRET_NAME" \
        --namespace="$NAMESPACE" \
        $LITERALS \
        --dry-run=client -o yaml | \
    kubeseal --cert "$CERT_FILE" --format yaml | \
    kubectl apply -f -

    log_info "SealedSecret $SECRET_NAME created and applied"
}

# ============================================
# HELPER FUNCTIONS
# ============================================

generate_password() {
    openssl rand -base64 16 | tr -dc 'a-zA-Z0-9' | head -c 16
}

create_namespaces() {
    log_info "Creating namespaces..."
    kubectl create namespace postgres --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace redis --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace login-app --dry-run=client -o yaml | kubectl apply -f -
    kubectl create namespace backup --dry-run=client -o yaml | kubectl apply -f -
}

# ============================================
# DATABASE & CACHE
# ============================================

deploy_postgresql() {
    log_info "Deploying PostgreSQL..."

    POSTGRES_PASSWORD=$(generate_password)

    echo "$POSTGRES_PASSWORD" > "$PROJECT_DIR/.postgres-password"
    chmod 600 "$PROJECT_DIR/.postgres-password"

    helm repo add bitnami https://charts.bitnami.com/bitnami 2>/dev/null || true
    helm repo update

    helm upgrade --install postgresql bitnami/postgresql \
        --namespace postgres \
        --set auth.postgresPassword="$POSTGRES_PASSWORD" \
        --set auth.username=appuser \
        --set auth.password="$POSTGRES_PASSWORD" \
        --set auth.database=appdb \
        --set architecture=standalone \
        --set primary.service.type=NodePort \
        --set-string primary.service.nodePorts.postgresql="30432" \
        --set primary.persistence.size=5Gi \
        --set primary.resources.requests.memory=256Mi \
        --set primary.resources.requests.cpu=100m \
        --set primary.resources.limits.memory=512Mi \
        --set primary.resources.limits.cpu=500m \
        --wait --timeout=300s

    log_info "PostgreSQL deployed successfully"
}

deploy_postgresql_backup() {
    log_info "Deploying PostgreSQL backup CronJob..."

    POSTGRES_PASSWORD=$(cat "$PROJECT_DIR/.postgres-password")

    kubectl create secret generic postgres-backup-secret \
        --namespace backup \
        --from-literal=PGPASSWORD="$POSTGRES_PASSWORD" \
        --dry-run=client -o yaml | kubectl apply -f -

    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: postgres-backup-pvc
  namespace: backup
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 5Gi
---
apiVersion: batch/v1
kind: CronJob
metadata:
  name: postgres-backup
  namespace: backup
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: backup
            image: bitnami/postgresql:16
            command:
            - /bin/bash
            - -c
            - |
              BACKUP_FILE=/backups/backup-\$(date +%Y%m%d-%H%M%S).sql
              pg_dump -h postgresql.postgres.svc.cluster.local -U appuser -d appdb > \$BACKUP_FILE
              gzip \$BACKUP_FILE
              find /backups -name "*.gz" -mtime +7 -delete
            env:
            - name: PGPASSWORD
              valueFrom:
                secretKeyRef:
                  name: postgres-backup-secret
                  key: PGPASSWORD
            volumeMounts:
            - name: backup-storage
              mountPath: /backups
          restartPolicy: OnFailure
          volumes:
          - name: backup-storage
            persistentVolumeClaim:
              claimName: postgres-backup-pvc
EOF

    log_info "PostgreSQL backup CronJob deployed (daily at 02:00 UTC)"
}

deploy_redis() {
    log_info "Deploying Redis..."

    REDIS_PASSWORD=$(generate_password)

    echo "$REDIS_PASSWORD" > "$PROJECT_DIR/.redis-password"
    chmod 600 "$PROJECT_DIR/.redis-password"

    helm upgrade --install redis bitnami/redis \
        --namespace redis \
        --set auth.password="$REDIS_PASSWORD" \
        --set architecture=standalone \
        --set master.service.type=NodePort \
        --set-string master.service.nodePorts.redis="30379" \
        --set master.persistence.size=2Gi \
        --set master.resources.requests.memory=128Mi \
        --set master.resources.requests.cpu=100m \
        --set master.resources.limits.memory=256Mi \
        --set master.resources.limits.cpu=250m \
        --wait --timeout=300s

    log_info "Redis deployed successfully"
}

# ============================================
# APPLICATION DEPLOYMENT
# ============================================

deploy_login_app() {
    log_info "Deploying Login Application with Sealed Secrets..."

    POSTGRES_PASSWORD=$(cat "$PROJECT_DIR/.postgres-password")
    REDIS_PASSWORD=$(cat "$PROJECT_DIR/.redis-password")
    APP_SECRET_KEY=$(generate_password)

    # Create ServiceAccount
    kubectl create serviceaccount login-app \
        --namespace login-app \
        --dry-run=client -o yaml | kubectl apply -f -

    # Create SealedSecret containing all sensitive values
    # kubeseal encrypts the plain secret with the controller's public key
    # Only the controller in kube-system can decrypt it back
    create_sealed_secret "login-app-secret" "login-app" \
        "POSTGRES_PASSWORD=$POSTGRES_PASSWORD" \
        "REDIS_PASSWORD=$REDIS_PASSWORD" \
        "SECRET_KEY=$APP_SECRET_KEY"

    # Wait for the controller to create the decrypted Secret
    log_info "Waiting for Sealed Secrets controller to decrypt..."
    for i in $(seq 1 30); do
        if kubectl get secret login-app-secret -n login-app &>/dev/null; then
            log_info "Secret created by controller"
            break
        fi
        if [ "$i" -eq 30 ]; then
            log_error "Timeout waiting for secret decryption"
            exit 1
        fi
        sleep 2
    done

    # Deploy with Helm - secrets.existingSecret tells the chart
    # to use the Secret created by Sealed Secrets controller
    helm upgrade --install login-app "$PROJECT_DIR/helm/login-app" \
        --namespace login-app \
        --set secrets.existingSecret=login-app-secret \
        --wait --timeout=300s

    log_info "Login Application deployed successfully"
}

# ============================================
# SUMMARY OUTPUT
# ============================================

print_cluster_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo "=============================================="
    echo "      K3s CLUSTER INSTALLATION COMPLETE"
    echo "=============================================="
    echo ""
    echo "Server: $SERVER_IP"
    echo ""
    echo "Components installed:"
    echo "  - K3s (Kubernetes)"
    echo "  - Helm (package manager)"
    echo "  - Sealed Secrets controller + kubeseal CLI"
    echo "  - PostgreSQL (namespace: postgres, port: 30432)"
    echo "  - Redis (namespace: redis, port: 30379)"
    echo "  - Backup CronJob (daily at 02:00 UTC)"
    echo ""
    echo "Credentials (local files, not in Git):"
    echo "  PostgreSQL: cat $PROJECT_DIR/.postgres-password"
    echo "  Redis:      cat $PROJECT_DIR/.redis-password"
    echo ""
    echo "Sealed Secrets public cert:"
    echo "  $PROJECT_DIR/sealed-secrets/pub-cert.pem"
    echo ""
    echo "=============================================="
}

print_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')

    echo ""
    echo "=============================================="
    echo "    FULL STACK INSTALLATION COMPLETE"
    echo "=============================================="
    echo ""
    echo "Access:"
    echo "  Login App:  http://$SERVER_IP:30080"
    echo "  PostgreSQL: $SERVER_IP:30432"
    echo "  Redis:      $SERVER_IP:30379"
    echo ""
    echo "Credentials (local files, not in Git):"
    echo "  PostgreSQL: cat $PROJECT_DIR/.postgres-password"
    echo "  Redis:      cat $PROJECT_DIR/.redis-password"
    echo ""
    echo "Sealed Secrets:"
    echo "  SealedSecret:   kubectl get sealedsecret -n login-app"
    echo "  Decrypted:      kubectl get secret login-app-secret -n login-app"
    echo "  Public cert:    $PROJECT_DIR/sealed-secrets/pub-cert.pem"
    echo ""
    echo "Verify:"
    echo "  curl http://$SERVER_IP:30080/ready"
    echo "  $PROJECT_DIR/scripts/test-postgres.sh"
    echo "  $PROJECT_DIR/scripts/test-redis.sh"
    echo ""
    echo "=============================================="
}

# ============================================
# MAIN COMMANDS
# ============================================

install_all() {
    check_root
    check_ubuntu
    install_dependencies
    install_k3s
    install_helm
    install_sealed_secrets_controller
    install_kubeseal_cli
    fetch_sealed_secrets_cert
    create_namespaces
    deploy_postgresql
    deploy_postgresql_backup
    deploy_redis
    print_cluster_summary
}

install_withapp() {
    install_all
    deploy_login_app
    copy_test_scripts
    print_summary
}

delete_all() {
    check_root
    log_info "Removing all components..."

    helm uninstall login-app --namespace login-app 2>/dev/null || true
    helm uninstall redis --namespace redis 2>/dev/null || true
    helm uninstall postgresql --namespace postgres 2>/dev/null || true
    helm uninstall sealed-secrets --namespace kube-system 2>/dev/null || true

    kubectl delete namespace login-app --ignore-not-found
    kubectl delete namespace redis --ignore-not-found
    kubectl delete namespace postgres --ignore-not-found
    kubectl delete namespace backup --ignore-not-found

    log_info "Uninstalling K3s..."
    /usr/local/bin/k3s-uninstall.sh 2>/dev/null || true

    rm -f "$PROJECT_DIR/.postgres-password"
    rm -f "$PROJECT_DIR/.redis-password"
    rm -rf "$PROJECT_DIR/sealed-secrets"

    log_info "All components removed successfully"
}

show_status() {
    echo "=== Nodes ==="
    kubectl get nodes 2>/dev/null || echo "K3s not running"
    echo ""
    echo "=== Pods ==="
    kubectl get pods -A 2>/dev/null || echo "K3s not running"
    echo ""
    echo "=== Services ==="
    kubectl get svc -A 2>/dev/null || echo "K3s not running"
    echo ""
    echo "=== Helm Releases ==="
    helm list -A 2>/dev/null || echo "Helm not available"
    echo ""
    echo "=== Sealed Secrets ==="
    kubectl get sealedsecret -A 2>/dev/null || echo "No sealed secrets found"
}

copy_test_scripts() {
    log_info "Setting up test scripts..."
    chmod +x "$PROJECT_DIR/scripts/test-postgres.sh"
    chmod +x "$PROJECT_DIR/scripts/test-redis.sh"
}

show_usage() {
    echo "Usage: $0 {install|install-withapp|delete|status}"
    echo ""
    echo "Commands:"
    echo "  install          - Install K3s, Helm, Sealed Secrets, PostgreSQL, Redis"
    echo "  install-withapp  - Install everything + Login App (with Sealed Secrets)"
    echo "  delete           - Remove entire stack including K3s"
    echo "  status           - Show cluster status, pods, services, sealed secrets"
}

case "${1:-}" in
    install)
        install_all
        ;;
    install-withapp)
        install_withapp
        ;;
    delete)
        delete_all
        ;;
    status)
        show_status
        ;;
    *)
        show_usage
        exit 1
        ;;
esac
