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

install_dependencies() {
    log_info "Installing dependencies..."
    apt-get update -qq
    apt-get install -y -qq curl wget apt-transport-https ca-certificates software-properties-common jq postgresql-client redis-tools
}

install_k3s() {
    log_info "Installing k3s..."
    if command -v k3s &> /dev/null; then
        log_warn "k3s already installed, skipping..."
        return
    fi
    curl -sfL https://get.k3s.io | sh -s - --write-kubeconfig-mode 644
    sleep 10
    mkdir -p /root/.kube
    cp /etc/rancher/k3s/k3s.yaml /root/.kube/config
    chmod 600 /root/.kube/config
    log_info "Waiting for k3s to be ready..."
    kubectl wait --for=condition=Ready nodes --all --timeout=120s
    log_info "k3s installed successfully"
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

install_sealed_secrets() {
    log_info "Installing Sealed Secrets controller..."
    helm repo add sealed-secrets https://bitnami-labs.github.io/sealed-secrets 2>/dev/null || true
    helm repo update
    helm upgrade --install sealed-secrets sealed-secrets/sealed-secrets \
        --namespace kube-system \
        --wait
    log_info "Sealed Secrets installed successfully"
}

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
    log_info "PostgreSQL password saved to $PROJECT_DIR/.postgres-password"
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
    
    log_info "PostgreSQL backup CronJob deployed successfully"
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
    log_info "Redis password saved to $PROJECT_DIR/.redis-password"
}

deploy_login_app() {
    log_info "Deploying Login Application..."
    
    POSTGRES_PASSWORD=$(cat "$PROJECT_DIR/.postgres-password")
    REDIS_PASSWORD=$(cat "$PROJECT_DIR/.redis-password")
    APP_SECRET_KEY=$(generate_password)
    
    helm upgrade --install login-app "$PROJECT_DIR/helm/login-app" \
        --namespace login-app \
        --set image.repository=sametdemirel/login-app \
        --set image.tag=1.0.1 \
        --set image.pullPolicy=IfNotPresent \
        --set postgresql.host=postgresql.postgres.svc.cluster.local \
        --set postgresql.port=5432 \
        --set postgresql.database=appdb \
        --set postgresql.username=appuser \
        --set postgresql.password="$POSTGRES_PASSWORD" \
        --set redis.host=redis-master.redis.svc.cluster.local \
        --set redis.port=6379 \
        --set redis.password="$REDIS_PASSWORD" \
        --set app.secretKey="$APP_SECRET_KEY" \
        --set service.nodePort=30080 \
        --wait --timeout=300s
    
    log_info "Login Application deployed successfully"
}

copy_test_scripts() {
    log_info "Setting up test scripts..."
    chmod +x "$PROJECT_DIR/scripts/test-postgres.sh"
    chmod +x "$PROJECT_DIR/scripts/test-redis.sh"
}

print_summary() {
    SERVER_IP=$(hostname -I | awk '{print $1}')
    
    echo ""
    echo "=============================================="
    echo "        INSTALLATION COMPLETE"
    echo "=============================================="
    echo ""
    echo "Access URLs:"
    echo "  Login App:  http://$SERVER_IP:30080"
    echo "  PostgreSQL: $SERVER_IP:30432"
    echo "  Redis:      $SERVER_IP:30379"
    echo ""
    echo "Credentials:"
    echo "  PostgreSQL: stored in $PROJECT_DIR/.postgres-password"
    echo "  Redis:      stored in $PROJECT_DIR/.redis-password"
    echo ""
    echo "Test connectivity:"
    echo "  $PROJECT_DIR/scripts/test-postgres.sh"
    echo "  $PROJECT_DIR/scripts/test-redis.sh"
    echo ""
    echo "Useful commands:"
    echo "  kubectl get pods -A"
    echo "  kubectl get svc -A"
    echo "  helm list -A"
    echo ""
    echo "=============================================="
}

install_all() {
    check_root
    check_ubuntu
    install_dependencies
    install_k3s
    install_helm
    install_sealed_secrets
    create_namespaces
    deploy_postgresql
    deploy_postgresql_backup
    deploy_redis
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
    
    log_info "Uninstalling k3s..."
    /usr/local/bin/k3s-uninstall.sh 2>/dev/null || true
    
    rm -f "$PROJECT_DIR/.postgres-password"
    rm -f "$PROJECT_DIR/.redis-password"
    
    log_info "All components removed successfully"
}

show_usage() {
    echo "Usage: $0 {install|delete|status}"
    echo ""
    echo "Commands:"
    echo "  install  - Install entire stack (k3s, PostgreSQL, Redis, Login App)"
    echo "  delete   - Remove entire stack"
    echo "  status   - Show current status"
}

show_status() {
    echo "=== Nodes ==="
    kubectl get nodes 2>/dev/null || echo "k3s not running"
    echo ""
    echo "=== Pods ==="
    kubectl get pods -A 2>/dev/null || echo "k3s not running"
    echo ""
    echo "=== Services ==="
    kubectl get svc -A 2>/dev/null || echo "k3s not running"
    echo ""
    echo "=== Helm Releases ==="
    helm list -A 2>/dev/null || echo "Helm not available"
}

case "${1:-}" in
    install)
        install_all
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
