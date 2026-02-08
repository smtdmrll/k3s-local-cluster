# K3s Local Kubernetes Cluster

Production-ready K3s cluster with PostgreSQL, Redis, and a full-featured DevOps management application.

## 🎯 Overview

This project provides an automated deployment solution for K3s (lightweight Kubernetes) with enterprise-grade components and a web-based management interface for remote cluster operations.

**Key Features:**
- 🚀 One-command K3s cluster deployment
- 🔐 Sealed Secrets integration for GitOps
- 📊 PostgreSQL database with automated backups
- ⚡ Redis caching layer
- 🌐 Web UI for remote cluster management
- 🛠 SSH-based Deploy Manager for infrastructure automation
- 📦 Image Establisher for instant application deployment

---

## 📋 Prerequisites

| Requirement | Specification |
|-------------|---------------|
| **OS** | Ubuntu 24.04 LTS |
| **RAM** | Minimum 4 GB |
| **CPU** | Minimum 2 cores |
| **Disk** | 40 GB available |
| **Access** | Root/sudo privileges |

---

## 🚀 Quick Start

```bash
git clone https://github.com/smtdmrll/k3s-local-cluster.git
cd k3s-local-cluster
chmod +x scripts/k3s-project.sh
```

### Installation Options

#### Option 1: Infrastructure Only
Deploys K3s cluster with core components (no web application).

```bash
sudo ./scripts/k3s-project.sh install
```

**Includes:** K3s • Helm • Sealed Secrets • PostgreSQL • Redis • Automated Backups

#### Option 2: Complete Stack
Deploys infrastructure + web management application.

```bash
sudo ./scripts/k3s-project.sh install-withapp
```

**Includes:** Everything from Option 1 + Login App with Deploy Manager & Image Establisher

Access the application at: `http://<SERVER-IP>:30080`

<p align="center">
  <img src="docs/screenshots/login.png" alt="Application Login" width="650"/>
</p>

---

## 🔧 Management Commands

```bash
# View cluster status
sudo ./scripts/k3s-project.sh status

# Complete removal
sudo ./scripts/k3s-project.sh delete
```

---

## 🖥 Application Features

<p align="center">
  <img src="docs/screenshots/dashboard.png" alt="Dashboard" width="700"/>
</p>

### Deploy Manager

Remote K3s cluster deployment via SSH. Supports both infrastructure-only and application deployment modes.

<p align="center">
  <img src="docs/screenshots/deploy-manager.png" alt="Deploy Manager" width="700"/>
</p>

**Capabilities:**
- 🎯 One-click K3s installation on remote Ubuntu servers
- 📦 Optional Docker image or Helm chart deployment
- 🔑 SSH key-based authentication
- 📝 Real-time deployment logs
- 💾 Persistent server configuration storage

**Requirements:**
- Target server: Ubuntu with SSH access
- SSH user: `devops` with sudo privileges

**Deployment Options:**
- **Docker Image**: Deploys container in `apps` namespace with NodePort service
- **Helm Chart**: Installs chart (format: `repository/chart`, e.g., `bitnami/nginx`)

### Image Establisher

Instant Docker image deployment to remote K3s clusters with automatic URL generation.

**How it works:**
1. SSH connection to target cluster
2. Dedicated namespace creation
3. Deployment + NodePort service creation
4. Automatic URL generation for immediate access

**Prerequisites:**
- ⚠️ **Target server must have K3s/Kubernetes already installed**
- SSH user must have `kubectl` access

**Popular images:**
- `nginx:alpine` (port 80)
- `httpd:latest` (port 80)
- `gcr.io/google-samples/hello-app:1.0` (port 8080)

### Saved Servers

Persistent storage of server credentials (IP + SSH key) per user. Enables one-click server selection in both Deploy Manager and Image Establisher.

---

## 📦 Deployed Components

| Component | Namespace | Access | Purpose |
|-----------|-----------|--------|---------|
| **K3s** | — | — | Kubernetes distribution |
| **Helm** | — | — | Package manager |
| **Sealed Secrets** | kube-system | Internal | Secret encryption |
| **PostgreSQL** | postgres | NodePort 30432 | Database (Bitnami) |
| **Redis** | redis | NodePort 30379 | Cache (Bitnami) |
| **Backup CronJob** | backup | — | Daily 02:00 UTC |
| **Login App** | login-app | NodePort 30080 | Web UI* |

*Available only with `install-withapp`

---

## 🛠 Technical Stack

**Infrastructure:** K3s v1.34 • Helm v3.20 • containerd  
**Data Layer:** PostgreSQL 17 • Redis 7  
**Application:** Python 3.11 • Flask 3.0 • Paramiko 3.4  
**Security:** Sealed Secrets • SSH key-based auth

---

## 💾 Backup & Recovery

- Automated daily PostgreSQL backups at 02:00 UTC
- Backups stored in persistent `/backups` volume
- CronJob-based scheduling

---

## 🔄 Multi-Node Expansion

```bash
# On master node
cat /var/lib/rancher/k3s/server/node-token

# On worker node
curl -sfL https://get.k3s.io | \
  K3S_URL=https://<MASTER-IP>:6443 \
  K3S_TOKEN=<TOKEN> sh -
```

---

## 📂 Project Structure

```
k3s-local-cluster/
├── app/                    # Flask application
│   ├── app.py              # Main backend
│   ├── Dockerfile
│   ├── requirements.txt
│   └── templates/          # UI templates
├── helm/login-app/         # Helm chart
├── scripts/
│   ├── k3s-project.sh      # Main installer
│   ├── test-postgres.sh
│   └── test-redis.sh
└── docs/
    ├── architecture.svg
    └── screenshots/
```

---

## 🏗 Architecture

<p align="center">
  <img src="docs/architecture.svg" alt="Architecture Diagram" width="100%"/>
</p>

---

## 📄 License

MIT
