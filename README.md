# K3s Local Kubernetes Cluster

Local Kubernetes cluster with PostgreSQL, Redis and a sample Login Application.

## Prerequisites

- Ubuntu 24.04 LTS (fresh installation)
- Minimum 4GB RAM, 2 CPU, 40GB Disk
- Internet connection
- Root or sudo access

## Quick Start

```bash
git clone <repository-url>
cd k3s-local-cluster

chmod +x scripts/k3s-project.sh

sudo ./scripts/k3s-project.sh install

sudo ./scripts/k3s-project.sh delete
```

## Architecture

```
+----------------------------------------------------------+
|                    Ubuntu 24.04 VM                        |
|  +----------------------------------------------------+  |
|  |                  K3s Cluster                       |  |
|  |  +-------------+  +-------------+  +------------+  |  |
|  |  |  Namespace  |  |  Namespace  |  | Namespace  |  |  |
|  |  |  postgres   |  |    redis    |  |  login-app |  |  |
|  |  |             |  |             |  |            |  |  |
|  |  | PostgreSQL  |  |   Redis     |  | Flask App  |  |  |
|  |  | (Primary)   |  |  Sentinel   |  | (Web UI)   |  |  |
|  |  | (Replica)   |  |  (Master)   |  |            |  |  |
|  |  |             |  |  (Replica)  |  |            |  |  |
|  |  | CronJob     |  |             |  |            |  |  |
|  |  | (Backup)    |  |             |  |            |  |  |
|  |  +-------------+  +-------------+  +------------+  |  |
|  |                                                    |  |
|  |  +-------------+  +-----------------------------+  |  |
|  |  |  Namespace  |  |        Traefik Ingress      |  |  |
|  |  |  secrets    |  |   (Built-in with k3s)       |  |  |
|  |  |             |  +-----------------------------+  |  |
|  |  | Sealed      |                                   |  |
|  |  | Secrets     |  NodePort: 30432 (PostgreSQL)     |  |
|  |  | Controller  |  NodePort: 30379 (Redis)          |  |
|  |  +-------------+  NodePort: 30080 (Login App)      |  |
|  +----------------------------------------------------+  |
+----------------------------------------------------------+
```

## Components

| Component | Namespace | Access |
|-----------|-----------|--------|
| PostgreSQL | postgres | NodePort 30432 |
| Redis | redis | NodePort 30379 |
| Login App | login-app | NodePort 30080 |
| Sealed Secrets | kube-system | Internal |

## Scripts

| Script | Description |
|--------|-------------|
| `scripts/k3s-project.sh install` | Install entire stack |
| `scripts/k3s-project.sh delete` | Remove entire stack |
| `scripts/test-postgres.sh` | Test PostgreSQL connectivity |
| `scripts/test-redis.sh` | Test Redis connectivity |

## Default Credentials

All credentials are managed via Sealed Secrets. Default values for development:

- PostgreSQL User: `appuser`
- PostgreSQL Database: `appdb`
- Redis: No authentication in dev mode

## Backup

PostgreSQL backups run daily at 02:00 UTC via CronJob. Backups are stored in `/backups` PersistentVolume.

## Migration to Multi-Node

To add worker nodes:

```bash
cat /var/lib/rancher/k3s/server/node-token

curl -sfL https://get.k3s.io | K3S_URL=https://<master-ip>:6443 K3S_TOKEN=<token> sh -
```

## License

MIT
