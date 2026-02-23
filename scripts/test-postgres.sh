#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ ! -f "$PROJECT_DIR/.postgres-password" ]; then
    echo -e "${RED}[ERROR]${NC} PostgreSQL password file not found"
    exit 1
fi

POSTGRES_PASSWORD=$(cat "$PROJECT_DIR/.postgres-password")
POSTGRES_HOST=${1:-localhost}
POSTGRES_PORT=${2:-30432}

echo "Testing PostgreSQL connectivity..."
echo "Host: $POSTGRES_HOST"
echo "Port: $POSTGRES_PORT"
echo ""

export PGPASSWORD="$POSTGRES_PASSWORD"

if psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U appuser -d appdb -c "SELECT version();" 2>/dev/null; then
    echo ""
    echo -e "${GREEN}[SUCCESS]${NC} PostgreSQL connection successful"
    
    echo ""
    echo "Running additional tests..."
    
    psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" -U appuser -d appdb -c "
        CREATE TABLE IF NOT EXISTS connection_test (
            id SERIAL PRIMARY KEY,
            test_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            message VARCHAR(255)
        );
        INSERT INTO connection_test (message) VALUES ('Connection test at $(date)');
        SELECT * FROM connection_test ORDER BY id DESC LIMIT 5;
    "
    
    echo ""
    echo -e "${GREEN}[SUCCESS]${NC} All PostgreSQL tests passed"
else
    echo -e "${RED}[ERROR]${NC} PostgreSQL connection failed"
    exit 1
fi
