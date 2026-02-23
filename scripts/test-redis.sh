#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

if [ ! -f "$PROJECT_DIR/.redis-password" ]; then
    echo -e "${RED}[ERROR]${NC} Redis password file not found"
    exit 1
fi

REDIS_PASSWORD=$(cat "$PROJECT_DIR/.redis-password")
REDIS_HOST=${1:-localhost}
REDIS_PORT=${2:-30379}

echo "Testing Redis connectivity..."
echo "Host: $REDIS_HOST"
echo "Port: $REDIS_PORT"
echo ""

if redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" PING 2>/dev/null | grep -q "PONG"; then
    echo -e "${GREEN}[SUCCESS]${NC} Redis PING successful"
    
    echo ""
    echo "Running additional tests..."
    
    TEST_KEY="test:connection:$(date +%s)"
    TEST_VALUE="Connection test at $(date)"
    
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" SET "$TEST_KEY" "$TEST_VALUE" EX 60 2>/dev/null
    RETRIEVED=$(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" GET "$TEST_KEY" 2>/dev/null)
    
    if [ "$RETRIEVED" == "$TEST_VALUE" ]; then
        echo -e "${GREEN}[SUCCESS]${NC} Redis SET/GET test passed"
    else
        echo -e "${RED}[ERROR]${NC} Redis SET/GET test failed"
        exit 1
    fi
    
    echo ""
    echo "Redis Server Info:"
    redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT" -a "$REDIS_PASSWORD" INFO server 2>/dev/null | grep -E "redis_version|uptime_in_seconds|connected_clients"
    
    echo ""
    echo -e "${GREEN}[SUCCESS]${NC} All Redis tests passed"
else
    echo -e "${RED}[ERROR]${NC} Redis connection failed"
    exit 1
fi
