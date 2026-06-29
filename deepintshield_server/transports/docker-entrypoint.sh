#!/bin/sh
set -e

# Function to fix permissions on mounted volumes
fix_permissions() {
    # Check if /app/data exists and fix ownership if needed
    if [ -d "/app/data" ]; then
        # Get current user info
        CURRENT_UID=$(id -u)
        CURRENT_GID=$(id -g)
        
        # Get directory ownership
        DATA_UID=$(stat -c '%u' /app/data 2>/dev/null || echo "0")
        DATA_GID=$(stat -c '%g' /app/data 2>/dev/null || echo "0")
        
        # If ownership doesn't match current user, try to fix it
        if [ "$DATA_UID" != "$CURRENT_UID" ] || [ "$DATA_GID" != "$CURRENT_GID" ]; then
            echo "Fixing permissions on /app/data (was $DATA_UID:$DATA_GID, setting to $CURRENT_UID:$CURRENT_GID)"
            
            # Try to change ownership (will work if running as root or if user has permission)
            if chown -R "$CURRENT_UID:$CURRENT_GID" /app/data 2>/dev/null; then
                echo "Successfully updated permissions on /app/data"
            else
                echo "Warning: Could not change ownership of /app/data. You may need to run:"
                echo "  docker run --user \$(id -u):\$(id -g) ..."
                echo "  or ensure the host directory is owned by UID:GID $CURRENT_UID:$CURRENT_GID"
            fi
        fi
        
        # Ensure logs subdirectory exists with correct permissions
        mkdir -p /app/data/logs
        chmod 755 /app/data/logs 2>/dev/null || true
    fi
}

# Fix permissions before starting the application
fix_permissions

# Materialize config.json from an environment variable or mounted source file.
# This keeps local file-based deployments and secret-driven container deployments aligned.
write_runtime_config() {
    CONFIG_PATH="${APP_DIR:-/app/data}/config.json"
    CONFIG_INLINE="${DEEPINTSHIELD_CONFIG:-$DEEPINTSHIELD_CONFIG}"
    CONFIG_FILE_PATH="${DEEPINTSHIELD_CONFIG_FILE:-$DEEPINTSHIELD_CONFIG_FILE}"

    if [ -n "$CONFIG_INLINE" ]; then
        mkdir -p "$(dirname "$CONFIG_PATH")"
        printf '%s' "$CONFIG_INLINE" > "$CONFIG_PATH"
        chmod 600 "$CONFIG_PATH" 2>/dev/null || true
        return
    fi

    if [ -n "$CONFIG_FILE_PATH" ]; then
        if [ ! -f "$CONFIG_FILE_PATH" ]; then
            echo "Error: DEEPINTSHIELD_CONFIG_FILE does not exist: $CONFIG_FILE_PATH" >&2
            exit 1
        fi
        mkdir -p "$(dirname "$CONFIG_PATH")"
        cp "$CONFIG_FILE_PATH" "$CONFIG_PATH"
        chmod 600 "$CONFIG_PATH" 2>/dev/null || true
    fi
}

# Materialize runtime config before parsing args or launching the app.
write_runtime_config

# Bring up the bundled redis-stack (RediSearch) so the semantic cache has a
# vector store, then point the gateway at it. Best-effort: if it can't start, we
# log and continue - the gateway degrades to no semantic cache rather than
# failing to boot. Skipped entirely when an external Redis is supplied.
start_bundled_redis() {
    if [ -n "$DEEPINTSHIELD_REDIS_ADDR" ]; then
        return
    fi
    if ! command -v redis-stack-server >/dev/null 2>&1; then
        echo "deepintshield: redis-stack-server not present in image; semantic cache disabled" >&2
        return
    fi
    # Persist the vector store in the mounted data volume (alongside config.db /
    # logs.db) so the semantic cache survives container restarts.
    mkdir -p "${APP_DIR:-/app/data}/redis"
    redis-stack-server --dir "${APP_DIR:-/app/data}/redis" --daemonize no >/tmp/redis-stack.log 2>&1 &
    i=0
    while [ "$i" -lt 30 ]; do
        if redis-cli ping 2>/dev/null | grep -q PONG; then
            export DEEPINTSHIELD_REDIS_ADDR="localhost:6379"
            export DEEPINTSHIELD_REDIS_DB="${DEEPINTSHIELD_REDIS_DB:-0}"
            echo "deepintshield: bundled redis-stack ready on :6379 (semantic cache enabled)"
            return
        fi
        i=$((i + 1))
        sleep 1
    done
    echo "deepintshield: bundled Redis did not become ready; semantic cache disabled for this run" >&2
}

start_bundled_redis

# Parse command line arguments and set environment variables
parse_args() {
    while [ $# -gt 0 ]; do
        case $1 in
            --port|-port)
                if [ -n "$2" ]; then
                    export APP_PORT="$2"
                    shift 2
                else
                    echo "Error: --port requires a value"
                    exit 1
                fi
                ;;
            --host|-host)
                if [ -n "$2" ]; then
                    export APP_HOST="$2"
                    shift 2
                else
                    echo "Error: --host requires a value"
                    exit 1
                fi
                ;;
            *)
                # Keep other arguments for the main application
                set -- "$@" "$1"
                shift
                ;;
        esac
    done
}

# Parse arguments if any are provided
if [ $# -gt 1 ]; then
    parse_args "$@"
fi

# Build the command with environment variables and standard arguments
exec /app/main -app-dir "$APP_DIR" -port "$APP_PORT" -host "$APP_HOST" -log-level "$LOG_LEVEL" -log-style "$LOG_STYLE"
