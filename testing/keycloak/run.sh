#!/bin/bash

set -e
cd "$(dirname "$0")"

BACKEND="keycloak"
CMD=$1
TEST=$2

source ../utils.sh
check_docker_connectivity

DOCKER_VERSION=${DOCKER_VERSION-latest}
DOCKER_IMAGE="quay.io/keycloak/keycloak:$DOCKER_VERSION"
DOCKER_NAME="plik.keycloak"
DOCKER_PORT=2607
ADMIN_USER="admin"
ADMIN_PASSWORD="admin"

function start {
    if status ; then
        echo "ALREADY RUNNING"
    else
        pull_docker_image

        echo -e "\n - Starting $DOCKER_NAME\n"

        docker run -d -p "$DOCKER_PORT:8080" \
            -e KEYCLOAK_ADMIN="$ADMIN_USER" \
            -e KEYCLOAK_ADMIN_PASSWORD="$ADMIN_PASSWORD" \
            --name "$DOCKER_NAME" "$DOCKER_IMAGE" \
            start-dev \
            --hostname=http://localhost:$DOCKER_PORT

        echo "waiting for keycloak to start ..."
        sleep 5
        if ! status ; then
            echo "IMAGE IS NOT RUNNING"
            exit 1
        fi

        # Wait for Keycloak to be fully ready (use OIDC discovery as health check, /health/ready needs --health-enabled)
        echo "waiting for keycloak to be ready ..."
        for i in {1..30}; do
            if curl -f -s "http://localhost:$DOCKER_PORT/realms/master/.well-known/openid-configuration" > /dev/null 2>&1; then
                echo "Keycloak is ready!"
                break
            fi
            echo "  still waiting... ($i/30)"
            sleep 2
        done

        # Configure Keycloak
        echo -e "\n - Configuring Keycloak realm and client\n"
        configure_keycloak
    fi
}

function configure_keycloak {
    # Get admin token
    TOKEN=$(curl -s -X POST "http://localhost:$DOCKER_PORT/realms/master/protocol/openid-connect/token" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=$ADMIN_USER" \
        -d "password=$ADMIN_PASSWORD" \
        -d "grant_type=password" \
        -d "client_id=admin-cli" | jq -r '.access_token')

    if [ -z "$TOKEN" ] || [ "$TOKEN" = "null" ]; then
        echo "Failed to get admin token"
        exit 1
    fi

    # Create realm
    echo "Creating realm 'plik'..."
    curl -s -X POST "http://localhost:$DOCKER_PORT/admin/realms" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "realm": "plik",
            "enabled": true,
            "displayName": "Plik"
        }' || echo "Realm may already exist"

    # Create client
    echo "Creating client 'plik'..."
    curl -s -X POST "http://localhost:$DOCKER_PORT/admin/realms/plik/clients" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "clientId": "plik",
            "enabled": true,
            "publicClient": false,
            "secret": "plik-secret",
            "redirectUris": ["http://localhost:8080/*", "http://127.0.0.1:44142/*"],
            "webOrigins": ["http://localhost:8080"],
            "protocol": "openid-connect",
            "standardFlowEnabled": true,
            "directAccessGrantsEnabled": false
        }' || echo "Client may already exist"

    # Create test user
    echo "Creating test user 'testuser'..."
    curl -s -X POST "http://localhost:$DOCKER_PORT/admin/realms/plik/users" \
        -H "Authorization: Bearer $TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
            "username": "testuser",
            "enabled": true,
            "email": "testuser@example.com",
            "firstName": "Test",
            "lastName": "User",
            "emailVerified": true
        }' || echo "User may already exist"

    # Get user ID
    USER_ID=$(curl -s -X GET "http://localhost:$DOCKER_PORT/admin/realms/plik/users?username=testuser" \
        -H "Authorization: Bearer $TOKEN" | jq -r '.[0].id')

    if [ -n "$USER_ID" ] && [ "$USER_ID" != "null" ]; then
        # Set user password
        echo "Setting password for test user..."
        curl -s -X PUT "http://localhost:$DOCKER_PORT/admin/realms/plik/users/$USER_ID/reset-password" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Content-Type: application/json" \
            -d '{
                "type": "password",
                "value": "password",
                "temporary": false
            }'
    fi

    echo -e "\nKeycloak configured successfully!"
    echo "Realm: plik"
    echo "Client ID: plik"
    echo "Client Secret: plik-secret"
    echo "Test User: testuser / password"
    echo "Keycloak Admin Console: http://localhost:$DOCKER_PORT (admin/admin)"
}

# Override run_tests from utils.sh to only run OIDC-specific tests.
# Keycloak is an auth provider, not a data/metadata backend,
# so we only run the OIDC test functions.
function run_tests {
    export PLIKD_CONFIG="$ROOT/testing/$BACKEND/plikd.cfg"
    ( cd "$ROOT/plik" && GORACE="halt_on_error=1" go test -count=1 -v -race -run "TestOIDC" ./... )
}

run_cmd
