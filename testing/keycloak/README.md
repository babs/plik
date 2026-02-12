# Keycloak OIDC Testing for Plik

This directory contains a complete test setup for Plik's OIDC authentication using Keycloak.

## Quick Start

### 1. Start Keycloak and auto-configure realm
```bash
./testing/keycloak/run.sh start
```

This will:
- Pull and start Keycloak on port 2607
- Auto-configure realm `plik`, client `plik`, and test user `testuser`

### 2. Build and start Plikd with OIDC
```bash
make
server/plikd --config testing/keycloak/plikd.cfg
```

### 3. Test the login flow
Open http://localhost:8080 in your browser and login with:
- **Username**: `testuser`
- **Password**: `password`

## Configuration Details

### Keycloak
- **URL**: http://localhost:2607
- **Admin Console**: http://localhost:2607 (admin/admin)
- **Realm**: plik
- **Client ID**: plik
- **Client Secret**: plik-secret
- **Test User**: testuser / password

### Plikd OIDC Settings
- **Provider URL**: http://localhost:2607/realms/plik
- **Provider Name**: Keycloak
- **Authentication**: forced (anonymous uploads disabled)
- **Local Login**: disabled (OIDC only)

## Management Commands

```bash
# Check status
./testing/keycloak/run.sh status

# Stop Keycloak
./testing/keycloak/run.sh stop

# Restart Keycloak
./testing/keycloak/run.sh restart
```

## Testing

Unlike other backends (mariadb, postgres, minio, etc.) which run the full test suite with a backend-specific config, keycloak only runs the `TestOIDC*` tests from `plik/z5_e2e_browser_auth_test.go`. This is because keycloak is an auth provider, not a data/metadata backend, and its `plikd.cfg` uses `FeatureAuthentication = "forced"` which would break unrelated tests.

```bash
# Run OIDC tests only (starts keycloak, configures realm, runs tests)
./testing/keycloak/run.sh test

# Or via the test-backends script
./testing/test_backends.sh keycloak
```

Keycloak is included in `make test-backends`, which runs all backend tests including OIDC.

## Notes
- The realm configuration is fully automated via REST API on startup
- DisableLocalLogin is enabled, so only OIDC login is available
- Domain validation is disabled by default (OIDCValidDomains is commented out)
