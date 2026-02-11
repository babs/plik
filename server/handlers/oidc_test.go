package handlers

import (
	"bytes"
	gocontext "context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/root-gg/plik/server/common"
	"github.com/root-gg/plik/server/context"
)

var oidcOAuth2TestEndpoint = oauth2.Endpoint{
	AuthURL:  "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort),
	TokenURL: "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort) + "/token",
}

var oidcUserinfoTestEndpoint = "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort) + "/userinfo"

var oidcTestDiscovery = oidcDiscovery{
	AuthorizationEndpoint: "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort) + "/authorize",
	TokenEndpoint:         "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort) + "/token",
	UserinfoEndpoint:      "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort) + "/userinfo",
}

var oidcTestOAuthToken = struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int32  `json:"expires_in"`
}{
	AccessToken:  "access_token",
	TokenType:    "token_type",
	RefreshToken: "refresh_token",
	ExpiresIn:    300,
}

func oidcMockHandler(user oidcUserInfo) http.HandlerFunc {
	return func(resp http.ResponseWriter, req *http.Request) {
		var responseBody []byte
		switch req.URL.Path {
		case "/.well-known/openid-configuration":
			responseBody, _ = json.Marshal(oidcTestDiscovery)
		case "/token":
			responseBody, _ = json.Marshal(oidcTestOAuthToken)
		case "/userinfo":
			responseBody, _ = json.Marshal(user)
		default:
			resp.WriteHeader(http.StatusInternalServerError)
			return
		}
		resp.Header().Set("Content-Type", "application/json")
		resp.Write(responseBody)
	}
}

func setupOIDCConfig(config *common.Configuration) {
	config.FeatureAuthentication = common.FeatureEnabled
	config.OIDCAuthentication = true
	config.OIDCClientID = "oidc_client_id"
	config.OIDCClientSecret = "oidc_client_secret"
	config.OIDCProviderURL = "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort)
}

func oidcTestState(t *testing.T, secret string) string {
	t.Helper()
	state := jwt.New(jwt.SigningMethodHS256)
	state.Claims.(jwt.MapClaims)["redirectURL"] = "https://plik.root.gg/auth/oidc/callback"
	state.Claims.(jwt.MapClaims)["expire"] = time.Now().Add(5 * time.Minute).Unix()
	b64state, err := state.SignedString([]byte(secret))
	require.NoError(t, err, "unable to sign state")
	return b64state
}

func oidcCallbackRequest(t *testing.T, state string) *http.Request {
	t.Helper()
	req, err := http.NewRequest("GET", "/auth/oidc/callback?code=code&state="+url.QueryEscape(state), bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")
	reqCtx := gocontext.WithValue(gocontext.TODO(), oidcEndpointContextKey, oidcOAuth2TestEndpoint)
	reqCtx = gocontext.WithValue(reqCtx, oidcUserinfoContextKey, oidcUserinfoTestEndpoint)
	req = req.WithContext(reqCtx)
	return req
}

func TestOIDCLogin(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUserInfo{}))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req, err := http.NewRequest("GET", "/auth/oidc/login", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	origin := "https://plik.root.gg"
	req.Header.Set("referer", origin)

	rr := ctx.NewRecorder(req)
	OIDCLogin(ctx, rr, req)

	context.TestOK(t, rr)

	respBody, err := io.ReadAll(rr.Body)
	require.NoError(t, err, "unable to read response body")
	require.NotEqual(t, 0, len(respBody), "invalid empty response body")

	URL, err := url.Parse(string(respBody))
	require.NoError(t, err, "unable to parse OIDC auth url")

	state, err := jwt.Parse(URL.Query().Get("state"), func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			t.Fatalf("Unexpected signing method: %v", token.Header["alg"])
		}

		if expire, ok := token.Claims.(jwt.MapClaims)["expire"]; ok {
			if _, ok = expire.(float64); ok {
				if time.Now().Unix() > (int64)(expire.(float64)) {
					t.Fatal("state expired")
				}
			} else {
				t.Fatal("invalid state expiration date")
			}
		} else {
			t.Fatal("Missing state expiration date")
		}

		return []byte(ctx.GetConfig().OIDCClientSecret), nil
	})
	require.NoError(t, err, "invalid oauth2 state")

	require.Equal(t, origin+"/auth/oidc/callback", state.Claims.(jwt.MapClaims)["redirectURL"].(string), "invalid state origin")
}

func TestOIDCLoginAuthDisabled(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	ctx.GetConfig().FeatureAuthentication = common.FeatureDisabled
	ctx.GetConfig().OIDCAuthentication = false

	req, err := http.NewRequest("GET", "/auth/oidc/login", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCLogin(ctx, rr, req)

	context.TestBadRequest(t, rr, "authentication is disabled")
}

func TestOIDCLoginOIDCDisabled(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	ctx.GetConfig().FeatureAuthentication = common.FeatureEnabled
	ctx.GetConfig().OIDCAuthentication = false

	req, err := http.NewRequest("GET", "/auth/oidc/login", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	req.Header.Set("referer", "http://plik.root.gg")

	rr := ctx.NewRecorder(req)
	OIDCLogin(ctx, rr, req)

	context.TestBadRequest(t, rr, "OIDC authentication is disabled")
}

func TestOIDCLoginMissingReferer(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	ctx.GetConfig().FeatureAuthentication = common.FeatureEnabled
	ctx.GetConfig().OIDCAuthentication = true

	req, err := http.NewRequest("GET", "/auth/oidc/login", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCLogin(ctx, rr, req)

	context.TestBadRequest(t, rr, "missing referer header")
}

func TestOIDCCallbackAuthDisabled(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	ctx.GetConfig().FeatureAuthentication = common.FeatureDisabled

	req, err := http.NewRequest("GET", "/auth/oidc/callback", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "authentication is disabled")
}

func TestOIDCCallbackOIDCDisabled(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())

	ctx.GetConfig().FeatureAuthentication = common.FeatureEnabled
	ctx.GetConfig().OIDCAuthentication = false

	req, err := http.NewRequest("GET", "/auth/oidc/callback", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "OIDC authentication is disabled")
}

func TestOIDCCallbackMissingCode(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	req, err := http.NewRequest("GET", "/auth/oidc/callback", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "missing oauth2 authorization code")
}

func TestOIDCCallbackMissingState(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	req, err := http.NewRequest("GET", "/auth/oidc/callback?code=code", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "missing oauth2 authorization state")
}

func TestOIDCCallbackInvalidState(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	req, err := http.NewRequest("GET", "/auth/oidc/callback?code=code&state=state", bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "invalid oauth2 state")
}

func TestOIDCCallbackExpiredState(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	state := jwt.New(jwt.SigningMethodHS256)
	state.Claims.(jwt.MapClaims)["expire"] = time.Now().Add(-5 * time.Minute).Unix()

	b64state, err := state.SignedString([]byte(ctx.GetConfig().OIDCClientSecret))
	require.NoError(t, err, "unable to sign state")

	req, err := http.NewRequest("GET", "/auth/oidc/callback?code=code&state="+url.QueryEscape(b64state), bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "invalid oauth2 state")
}

func TestOIDCCallbackInvalidRedirectURL(t *testing.T) {
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	state := jwt.New(jwt.SigningMethodHS256)
	state.Claims.(jwt.MapClaims)["redirectURL"] = "https://evil.com/steal"
	state.Claims.(jwt.MapClaims)["expire"] = time.Now().Add(5 * time.Minute).Unix()

	b64state, err := state.SignedString([]byte(ctx.GetConfig().OIDCClientSecret))
	require.NoError(t, err, "unable to sign state")

	req, err := http.NewRequest("GET", "/auth/oidc/callback?code=code&state="+url.QueryEscape(b64state), bytes.NewBuffer([]byte{}))
	require.NoError(t, err, "unable to create new request")

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestBadRequest(t, rr, "invalid redirectURL")
}

func TestOIDCCallback(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	oidcUser := oidcUserInfo{
		Sub:   "user123",
		Email: "plik@root.gg",
		Name:  "plik.root.gg",
	}

	user := common.NewUser(common.ProviderOIDC, "user123")
	user.Login = oidcUser.Sub
	user.Name = oidcUser.Name
	user.Email = oidcUser.Email
	err := ctx.GetMetadataBackend().CreateUser(user)
	require.NoError(t, err, "unable to create test user")

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	require.Equal(t, 301, rr.Code, "handler returned wrong status code")

	respBody, err := io.ReadAll(rr.Body)
	require.NoError(t, err, "unable to read response body")
	require.NotEqual(t, 0, len(respBody), "invalid empty response body")

	var sessionCookie string
	var xsrfCookie string
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "plik-session" {
			sessionCookie = cookie.Value
		}
		if cookie.Name == "plik-xsrf" {
			xsrfCookie = cookie.Value
		}
	}

	require.NotEqual(t, "", sessionCookie, "missing plik session cookie")
	require.NotEqual(t, "", xsrfCookie, "missing plik xsrf cookie")
}

func TestOIDCCallbackCreateUser(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	oidcUser := oidcUserInfo{
		Sub:   "user456",
		Email: "newuser@root.gg",
		Name:  "New User",
	}

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	require.Equal(t, 301, rr.Code, "handler returned wrong status code")

	respBody, err := io.ReadAll(rr.Body)
	require.NoError(t, err, "unable to read response body")
	require.NotEqual(t, 0, len(respBody), "invalid empty response body")

	var sessionCookie string
	var xsrfCookie string
	for _, cookie := range rr.Result().Cookies() {
		if cookie.Name == "plik-session" {
			sessionCookie = cookie.Value
		}
		if cookie.Name == "plik-xsrf" {
			xsrfCookie = cookie.Value
		}
	}

	require.NotEqual(t, "", sessionCookie, "missing plik session cookie")
	require.NotEqual(t, "", xsrfCookie, "missing plik xsrf cookie")

	user, err := ctx.GetMetadataBackend().GetUser("oidc:user456")
	require.NoError(t, err)
	require.NotNil(t, user, "missing user")
	require.Equal(t, oidcUser.Email, user.Email, "invalid user email")
	require.Equal(t, oidcUser.Name, user.Name, "invalid user name")
}

func TestOIDCCallbackCreateUserNotWhitelisted(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	ctx.SetWhitelisted(false)
	setupOIDCConfig(ctx.GetConfig())

	oidcUser := oidcUserInfo{
		Sub:   "user789",
		Email: "blocked@root.gg",
		Name:  "Blocked User",
	}

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestForbidden(t, rr, "unable to create user from untrusted source IP address")
}

func TestOIDCCallbackUpdateUserFields(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())

	user := common.NewUser(common.ProviderOIDC, "updateuser")
	user.Login = "updateuser"
	user.Name = "Old Name"
	user.Email = "old@root.gg"
	err := ctx.GetMetadataBackend().CreateUser(user)
	require.NoError(t, err, "unable to create test user")

	oidcUser := oidcUserInfo{
		Sub:              "updateuser",
		Email:            "new@root.gg",
		Name:             "New Name",
		PreferredUsername: "newlogin",
	}

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	require.Equal(t, 301, rr.Code, "handler returned wrong status code")

	updated, err := ctx.GetMetadataBackend().GetUser("oidc:updateuser")
	require.NoError(t, err)
	require.NotNil(t, updated, "missing user")
	require.Equal(t, "new@root.gg", updated.Email, "email not updated")
	require.Equal(t, "New Name", updated.Name, "name not updated")
	require.Equal(t, "newlogin", updated.Login, "login not updated")
}

func TestOIDCCallbackInvalidDomain(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())
	ctx.GetConfig().OIDCValidDomains = []string{"allowed.com"}

	oidcUser := oidcUserInfo{
		Sub:   "domainuser",
		Email: "user@forbidden.com",
		Name:  "Domain User",
	}

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestForbidden(t, rr, "unauthorized domain name")
}

func TestOIDCCallbackExistingUserInvalidDomain(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())
	ctx.GetConfig().OIDCValidDomains = []string{"allowed.com"}

	oidcUser := oidcUserInfo{
		Sub:   "existinguser",
		Email: "user@revoked.com",
		Name:  "Existing User",
	}

	user := common.NewUser(common.ProviderOIDC, "existinguser")
	user.Login = oidcUser.Sub
	user.Name = oidcUser.Name
	user.Email = oidcUser.Email
	err := ctx.GetMetadataBackend().CreateUser(user)
	require.NoError(t, err, "unable to create test user")

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestForbidden(t, rr, "unauthorized domain name")
}

func TestOIDCCallbackDomainValidationNoEmail(t *testing.T) {
	ResetOIDCDiscoveryCache()
	ctx := newTestingContext(common.NewConfiguration())
	setupOIDCConfig(ctx.GetConfig())
	ctx.GetConfig().OIDCValidDomains = []string{"allowed.com"}

	oidcUser := oidcUserInfo{
		Sub:  "noemail_user",
		Name: "No Email User",
	}

	shutdown, err := common.StartAPIMockServer(oidcMockHandler(oidcUser))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	req := oidcCallbackRequest(t, oidcTestState(t, ctx.GetConfig().OIDCClientSecret))

	rr := ctx.NewRecorder(req)
	OIDCCallback(ctx, rr, req)

	context.TestForbidden(t, rr, "email is required when domain validation is enabled")
}

func TestDiscoverOIDCCache(t *testing.T) {
	ResetOIDCDiscoveryCache()

	var fetchCount atomic.Int32
	handler := func(resp http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/.well-known/openid-configuration" {
			fetchCount.Add(1)
			responseBody, _ := json.Marshal(oidcTestDiscovery)
			resp.Header().Set("Content-Type", "application/json")
			resp.Write(responseBody)
			return
		}
		resp.WriteHeader(http.StatusInternalServerError)
	}

	shutdown, err := common.StartAPIMockServer(http.HandlerFunc(handler))
	defer shutdown()
	require.NoError(t, err, "unable to start mock server")

	providerURL := "http://127.0.0.1:" + strconv.Itoa(common.APIMockServerDefaultPort)

	// First call: cache miss, should fetch
	d1, err := discoverOIDC(providerURL)
	require.NoError(t, err)
	require.NotNil(t, d1)
	require.Equal(t, int32(1), fetchCount.Load(), "expected one fetch on cache miss")

	// Second call: cache hit, no fetch
	d2, err := discoverOIDC(providerURL)
	require.NoError(t, err)
	require.Equal(t, d1, d2)
	require.Equal(t, int32(1), fetchCount.Load(), "expected no additional fetch on cache hit")

	// Expire cache manually
	oidcDiscoveryMu.Lock()
	oidcDiscoveryCache.fetchedAt = time.Now().Add(-2 * oidcDiscoveryCacheTTL)
	oidcDiscoveryMu.Unlock()

	// Third call: stale-while-revalidate returns stale value, triggers background refresh
	d3, err := discoverOIDC(providerURL)
	require.NoError(t, err)
	require.NotNil(t, d3)

	// Wait for background goroutine to complete the refresh
	require.Eventually(t, func() bool {
		return fetchCount.Load() == int32(2)
	}, 5*time.Second, 10*time.Millisecond, "expected background re-fetch after cache expiry")

	// Fourth call: should return fresh cached value without another fetch
	d4, err := discoverOIDC(providerURL)
	require.NoError(t, err)
	require.NotNil(t, d4)
	require.Equal(t, int32(2), fetchCount.Load(), "expected no additional fetch after refresh")
}
