package handlers

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/oauth2"

	"github.com/root-gg/plik/server/common"
	"github.com/root-gg/plik/server/context"
)

var oidcEndpointContextKey = "oidc_endpoint"
var oidcUserinfoContextKey = "oidc_userinfo_endpoint"

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

const oidcHTTPTimeout = 10 * time.Second
const oidcDiscoveryCacheTTL = 1 * time.Hour
const oidcMaxResponseSize = 1 << 20 // 1MB

var oidcHTTPClient = &http.Client{Timeout: oidcHTTPTimeout}

// Separate client for userinfo: no redirects to avoid leaking Bearer token
var oidcUserinfoHTTPClient = &http.Client{
	Timeout: oidcHTTPTimeout,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type oidcDiscoveryEntry struct {
	discovery   *oidcDiscovery
	providerURL string
	fetchedAt   time.Time
}

var (
	oidcDiscoveryCache      *oidcDiscoveryEntry
	oidcDiscoveryMu         sync.Mutex
	oidcDiscoveryRefreshing bool
)

func fetchOIDCDiscovery(providerURL string) (*oidcDiscovery, error) {
	discoveryURL := strings.TrimRight(providerURL, "/") + "/.well-known/openid-configuration"
	resp, err := oidcHTTPClient.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("unable to fetch OIDC discovery document: %s", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OIDC discovery endpoint returned status %d", resp.StatusCode)
	}

	var discovery oidcDiscovery
	if err := json.NewDecoder(io.LimitReader(resp.Body, oidcMaxResponseSize)).Decode(&discovery); err != nil {
		return nil, fmt.Errorf("unable to parse OIDC discovery document: %s", err)
	}

	if discovery.AuthorizationEndpoint == "" || discovery.TokenEndpoint == "" || discovery.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery document missing required endpoints")
	}

	return &discovery, nil
}

// InitOIDCDiscovery fetches the OIDC discovery document at startup.
// Fails fast if the provider is unreachable or misconfigured.
func InitOIDCDiscovery(providerURL string) error {
	_, err := discoverOIDC(providerURL)
	return err
}

// discoverOIDC fetches and caches the OIDC discovery document.
// Stale-while-revalidate: returns stale cached value immediately while
// a single background goroutine refreshes. Only the cold start (no cache)
// fetches synchronously.
func discoverOIDC(providerURL string) (*oidcDiscovery, error) {
	oidcDiscoveryMu.Lock()
	cached := oidcDiscoveryCache
	if cached != nil && cached.providerURL == providerURL {
		if time.Since(cached.fetchedAt) < oidcDiscoveryCacheTTL {
			oidcDiscoveryMu.Unlock()
			return cached.discovery, nil
		}
		// Stale: return immediately, trigger single background refresh
		if !oidcDiscoveryRefreshing {
			oidcDiscoveryRefreshing = true
			go refreshOIDCDiscovery(providerURL)
		}
		oidcDiscoveryMu.Unlock()
		return cached.discovery, nil
	}
	oidcDiscoveryMu.Unlock()

	// Cold start: synchronous fetch
	discovery, err := fetchOIDCDiscovery(providerURL)
	if err != nil {
		return nil, err
	}

	oidcDiscoveryMu.Lock()
	oidcDiscoveryCache = &oidcDiscoveryEntry{
		discovery:   discovery,
		providerURL: providerURL,
		fetchedAt:   time.Now(),
	}
	oidcDiscoveryMu.Unlock()

	return discovery, nil
}

func refreshOIDCDiscovery(providerURL string) {
	discovery, err := fetchOIDCDiscovery(providerURL)
	oidcDiscoveryMu.Lock()
	defer oidcDiscoveryMu.Unlock()
	oidcDiscoveryRefreshing = false
	if err == nil {
		oidcDiscoveryCache = &oidcDiscoveryEntry{
			discovery:   discovery,
			providerURL: providerURL,
			fetchedAt:   time.Now(),
		}
	}
}

// ResetOIDCDiscoveryCache resets the cached OIDC discovery document (for testing)
func ResetOIDCDiscoveryCache() {
	oidcDiscoveryMu.Lock()
	defer oidcDiscoveryMu.Unlock()
	oidcDiscoveryCache = nil
	oidcDiscoveryRefreshing = false
}

// OIDCLogin return OIDC provider user consent URL.
func OIDCLogin(ctx *context.Context, resp http.ResponseWriter, req *http.Request) {
	config := ctx.GetConfig()

	if config.FeatureAuthentication == common.FeatureDisabled {
		ctx.BadRequest("authentication is disabled")
		return
	}

	if !config.OIDCAuthentication {
		ctx.BadRequest("OIDC authentication is disabled")
		return
	}

	redirectURL, err := getRedirectURL(ctx, "/auth/oidc/callback")
	if err != nil {
		handleHTTPError(ctx, err)
		return
	}

	discovery, err := discoverOIDC(config.OIDCProviderURL)
	if err != nil {
		ctx.InternalServerError("unable to discover OIDC endpoints", err)
		return
	}

	conf := &oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}

	state := jwt.New(jwt.SigningMethodHS256)
	state.Claims.(jwt.MapClaims)["redirectURL"] = redirectURL
	state.Claims.(jwt.MapClaims)["expire"] = time.Now().Add(time.Minute * 5).Unix()

	b64state, err := state.SignedString([]byte(config.OIDCClientSecret))
	if err != nil {
		ctx.InternalServerError("unable to sign state", err)
		return
	}

	url := conf.AuthCodeURL(b64state)

	_, _ = resp.Write([]byte(url))
}

type oidcUserInfo struct {
	Sub              string `json:"sub"`
	Email            string `json:"email"`
	Name             string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

// OIDCCallback authenticate OIDC user.
func OIDCCallback(ctx *context.Context, resp http.ResponseWriter, req *http.Request) {
	config := ctx.GetConfig()

	if config.FeatureAuthentication == common.FeatureDisabled {
		ctx.BadRequest("authentication is disabled")
		return
	}

	if !config.OIDCAuthentication {
		ctx.BadRequest("OIDC authentication is disabled")
		return
	}

	code := req.URL.Query().Get("code")
	if code == "" {
		ctx.MissingParameter("oauth2 authorization code")
		return
	}

	b64state := req.URL.Query().Get("state")
	if b64state == "" {
		ctx.MissingParameter("oauth2 authorization state")
		return
	}

	state, err := jwt.Parse(b64state, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		if expire, ok := token.Claims.(jwt.MapClaims)["expire"]; ok {
			if _, ok = expire.(float64); ok {
				if time.Now().Unix() > (int64)(expire.(float64)) {
					return nil, fmt.Errorf("state has expired")
				}
			} else {
				return nil, fmt.Errorf("invalid expiration date")
			}
		} else {
			return nil, fmt.Errorf("missing expiration date")
		}

		return []byte(config.OIDCClientSecret), nil
	})
	if err != nil {
		ctx.InvalidParameter("oauth2 state : %s", err)
		return
	}

	if _, ok := state.Claims.(jwt.MapClaims)["redirectURL"]; !ok {
		ctx.InvalidParameter("oauth2 state : missing redirectURL")
		return
	}

	if _, ok := state.Claims.(jwt.MapClaims)["redirectURL"].(string); !ok {
		ctx.InvalidParameter("oauth2 state : invalid redirectURL")
		return
	}

	redirectURL := state.Claims.(jwt.MapClaims)["redirectURL"].(string)

	parsedRedirectURL, err := url.Parse(redirectURL)
	if err != nil || !strings.HasSuffix(parsedRedirectURL.Path, "/auth/oidc/callback") {
		ctx.InvalidParameter("oauth2 state : invalid redirectURL")
		return
	}

	discovery, err := discoverOIDC(config.OIDCProviderURL)
	if err != nil {
		ctx.InternalServerError("unable to discover OIDC endpoints", err)
		return
	}

	conf := &oauth2.Config{
		ClientID:     config.OIDCClientID,
		ClientSecret: config.OIDCClientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  discovery.AuthorizationEndpoint,
			TokenURL: discovery.TokenEndpoint,
		},
	}

	userinfoEndpoint := discovery.UserinfoEndpoint

	// For testing purpose
	if customEndpoint := req.Context().Value(oidcEndpointContextKey); customEndpoint != nil {
		conf.Endpoint = customEndpoint.(oauth2.Endpoint)
	}
	if customUserinfo := req.Context().Value(oidcUserinfoContextKey); customUserinfo != nil {
		userinfoEndpoint = customUserinfo.(string)
	}

	token, err := conf.Exchange(req.Context(), code)
	if err != nil {
		ctx.InternalServerError("unable to exchange OIDC authorization code", err)
		return
	}

	userinfoReq, err := http.NewRequestWithContext(req.Context(), "GET", userinfoEndpoint, nil)
	if err != nil {
		ctx.InternalServerError("unable to create userinfo request", err)
		return
	}
	userinfoReq.Header.Set("Authorization", "Bearer "+token.AccessToken)

	userinfoResp, err := oidcUserinfoHTTPClient.Do(userinfoReq)
	if err != nil {
		ctx.InternalServerError("unable to fetch OIDC userinfo", err)
		return
	}
	defer userinfoResp.Body.Close()

	if userinfoResp.StatusCode != http.StatusOK {
		ctx.InternalServerError("OIDC userinfo endpoint returned unexpected status", fmt.Errorf("status %d", userinfoResp.StatusCode))
		return
	}

	var userInfo oidcUserInfo
	if err := json.NewDecoder(io.LimitReader(userinfoResp.Body, oidcMaxResponseSize)).Decode(&userInfo); err != nil {
		ctx.InternalServerError("unable to parse OIDC userinfo", err)
		return
	}

	// Determine user identifier
	providerID := userInfo.Sub
	if providerID == "" {
		providerID = userInfo.Email
	}
	if providerID == "" {
		ctx.InternalServerError("OIDC userinfo missing sub and email", nil)
		return
	}

	// Intentional: validate domain on every login (not just creation) to revoke access when allowed domains change
	if len(config.OIDCValidDomains) > 0 {
		if userInfo.Email == "" {
			ctx.Forbidden("email is required when domain validation is enabled")
			return
		}
		components := strings.Split(userInfo.Email, "@")
		if len(components) != 2 {
			ctx.Forbidden("invalid email address")
			return
		}
		goodDomain := false
		for _, validDomain := range config.OIDCValidDomains {
			if strings.EqualFold(components[1], validDomain) {
				goodDomain = true
				break
			}
		}
		if !goodDomain {
			ctx.Forbidden("unauthorized domain name")
			return
		}
	}

	user, err := ctx.GetMetadataBackend().GetUser(common.GetUserID(common.ProviderOIDC, providerID))
	if err != nil {
		ctx.InternalServerError("unable to get user from metadata backend", err)
		return
	}

	if user == nil {
		if ctx.IsWhitelisted() {
			user = common.NewUser(common.ProviderOIDC, providerID)
			user.Login = providerID
			if userInfo.PreferredUsername != "" {
				user.Login = userInfo.PreferredUsername
			}
			if userInfo.Name != "" {
				user.Name = userInfo.Name
			}
			user.Email = userInfo.Email

			err = ctx.GetMetadataBackend().CreateUser(user)
			if err != nil {
				ctx.InternalServerError("unable to create user : %s", err)
				return
			}
		} else {
			ctx.Forbidden("unable to create user from untrusted source IP address")
			return
		}
	} else {
		updated := false
		if userInfo.Email != "" && user.Email != userInfo.Email {
			user.Email = userInfo.Email
			updated = true
		}
		if userInfo.Name != "" && user.Name != userInfo.Name {
			user.Name = userInfo.Name
			updated = true
		}
		if userInfo.PreferredUsername != "" && user.Login != userInfo.PreferredUsername {
			user.Login = userInfo.PreferredUsername
			updated = true
		}
		if updated {
			err = ctx.GetMetadataBackend().UpdateUser(user)
			if err != nil {
				ctx.InternalServerError("unable to update user : %s", err)
				return
			}
		}
	}

	sessionCookie, xsrfCookie, err := ctx.GetAuthenticator().GenAuthCookies(user)
	if err != nil {
		ctx.InternalServerError("unable to generate session cookies", err)
		return
	}
	http.SetCookie(resp, sessionCookie)
	http.SetCookie(resp, xsrfCookie)

	http.Redirect(resp, req, config.Path+"/#/login", http.StatusMovedPermanently)
}
