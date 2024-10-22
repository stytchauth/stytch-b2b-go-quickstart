package main

import (
	"cmp"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/b2bstytchapi"
	b2bdiscovery "github.com/stytchauth/stytch-go/v12/stytch/b2b/discovery"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/discovery/intermediatesessions"
	organizations2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/discovery/organizations"
	discovery2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/magiclinks/discovery"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/magiclinks/email/discovery"
	oauthdiscovery "github.com/stytchauth/stytch-go/v12/stytch/b2b/oauth/discovery"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/organizations"
	sessions2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/sessions"
	"github.com/stytchauth/stytch-go/v12/stytch/methodoptions"
)

var ctx = context.Background()

func main() {
	// Load variables from .env file into the environment.
	if err := godotenv.Load(".env.local"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Instantiate a new API service.
	service := NewAuthService(
		os.Getenv("STYTCH_PROJECT_ID"),
		os.Getenv("STYTCH_SECRET"),
	)

	// Register HTTP handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/", service.indexHandler)
	mux.HandleFunc("/logout", service.logoutHandler)

	mux.HandleFunc("/send-magic-link", service.sendMagicLinkHandler)
	mux.HandleFunc("/authenticate", service.authenticateHandler)
	mux.HandleFunc("/create-organization", service.createOrgHandler)
	mux.HandleFunc("/exchange/{organizationId}", service.exchangeOrgHandler)
	mux.HandleFunc("/switch-orgs", service.switchOrgsHandler)
	mux.HandleFunc("/orgs/{organizationSlug}", service.orgIndexHandler)
	mux.HandleFunc("/enable-jit", service.enableJitHandler)

	// Static assets.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Start server.
	server := http.Server{
		Addr:    ":3000",
		Handler: mux,
	}
	log.Println("WARNING: For testing purposes only. Not intended for production use...")
	log.Println("Starting server on http://localhost:3000")
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

//
// Magic Links Service.
//

type AuthService struct {
	client *b2bstytchapi.API
	store  *sessions.CookieStore
}

func NewAuthService(projectId, secret string) *AuthService {
	client, err := b2bstytchapi.NewClient(projectId, secret)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	return &AuthService{
		client: client,
		store:  sessions.NewCookieStore([]byte("your-secret-key")),
	}
}

//
// Magic Links handlers.
//

func (s *AuthService) indexHandler(w http.ResponseWriter, r *http.Request) {
	// Check for an existing session token in the browser.
	// If one is found, and it corresponds to an active session,
	// redirect the user.
	member, org, ok := s.authenticatedMemberAndOrg(w, r)
	if ok {
		if err := RenderTemplate(w, LoggedIn, &TemplateData{
			Member:       member,
			Organization: org,
		}); err != nil {
			log.Printf("Error rendering template: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	w.Header().Add("Cache-Control", "no-cache, no-store, must-revalidate")
	http.ServeFile(w, r, "templates/discoveryLogin.html")
}

func (s *AuthService) logoutHandler(w http.ResponseWriter, r *http.Request) {
	s.clearSession(w, r, sessionKey)
	s.indexHandler(w, r)
}

// sendMagicLinkHandler is an example of initiating Magic Link authentication.
// Magic Links can be used for "Discovery Sign-up or Login" (no OrgID passed) OR "Organization Login" (with an OrgID passed).
// You can read more about these differences here: https://stytch.com/docs/b2b/guides/login-flows.
// In this example app, we only use Magic Links for Discovery Sign-up or Login.
func (s *AuthService) sendMagicLinkHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	email := r.Form.Get("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

		_, err := s.client.MagicLinks.Email.Discovery.Send(ctx, &discovery.SendParams{
			EmailAddress: email,
		})
		if err != nil {
			log.Printf("Error sending email: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

	log.Println("Successfully sent magic link email")
	http.ServeFile(w, r, "templates/emailSent.html")
}

// authenticateHandler demonstrates completing a multistep authentication flow.
// For these flows Stytch will call the Redirect URL specified in your dashboard
// with an auth token and stytch_token_type that will allow you to complete the flow.
// Read more about Redirect URLs and Token Types here: https://stytch.com/docs/b2b/guides/dashboard/redirect-urls.
func (s *AuthService) authenticateHandler(w http.ResponseWriter, r *http.Request) {
	tokenType := r.URL.Query().Get("stytch_token_type")
	token := r.URL.Query().Get("token")

	var authenticatedEmail string;
	var responseDiscoveredOrgs []b2bdiscovery.DiscoveredOrganization;

	if tokenType == "discovery" {
		resp, err := s.client.MagicLinks.Discovery.Authenticate(ctx, &discovery2.AuthenticateParams{
			DiscoveryMagicLinksToken: token,
		})
		if err != nil {
			fmt.Printf("Error authenticating: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// The intermediate_session_token (IST) allows you to persist authentication state while
		// you present the user with the Organizations they can log into, or the option to create
		// a new Organization.
		s.saveSession(w, r, intermediateSessionKey, resp.IntermediateSessionToken)

		authenticatedEmail = resp.EmailAddress
		responseDiscoveredOrgs = resp.DiscoveredOrganizations
	} else if tokenType == "discovery_oauth" {
		resp, err := s.client.OAuth.Discovery.Authenticate(ctx, &oauthdiscovery.AuthenticateParams{
			DiscoveryOAuthToken: token,
		})
		if err != nil {
			log.Printf("Error authenticating: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		s.saveSession(w, r, intermediateSessionKey, resp.IntermediateSessionToken)

		authenticatedEmail = resp.EmailAddress
		responseDiscoveredOrgs = resp.DiscoveredOrganizations
	} else {
		log.Printf("Error: unrecognized token type %s\n", tokenType)
		http.Error(w, fmt.Sprintf("Unrecognized token type %s", tokenType), http.StatusBadRequest)
		return
	}

	discoveredOrgs := make([]DiscoveredOrganization, len(responseDiscoveredOrgs))
	for i := range responseDiscoveredOrgs {
		discoveredOrgs[i] = DiscoveredOrganization{
			OrganizationId:   responseDiscoveredOrgs[i].Organization.OrganizationID,
			OrganizationName: responseDiscoveredOrgs[i].Organization.OrganizationName,
		}
	}
	// Sort Organizations alphabetically.
	slices.SortFunc(discoveredOrgs, func(a, b DiscoveredOrganization) int {
		return cmp.Compare(a.OrganizationName, b.OrganizationName)
	})

	log.Println("Successfully authenticated with discovery")
	if err := RenderTemplate(w, DiscoveredOrganizations, &TemplateData{
		Email:                   authenticatedEmail,
		IsLogin:                 true,
		DiscoveredOrganizations: discoveredOrgs,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// createOrgHandler is an example of creating a new Organization after Discovery
// authentication.
// To test this, select "Create New Organization" and input a name and slug for your new Org.
// This will then exchange the IST returned from the discovery.authenticate() call, which
// allows Stytch to enforce that users are properly authenticated and verified prior to
// creating an Organization.
func (s *AuthService) createOrgHandler(w http.ResponseWriter, r *http.Request) {
	istSession, _ := s.store.Get(r, intermediateSessionKey)
	ist := istSession.Values["token"].(string)
	if ist == "" {
		log.Println("Error: IST required to create an Organization")
		http.Error(w, "IST required to create an Organization", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	orgName := strings.TrimSpace(r.Form.Get("org-name"))
	orgSlug := strings.ReplaceAll(r.Form.Get("org-slug"), " ", "")
	log.Printf("Creating Org with name = '%s', slug = '%s'\n", orgName, orgSlug)
	resp, err := s.client.Discovery.Organizations.Create(ctx, &organizations2.CreateParams{
		IntermediateSessionToken: ist,
		OrganizationName:         orgName,
		OrganizationSlug:         orgSlug,
	})
	if err != nil {
		log.Printf("Error creating organization: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Clear IST token.
	delete(istSession.Values, "token")
	_ = s.store.Save(r, w, istSession)

	// Store full session token.
	fullSession, _ := s.store.Get(r, sessionKey)
	fullSession.Values["token"] = resp.SessionToken
	_ = s.store.Save(r, w, fullSession)

	s.indexHandler(w, r)
}

// exchangeOrgHandler allows users to log into an existing Organization that they belong
// to, or are eligible to join by Email Domain JIT Provision, or a pending invite, after
// they complete the Discovery flow.
// You will exchange the IST returned from the discovery.authenticate() method call to
// complete the login process.
func (s *AuthService) exchangeOrgHandler(w http.ResponseWriter, r *http.Request) {
	organizationId := r.PathValue("organizationId")
	ist, exists := s.getSession(r, intermediateSessionKey)
	if exists {
		resp, err := s.client.Discovery.IntermediateSessions.Exchange(
			ctx,
			&intermediatesessions.ExchangeParams{
				IntermediateSessionToken: ist,
				OrganizationID:           organizationId,
			},
		)
		if err != nil {
			log.Printf("Error exchanging organization: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Println("Successfully exchanged token")

		// Clear IST token, store full session token.
		s.clearSession(w, r, ist)
		s.saveSession(w, r, sessionKey, resp.SessionToken)

		s.indexHandler(w, r)
		return
	}

	// Check for a full session token.
	token, exists := s.getSession(r, sessionKey)
	if !exists {
		log.Println("Error: either IST or Session Token required")
		http.Error(w, "Either IST or Session Token required", http.StatusBadRequest)
		return
	}

	resp, err := s.client.Sessions.Exchange(ctx, &sessions2.ExchangeParams{
		OrganizationID: organizationId,
		SessionToken:   token,
	})
	if err != nil {
		log.Printf("Error exchanging token for Organization: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.saveSession(w, r, sessionKey, resp.SessionToken)
	s.indexHandler(w, r)
}

// switchOrgsHandler shows an example of Organization Switching post-authentication.
// This allows a logged in Member on one Organization to "exchange" their session for
// a session on another Organization that they belong to, all while ensuring that each
// Organization's authentication requirements are honored and respecting data isolation
// between tenants.
func (s *AuthService) switchOrgsHandler(w http.ResponseWriter, r *http.Request) {
	fullSession, _ := s.store.Get(r, sessionKey)
	token := fullSession.Values["token"].(string)
	if token == "" {
		log.Println("No session token found")
		s.indexHandler(w, r)
		return
	}

	resp, err := s.client.Discovery.Organizations.List(ctx, &organizations2.ListParams{
		SessionToken: token,
	})
	if err != nil {
		log.Printf("Error listing organizations: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	discoveredOrgs := make([]DiscoveredOrganization, len(resp.DiscoveredOrganizations))
	for i := range resp.DiscoveredOrganizations {
		discoveredOrgs[i] = DiscoveredOrganization{
			OrganizationId:   resp.DiscoveredOrganizations[i].Organization.OrganizationID,
			OrganizationName: resp.DiscoveredOrganizations[i].Organization.OrganizationName,
		}
	}
	slices.SortFunc(discoveredOrgs, func(a, b DiscoveredOrganization) int {
		return cmp.Compare(a.OrganizationName, b.OrganizationName)
	})

	if err := RenderTemplate(w, DiscoveredOrganizations, &TemplateData{
		Email:                   resp.EmailAddress,
		IsLogin:                 false,
		DiscoveredOrganizations: discoveredOrgs,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// orgIndexHandler performs Organization Login (if the user is logged out) or
// Session Exchange (if the user is logged in).
func (s *AuthService) orgIndexHandler(w http.ResponseWriter, r *http.Request) {
	organizationSlug := r.PathValue("organizationSlug")
	token, _ := s.getSession(r, sessionKey)

	_, org, ok := s.authenticatedMemberAndOrg(w, r)
	if ok {
		if organizationSlug == org.OrganizationSlug {
			// User is currently logged into this Organization.
			s.indexHandler(w, r)
			return
		}

		resp, err := s.client.Discovery.Organizations.List(ctx, &organizations2.ListParams{
			SessionToken: token,
		})
		if err != nil {
			log.Printf("Error listing organizations: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		for i := range resp.DiscoveredOrganizations {
			if resp.DiscoveredOrganizations[i].Organization.OrganizationSlug == organizationSlug {
				discoveredOrgId := resp.DiscoveredOrganizations[i].Organization.OrganizationID
				http.Redirect(w, r, fmt.Sprintf("/exchange/%s", discoveredOrgId), http.StatusSeeOther)
				return
			}
		}
	}

	// User isn't a current member of Organization, have them login.
	resp, err := s.client.Organizations.Search(ctx, &organizations.SearchParams{
		Query: &organizations.SearchQuery{
			Operator: organizations.SearchQueryOperatorAND,
			Operands: []map[string]any{
				{
					"filter_name":  "organization_slugs",
					"filter_value": []string{organizationSlug},
				},
			},
		},
	})
	if err != nil {
		log.Printf("Error searching organizations: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if len(resp.Organizations) == 0 {
		log.Println("Error: no organizations found")
		http.Error(w, "No organizations found", http.StatusNotFound)
		return
	}

	if err := RenderTemplate(w, OrganizationLogin, &TemplateData{
		OrganizationId:   resp.Organizations[0].OrganizationID,
		OrganizationName: resp.Organizations[0].OrganizationName,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// enableJitHandler performs authorized updating of Organization Settings + Just-in-Time
// (JIT) Provisioning/
// Once enabled:
//  1. Logout.
//  2. Initiate magic link for an email alias (e.g. ada+1@stytch.com).
//  3. After clicking the Magic Link you'll see the option to join the organization with JIT enabled
//     Use your work email address to test this, as JIT cannot be enabled for common email domains.
func (s *AuthService) enableJitHandler(w http.ResponseWriter, r *http.Request) {
	member, org, ok := s.authenticatedMemberAndOrg(w, r)
	if !ok {
		s.indexHandler(w, r)
		return
	}

	token, ok := s.getSession(r, sessionKey)
	if !ok {
		log.Println("Error: session Token required")
		http.Error(w, "Session Token required", http.StatusUnauthorized)
		return
	}

	// Note: not allowed for common domains like gmail.com.
	domain := strings.Split(member.EmailAddress, "@")[1]

	_, err := s.client.Organizations.Update(
		ctx,
		&organizations.UpdateParams{
			OrganizationID:       org.OrganizationID,
			EmailAllowedDomains:  []string{domain},
			EmailJITProvisioning: "RESTRICTED",
		},
		&organizations.UpdateRequestOptions{
			Authorization: methodoptions.Authorization{
				SessionToken: token,
			},
		},
	)
	if err != nil {
		log.Printf("Error updating Organization JIT Provisioning settings: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Println("Updated Organization JIT Provisioning settings")
	s.indexHandler(w, r)
}

//
// Session management.
//

const (
	// FullSessionTokenKey is the name of the cookie store key where a full session token is stored.
	sessionKey = "stytch-session-token"

	// IstKey is the name of the cookie store key where an intermediate session token is stored.
	intermediateSessionKey = "stytch-ist"
)

// getSession retrieves a session token located by the specified cookie name.
func (s *AuthService) getSession(r *http.Request, name string) (token string, exists bool) {
	session, err := s.store.Get(r, name)
	if session == nil || err != nil {
		return "", false
	}
	token, ok := session.Values["token"].(string)
	return token, token != "" && ok
}

// saveSession stores the provided token in a cookie, specified by name.
func (s *AuthService) saveSession(w http.ResponseWriter, r *http.Request, key, token string) {
	session, _ := s.store.Get(r, key)
	session.Values["token"] = token
	_ = session.Save(r, w)
}

// clearSession deletes the token from the specified session.
func (s *AuthService) clearSession(w http.ResponseWriter, r *http.Request, key string) {
	session, _ := s.store.Get(r, key)
	delete(session.Values, "token")
	_ = s.store.Save(r, w, session)
}

// authenticatedMemberAndOrg retrieves the organizations.Member and organizations.Organization
// from the Stytch API, based on the requester's session token.
func (s *AuthService) authenticatedMemberAndOrg(
	w http.ResponseWriter,
	r *http.Request,
) (*organizations.Member, *organizations.Organization, bool) {
	token, exists := s.getSession(r, sessionKey)
	if !exists {
		return nil, nil, false
	}

	resp, err := s.client.Sessions.Authenticate(ctx, &sessions2.AuthenticateParams{
		SessionToken: token,
	})
	if err != nil {
		log.Printf("Error authenticating session: %v\n", err)
		s.clearSession(w, r, sessionKey)
		return nil, nil, false
	}

	return &resp.Member, &resp.Organization, true
}
