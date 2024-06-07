package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/b2bstytchapi"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/discovery/intermediatesessions"
	organizations2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/discovery/organizations"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/magiclinks"
	discovery2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/magiclinks/discovery"
	email2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/magiclinks/email"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/magiclinks/email/discovery"
	"github.com/stytchauth/stytch-go/v12/stytch/b2b/organizations"
	sessions2 "github.com/stytchauth/stytch-go/v12/stytch/b2b/sessions"
)

var ctx = context.Background()

func main() {
	// Load variables from .env file into the environment.
	if err := godotenv.Load(".env.local"); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Instantiate a new API service.
	service := NewMagicLinksService(
		os.Getenv("STYTCH_PROJECT_ID"),
		os.Getenv("STYTCH_SECRET"),
	)

	// Register HTTP handlers.
	mux := http.NewServeMux()
	mux.HandleFunc("/", service.indexHandler)

	// Static assets.
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	// Declare the static file directory
	// this is to ensure our static assets & css are accessible & rendered
	//staticFileDirectory := http.Dir("./assets/")
	//staticFileHandler := http.StripPrefix("/assets/", http.FileServer(staticFileDirectory))
	//mux.PathPrefix("/assets/").Handler(staticFileHandler)

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

type MagicLinksService struct {
	client *b2bstytchapi.API
	store  *sessions.CookieStore
}

func NewMagicLinksService(projectId, secret string) *MagicLinksService {
	client, err := b2bstytchapi.NewClient(projectId, secret)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	return &MagicLinksService{
		client: client,
		store:  sessions.NewCookieStore([]byte("your-secret-key")),
	}
}

//
// Magic Links handlers.
//

func (s *MagicLinksService) indexHandler(w http.ResponseWriter, r *http.Request) {
	// Check for an existing session token in the browser.
	// If one is found, and it corresponds to an active session,
	// redirect the user.
	member, org := s.authenticatedMemberAndOrg(w, r)
	if member != nil && org != nil {
		if err := RenderTemplate(w, LoggedIn, &TemplateData{
			Member:       member,
			Organization: org,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	}

	if err := RenderTemplate(w, DiscoveryLogin, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *MagicLinksService) sendMagicLinkHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	email := r.Form.Get("email")
	orgId := r.Form.Get("orgId")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	if orgId == "" {
		_, err := s.client.MagicLinks.Email.Discovery.Send(ctx, &discovery.SendParams{
			EmailAddress: email,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		_, err := s.client.MagicLinks.Email.LoginOrSignup(ctx, &email2.LoginOrSignupParams{
			OrganizationID: orgId,
			EmailAddress:   email,
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := RenderTemplate(w, EmailSent, nil); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *MagicLinksService) authenticateHandler(w http.ResponseWriter, r *http.Request) {
	tokenType := r.URL.Query().Get("stytch_token_type")
	token := r.URL.Query().Get("token")

	if tokenType == "discovery" {
		resp, err := s.client.MagicLinks.Discovery.Authenticate(ctx, &discovery2.AuthenticateParams{
			DiscoveryMagicLinksToken: token,
		})
		if err != nil {
			log.Printf("Error authenticating: %v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// The intermediate_session_token (IST) allows you to persist authentication state while
		// you present the user with the Organizations they can log into, or the option to create
		// a new Organization.
		session, _ := s.store.Get(r, istKey)
		session.Values["token"] = resp.IntermediateSessionToken
		_ = s.store.Save(r, w, session)

		discoveredOrgs := make([]DiscoveredOrganization, len(resp.DiscoveredOrganizations))
		for i := range resp.DiscoveredOrganizations {
			discoveredOrgs[i] = DiscoveredOrganization{
				OrganizationId:   resp.DiscoveredOrganizations[i].Organization.OrganizationID,
				OrganizationName: resp.DiscoveredOrganizations[i].Organization.OrganizationName,
			}
		}

		if err := RenderTemplate(w, DiscoveredOrganizations, &TemplateData{
			Email:                   resp.EmailAddress,
			IsLogin:                 true,
			DiscoveredOrganizations: discoveredOrgs,
		}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if tokenType == "multi_tenant_magic_links" {
		resp, err := s.client.MagicLinks.Authenticate(ctx, &magiclinks.AuthenticateParams{
			MagicLinksToken: token,
		})
		if err != nil {
			log.Printf("Error authenticating: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		session, _ := s.store.Get(r, fullSessionTokenKey)
		session.Values["token"] = resp.SessionToken
		_ = s.store.Save(r, w, session)

		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	http.Error(w, fmt.Sprintf("Unrecognized token type %s", tokenType), http.StatusBadRequest)
}

func (s *MagicLinksService) createOrgHandler(w http.ResponseWriter, r *http.Request) {
	istSession, _ := s.store.Get(r, istKey)
	ist := istSession.Values["token"].(string)
	if ist == "" {
		http.Error(w, "IST required to create an Organization", http.StatusBadRequest)
		return
	}

	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form: %v\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	orgName := strings.TrimSpace(r.Form.Get("orgName"))
	orgSlug := strings.ReplaceAll(r.Form.Get("orgSlug"), " ", "")
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
	fullSession, _ := s.store.Get(r, fullSessionTokenKey)
	fullSession.Values["token"] = resp.SessionToken
	_ = s.store.Save(r, w, fullSession)

	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *MagicLinksService) exchangeOrgHandler(w http.ResponseWriter, r *http.Request) {
	istSession, _ := s.store.Get(r, istKey)
	ist := istSession.Values["token"].(string)
	organizationId := r.PathValue("organizationId")
	if ist != "" {
		resp, err := s.client.Discovery.IntermediateSessions.Exchange(ctx, &intermediatesessions.ExchangeParams{
			IntermediateSessionToken: ist,
			OrganizationID:           organizationId,
		})
		if err != nil {
			log.Printf("Error exchanging organization: %v\n", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Clear IST token.
		delete(istSession.Values, "token")
		_ = s.store.Save(r, w, istSession)

		// Store full session token.
		fullSession, _ := s.store.Get(r, fullSessionTokenKey)
		fullSession.Values["token"] = resp.SessionToken
		_ = s.store.Save(r, w, fullSession)

		return
	}
}

//
// Helpers.
//

const (
	// FullSessionTokenKey is the name of the cookie store key where a full session token is stored.
	fullSessionTokenKey = "stytch-session-token"

	// IstKey is the name of the cookie store key where an intermediate session token is stored.
	istKey = "ist"
)

func (s *MagicLinksService) authenticatedMemberAndOrg(
	w http.ResponseWriter,
	r *http.Request,
) (*organizations.Member, *organizations.Organization) {
	session, err := s.store.Get(r, fullSessionTokenKey)
	if err != nil {
		log.Printf("Error getting session: %v\n", err)
		return nil, nil
	}

	token, ok := session.Values["token"].(string)
	if !ok || token == "" {
		return nil, nil
	}

	resp, err := s.client.Sessions.Authenticate(ctx, &sessions2.AuthenticateParams{
		SessionToken: token,
	})
	if err != nil {
		log.Printf("Error authenticating session: %v\n", err)
		delete(session.Values, "token")
		_ = session.Save(r, w)
		return nil, nil
	}

	return &resp.Member, &resp.Organization
}
