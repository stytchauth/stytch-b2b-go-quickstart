package main

import (
	"html/template"
	"net/http"

	"github.com/stytchauth/stytch-go/v12/stytch/b2b/organizations"
)

type TemplateFilename string

var (
	DiscoveredOrganizations TemplateFilename = "templates/discoveredOrganizations.html"
	DiscoveryLogin          TemplateFilename = "templates/discoveryLogin.html"
	EmailSent               TemplateFilename = "templates/emailSent.html"
	LoggedIn                TemplateFilename = "templates/loggedIn.html"
	OrganizationLogin       TemplateFilename = "templates/organizationLogin.html"
)

type DiscoveredOrganization struct {
	OrganizationId   string
	OrganizationName string
}

type TemplateData struct {
	Email                   string
	IsLogin                 bool
	Member                  *organizations.Member
	Organization            *organizations.Organization
	DiscoveredOrganizations []DiscoveredOrganization
}

func RenderTemplate(
	w http.ResponseWriter,
	filename TemplateFilename,
	data any,
) error {
	t, err := template.ParseFiles(string(filename))
	if err != nil {
		return err
	}
	return t.Execute(w, data)
}
