package main

import (
	"html/template"
	"net/http"

	"github.com/stytchauth/stytch-go/v12/stytch/b2b/organizations"
)

type TemplateFilename string

var (
	DiscoveredOrganizations TemplateFilename = "templates/discoveredOrganizations.gohtml"
	LoggedIn                TemplateFilename = "templates/loggedIn.gohtml"
	OrganizationLogin       TemplateFilename = "templates/organizationLogin.gohtml"
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
	OrganizationId          string
	OrganizationName        string
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
