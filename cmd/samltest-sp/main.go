// Command samltest-sp is a tiny SAML service provider for trying Keyhaven's
// SAML support end to end. It uses an independent SAML library (gosaml2) to
// verify Keyhaven's signed responses.
//
//	go run ./cmd/samltest-sp -idp https://id.example.com
//
// Register it in Keyhaven's admin console (SAML apps) with:
//
//	entity ID: http://localhost:8091/saml/metadata
//	ACS URL:   http://localhost:8091/saml/acs
package main

import (
	"crypto/x509"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/beevik/etree"
	saml2 "github.com/russellhaering/gosaml2"
	dsig "github.com/russellhaering/goxmldsig"
)

var page = template.Must(template.New("").Parse(`<!doctype html><meta charset="utf-8">
<title>SAML test app</title>
<style>body{font:16px system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid #ddd;padding:6px 8px;text-align:left}
code{background:#f3f3f3;padding:1px 4px;border-radius:4px}.err{color:#b00}</style>
<h1>SAML test app</h1>
{{if .Error}}<p class="err">{{.Error}}</p>{{end}}
{{if .Info}}
  <p>✅ Signed in via SAML. Response signature verified against <code>{{.IdP}}</code>.</p>
  <table>
    <tr><th>NameID</th><td><code>{{.Info.NameID}}</code></td></tr>
    <tr><th>NameID format</th><td><code>{{.Info.NameIDFormat}}</code></td></tr>
    <tr><th>Session index</th><td><code>{{.Info.SessionIndex}}</code></td></tr>
    {{range .Attrs}}<tr><th>{{.K}}</th><td>{{.V}}</td></tr>{{end}}
  </table>
  <p><a href="/saml/login">Sign in again</a></p>
{{else}}
  <p><a href="/saml/login">Sign in with Keyhaven (SAML)</a></p>
{{end}}`))

type kv struct{ K, V string }

func render(w http.ResponseWriter, data map[string]any) {
	if err := page.Execute(w, data); err != nil {
		log.Printf("render: %v", err)
	}
}

func main() {
	idp := flag.String("idp", "", "Keyhaven issuer URL, e.g. https://id.example.com (required)")
	addr := flag.String("addr", "localhost:8091", "listen address")
	flag.Parse()
	if *idp == "" {
		log.Fatal("-idp is required")
	}
	base := "http://" + *addr

	sp, err := spFromMetadata(strings.TrimSuffix(*idp, "/")+"/saml/metadata", base)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		render(w, map[string]any{})
	})
	http.HandleFunc("/saml/login", func(w http.ResponseWriter, r *http.Request) {
		u, err := sp.BuildAuthURL("/")
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		http.Redirect(w, r, u, http.StatusFound)
	})
	http.HandleFunc("POST /saml/acs", func(w http.ResponseWriter, r *http.Request) {
		info, err := sp.RetrieveAssertionInfo(r.FormValue("SAMLResponse"))
		if err == nil && (info.WarningInfo.InvalidTime || info.WarningInfo.NotInAudience) {
			err = fmt.Errorf("assertion failed checks: %+v", *info.WarningInfo)
		}
		if err != nil {
			log.Printf("REJECTED response: %q", err.Error()) // #nosec G706 -- %q escapes control characters; local test tool
			render(w, map[string]any{"Error": "Response rejected: " + err.Error()})
			return
		}
		var attrs []kv
		for k, v := range info.Values {
			var vals []string
			for _, av := range v.Values {
				vals = append(vals, av.Value)
			}
			attrs = append(attrs, kv{k, strings.Join(vals, ", ")})
		}
		sort.Slice(attrs, func(i, j int) bool { return attrs[i].K < attrs[j].K })
		log.Printf("SIGNED IN nameID=%q attributes=%q", info.NameID, fmt.Sprint(attrs)) // #nosec G706 -- %q escapes control characters; local test tool
		render(w, map[string]any{"Info": info, "Attrs": attrs, "IdP": sp.IdentityProviderIssuer})
	})

	log.Printf("SAML test app on %s (entity ID %s/saml/metadata, ACS %s/saml/acs)", base, base, base)
	srv := &http.Server{Addr: *addr, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// spFromMetadata configures the SP from the IdP's published metadata.
func spFromMetadata(metadataURL, base string) (*saml2.SAMLServiceProvider, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	res, err := client.Get(metadataURL)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: %s (is SAML enabled on Keyhaven?)", metadataURL, res.Status)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(body); err != nil {
		return nil, err
	}
	certEl, ssoEl := doc.FindElement("//X509Certificate"), doc.FindElement("//SingleSignOnService")
	if certEl == nil || ssoEl == nil {
		return nil, fmt.Errorf("metadata missing certificate or SSO endpoint")
	}
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(certEl.Text()))
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:      ssoEl.SelectAttrValue("Location", ""),
		IdentityProviderIssuer:      doc.Root().SelectAttrValue("entityID", ""),
		ServiceProviderIssuer:       base + "/saml/metadata",
		AssertionConsumerServiceURL: base + "/saml/acs",
		AudienceURI:                 base + "/saml/metadata",
		IDPCertificateStore:         &dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}},
		SPKeyStore:                  dsig.RandomKeyStoreForTest(),
	}, nil
}
