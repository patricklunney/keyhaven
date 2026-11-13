package saml

import (
	"bytes"
	"encoding/base64"

	"github.com/beevik/etree"
)

// Metadata returns the IdP's SAML metadata document (served over HTTPS).
func (idp *IdP) Metadata() ([]byte, error) {
	ed := etree.NewElement("md:EntityDescriptor")
	ed.CreateAttr("xmlns:md", NSMetadata)
	ed.CreateAttr("xmlns:ds", NSDSig)
	ed.CreateAttr("entityID", idp.EntityID)
	ed.CreateAttr("cacheDuration", "PT24H")

	d := ed.CreateElement("md:IDPSSODescriptor")
	d.CreateAttr("protocolSupportEnumeration", NSProtocol)
	d.CreateAttr("WantAuthnRequestsSigned", "false")

	kd := d.CreateElement("md:KeyDescriptor")
	kd.CreateAttr("use", "signing")
	kd.CreateElement("ds:KeyInfo").CreateElement("ds:X509Data").CreateElement("ds:X509Certificate").
		SetText(base64.StdEncoding.EncodeToString(idp.Cert.Raw))

	d.CreateElement("md:NameIDFormat").SetText(NameIDPersistent)
	d.CreateElement("md:NameIDFormat").SetText(NameIDUnspecified)
	for _, binding := range []string{BindingRedirect, BindingPOST} {
		s := d.CreateElement("md:SingleSignOnService")
		s.CreateAttr("Binding", binding)
		s.CreateAttr("Location", idp.SSOURL)
	}

	doc := etree.NewDocument()
	doc.CreateProcInst("xml", `version="1.0" encoding="UTF-8"`)
	doc.SetRoot(ed)
	doc.Indent(2)
	var buf bytes.Buffer
	if _, err := doc.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
