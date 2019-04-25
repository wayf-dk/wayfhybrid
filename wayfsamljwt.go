package main

import (
    "crypto"
	"crypto/rand"
 	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/y0ssar1an/q"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	formdata struct {
		Acs          string
		Samlresponse string
		RelayState   string
		WsFed        bool
		Ard          template.JS
	}

	MDQ struct {
		Mdq string
	}

	// Due to the specialization of the MDQ we need a common cache

	MdqCache struct {
		Cache map[string]*goxml.Xp
		Lock  sync.Mutex
	}
)

const (
	HRAXML = `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://wayf.wayf.dk">
  <md:SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:1.1:protocol urn:oasis:names:tc:SAML:2.0:protocol">
    <md:AttributeConsumingService index="0">
      <md:RequestedAttribute FriendlyName="sn" singular="true" must="true" Name="urn:oid:2.5.4.4" AttributeName="surname"/>
      <md:RequestedAttribute FriendlyName="gn" singular="true" must="true" Name="urn:oid:2.5.4.42"  AttributeName="givenname"/>
      <md:RequestedAttribute FriendlyName="cn" singular="true" must="true" Name="urn:oid:2.5.4.3"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrincipalName" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.6" isRequired="true"/>
      <md:RequestedAttribute FriendlyName="mail" Name="urn:oid:0.9.2342.19200300.100.1.3" AttributeName="emailaddress"/>
      <md:RequestedAttribute FriendlyName="eduPersonPrimaryAffiliation" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.5"/>
      <md:RequestedAttribute FriendlyName="organizationName" singular="true" must="true" Name="urn:oid:2.5.4.10"/>
      <md:RequestedAttribute FriendlyName="eduPersonAssurance" singular="true" must="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.11"/>
      <md:RequestedAttribute FriendlyName="schacPersonalUniqueID" Name="urn:oid:1.3.6.1.4.1.25178.1.2.15"/>
      <md:RequestedAttribute FriendlyName="schacCountryOfCitizenship" singular="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.5" />
      <md:RequestedAttribute FriendlyName="eduPersonScopedAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.9" />
      <md:RequestedAttribute FriendlyName="preferredLanguage" Name="urn:oid:2.16.840.1.113730.3.1.39" />
      <md:RequestedAttribute FriendlyName="eduPersonEntitlement" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7" />
      <md:RequestedAttribute FriendlyName="norEduPersonLIN" Name="urn:oid:1.3.6.1.4.1.2428.90.1.4" />
      <md:RequestedAttribute FriendlyName="schacHomeOrganization" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.9" />
      <md:RequestedAttribute FriendlyName="eduPersonTargetedID" computed="true" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10" />
      <md:RequestedAttribute FriendlyName="schacDateOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.2.3" />
      <md:RequestedAttribute FriendlyName="schacYearOfBirth" Name="urn:oid:1.3.6.1.4.1.25178.1.0.2.3" />
      <md:RequestedAttribute FriendlyName="schacHomeOrganizationType" computed="true" Name="urn:oid:1.3.6.1.4.1.25178.1.2.10" />
      <md:RequestedAttribute FriendlyName="eduPersonAffiliation" Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.1" />
      <md:RequestedAttribute FriendlyName="displayName" Name="urn:oid:2.16.840.1.113730.3.1.241" />
    </md:AttributeConsumingService>
  </md:SPSSODescriptor>
</md:EntityDescriptor>
`
	postformTemplate = `<html>
<body onload="document.forms[0].submit()">
<form action="{{.Acs}}" method="POST">
<input type="hidden" name="SAMLResponse" value="{{.Samlresponse}}" />
{{if .RelayState }}
<input type="hidden" name="RelayState" value="{{.RelayState}}" />
{{end}}
</form>
</body>
</html>
`
	mdCert = `MIIDBTCCAe2gAwIBAgIBBzANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJESzEN MAsGA1UEChMEV0FZRjEeMBwGA1UEAxMVbWV0YWRhdGEuMjAxNi5zaWduaW5nMB4X DTE1MDEwMTAwMDAwMFoXDTI1MTIzMTAwMDAwMFowPDELMAkGA1UEBhMCREsxDTAL BgNVBAoTBFdBWUYxHjAcBgNVBAMTFW1ldGFkYXRhLjIwMTYuc2lnbmluZzCCASIw DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8csKphZWfERIcorQzodVnR9vUS LzxXI0DGL98afvJvEfsbqy5WHhS1Sl1CnYoKSl6NtO7UC6wix3gxa0OasB6vsUe0 LDsXndLhyKziZIsu0D/sHvaz6jucs6Q7gvuyUztohtzSEu2iIyCzUQMSwwAJwtY3 AVNssxJaG+CF6bwU8ARQxUqlpB8Ufx2knFLnL8NJcZcXKz+ZpnNZtEWu5cIRPSiI pWkc4efwk78pqFdLr14fPBo9jgfzunq71TjnP0G2wYD15dq9ShWGKNm6sT6xs29i BNjI/MZzD7Srp6GWdMjEVcbWSlA7YBc0FpdwWZpDUDwj6D2l/8FRSNjqyTUCAwEA AaMSMBAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQAXkE3WqIly NAeHXjDvJPDy8JBWeHOt7CpLJ8mDvD3Ev7uTiM2I5Mh/arMAH6T2aMxiCrk4k1qF ibX0wIlWDfCCvCUfDELaCcpSjHFmumbt0cI1SBhYh6Kt0kWYsEdyzpGm0gPl+YID Rg6VNKINJeOBM6r/avh3aRzmh2pGz1M1DAucEXz6L0caCkxU3RXFRzvvakW01qKO 2hc6WhxfqMUmSIxi+SAPlLN3L2kS0ItTJ3RSxVPA2zF7yVgoI0yrLBhR2AQgWCS2 eW2q8fSxpyb0sDCGVV/AAsunKYSO8i2Hjvu13lcRx/JxLwdlm8+NNNGX52qwz0Lo i1lLXSO09bfw`

	MdSetHub         = "https://wayf.wayf.dk/MDQ/hub/"
	MdSetInternal    = "https://wayf.wayf.dk/MDQ/int/"
	MdSetExternalIdP = "https://wayf.wayf.dk/MDQ/idp/"
	MdSetExternalSP  = "https://wayf.wayf.dk/MDQ/sp/"
)

var (
	_ = q.Q
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	postForm *template.Template

	hubRequestedAttributes                         *goxml.Xp
	mdHub, mdInternal, mdExternalIdP, mdExternalSP *MDQ
	mdqCache                                       = MdqCache{Cache: map[string]*goxml.Xp{}}
	whitespace                                     = regexp.MustCompile("\\s")
)

func main() {
	postForm = template.Must(template.New("PostForm").Parse(postformTemplate))
	hubRequestedAttributes = goxml.NewXpFromString(HRAXML)

	mdHub = &MDQ{Mdq: MdSetHub}
	mdInternal = &MDQ{Mdq: MdSetInternal}
	mdExternalIdP = &MDQ{Mdq: MdSetExternalIdP}
	mdExternalSP = &MDQ{Mdq: MdSetExternalSP}

	gosaml.Config = gosaml.Conf{
		SamlSchema: "schemas/saml-schema-protocol-2.0.xsd",
		CertPath:   "",
	}

	httpMux := http.NewServeMux()

	httpMux.Handle("/favicon.ico", http.NotFoundHandler())
	httpMux.Handle("/saml2jwt", appHandler(saml2jwt))
	httpMux.Handle("/jwt2saml", appHandler(jwt2saml))

	finish := make(chan bool)

	go func() {
		listenOn := "127.0.0.1:8365"
		log.Println("listening on ", listenOn)
		err := http.ListenAndServe(listenOn, httpMux)
		if err != nil {
			log.Printf("main(): %s\n", err)
		}
	}()

	<-finish
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	log.Printf("%s %s %s %+v", remoteAddr, r.Method, r.Host, r.URL)
	starttime := time.Now()
	err := fn(w, r)

	status := 200
	if err != nil {
		status = 500
		if err.Error() == "401" {
			status = 401
		}
		http.Error(w, err.Error(), status)
	} else {
		err = fmt.Errorf("OK")
	}

	if ra, ok := r.Header["X-Forwarded-For"]; ok {
		remoteAddr = ra[0]
	}

	log.Printf("%s %s %s %+v %1.3f %d %s", remoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)

	switch x := err.(type) {
	case goxml.Werror:
		if x.Xp != nil {
			logtag := gosaml.DumpFile(r, x.Xp)
			log.Print("logtag: " + logtag)
		}
		log.Print(x.FullError())
		log.Print(x.Stack(5))
	}
}

func (mdq *MDQ) MDQ(key string) (xp *goxml.Xp, err error) {
	mdqCache.Lock.Lock()
	cacheKey := mdq.Mdq + key
	xp, ok := mdqCache.Cache[cacheKey]
	if ok {
		if xp != nil {
			xp = xp.CpXp()
		} else {
			err = errors.New("No md found")
		}
		mdqCache.Lock.Unlock()
		fmt.Println("from cache", cacheKey, err)
		return
	}
	mdqCache.Lock.Unlock()

	client := &http.Client{}
	req, _ := http.NewRequest("GET", mdq.Mdq+url.PathEscape(key), nil)
	req.Header.Add("Cookie", "wayfid=wayf-qa")
	response, err := client.Do(req)

	mdqCache.Lock.Lock()
	defer mdqCache.Lock.Unlock()

	if response.StatusCode == 500 || err != nil {
		mdqCache.Cache[cacheKey] = nil
		return nil, errors.New("No md found")
	}

	defer response.Body.Close()
	xml, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return
	}
	//md := gosaml.Inflate(xml)
	xp = goxml.NewXp(xml)
	if xp.QueryBool(nil, "not(/md:EntityDescriptor)") { // we need to return an error if we got nothing
		err = errors.New("No md found")
		xp = nil
		mdqCache.Cache[cacheKey] = nil
		return
	}

	_, err = xp.SchemaValidate("schemas/saml-schema-metadata-2.0.xsd")
	if err != nil {
		xp = nil
		mdqCache.Cache[cacheKey] = nil
		return
	}

	err = errors.New("Md signature validation failed 1")
	signatures := xp.Query(nil, "/md:EntityDescriptor")
	if len(signatures) == 1 {
		err = gosaml.VerifySign(xp, []string{mdCert}, signatures[0])
	}
	if err != nil { // len != 1 or validation error
		return nil, err
	}

	fmt.Println("from MDQ", cacheKey)
	mdqCache.Cache[cacheKey] = xp
	return
}

func samlTime2JwtTime(xmlTime string) int64 {
	samlTime, _ := time.Parse(gosaml.XsDateTime, xmlTime)
	return samlTime.Unix()
}

func jwt2saml(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	// we need to identify the sender first for getting the key for checking the signature
	headerPayloadSignature := strings.SplitN(r.Form.Get("jwt"), ".", 3)
	payload, _ := base64.RawURLEncoding.DecodeString(headerPayloadSignature[1])

	var attrs map[string]interface{}
	err = json.Unmarshal(payload, &attrs)
	if err != nil {
		return err
	}

	request, hubSpMd, idpMd, _, _, _, err := gosaml.ReceiveAuthnRequest(r, gosaml.MdSets{mdHub, mdExternalSP}, gosaml.MdSets{mdInternal, mdExternalIdP}, attrs["sso"].(string))
	if err != nil {
		return
	}

	certificates := idpMd.QueryMulti(nil, "./md:IDPSSODescriptor"+gosaml.SigningCertQuery)

	if len(certificates) == 0 {
		return errors.New("No Certs found")
	}


	validated := false
	for _, certificate := range certificates {
	    validated = validated || verify(certificate, strings.Join(headerPayloadSignature[:2], "."), headerPayloadSignature[2])
	}

	if !validated {
		return fmt.Errorf("Signature validation error")
	}

	//    iat := attrs["iat"].(int64)
	sourceResponse := goxml.NewXpFromString("")
	sourceResponse.QueryDashP(nil, "/samlp:Response/saml:Issuer", attrs["iss"].(string), nil)
	for _, aa := range attrs["aa"].([]interface{}) {
		sourceResponse.QueryDashP(nil, "/samlp:Response/saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[0]", aa.(string), nil)
	}

	response := gosaml.NewResponse(idpMd, hubSpMd, request, sourceResponse)
	destinationAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[1]`, "", nil)

	requestedAttributes := hubRequestedAttributes.Query(nil, `//md:RequestedAttribute`)
	for _, requestedAttribute := range requestedAttributes {
		friendlyName := hubRequestedAttributes.Query1(requestedAttribute, "@FriendlyName")
		if _, ok := attrs[friendlyName]; !ok {
			continue
		}
		attr := response.QueryDashP(destinationAttributes, `saml:Attribute[@Name=`+strconv.Quote(friendlyName)+`]`, "", nil)
		response.QueryDashP(attr, `@NameFormat`, "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", nil)
		for _, value := range attrs[friendlyName].([]interface{}) {
			response.QueryDashP(attr, "saml:AttributeValue[0]", value.(string), nil)
		}
	}

	err = gosaml.SignResponse(response, "/samlp:Response/saml:Assertion", idpMd, "sha256", gosaml.SAMLSign)
	if err != nil {
		return err
	}

	acs := hubSpMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+gosaml.POST+`"]/@Location`)

	data := formdata{Acs: acs, Samlresponse: base64.StdEncoding.EncodeToString(response.Dump()), RelayState: r.Form.Get("RelayState")}
	postForm.Execute(w, data)
	return
}

// saml2jwt handles saml2jwt request
func saml2jwt(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	// backward compatible - use either or
	acs := r.Form.Get("acs")
	//app := r.Form.Get("app")
	entityID := r.Form.Get("issuer")
	eid := url.PathEscape(entityID) + "/"
	idpentityid := r.Form.Get("idpentityid")

	spMd, _, err := gosaml.FindInMetadataSets(gosaml.MdSets{mdInternal, mdExternalSP}, entityID)
	if err != nil {
		return
	}

	if _, ok := r.Form["SAMLResponse"]; ok {
		issuers := gosaml.MdSets{&MDQ{Mdq: MdSetHub}, &MDQ{Mdq: MdSetExternalSP + eid}}
		response, _, _, _, _, _, err := gosaml.ReceiveSAMLResponse(r, issuers, gosaml.MdSets{mdInternal, mdExternalSP}, acs, nil)
		if err != nil {
			return err
		}

		attrs := map[string]interface{}{}

		assertion := response.Query(nil, "/samlp:Response/saml:Assertion")[0]
		names := response.QueryMulti(assertion, "saml:AttributeStatement/saml:Attribute/@Name")
		for _, name := range names {
			//basic := basic2uri[name].basic
			attrs[name] = response.QueryMulti(assertion, "saml:AttributeStatement/saml:Attribute[@Name="+strconv.Quote(name)+"]/saml:AttributeValue")
		}

		attrs["iss"] = response.Query1(assertion, "./saml:Issuer")
		attrs["aud"] = response.Query1(assertion, "./saml:Conditions/saml:AudienceRestriction/saml:Audience")
		attrs["aa"] = response.QueryMulti(assertion, "./saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority")
		attrs["nbf"] = samlTime2JwtTime(response.Query1(assertion, "./saml:Conditions/@NotBefore"))
		attrs["exp"] = samlTime2JwtTime(response.Query1(assertion, "./saml:Conditions/@NotOnOrAfter"))
		attrs["iat"] = samlTime2JwtTime(response.Query1(assertion, "@IssueInstant"))

		cert := spMd.Query1(nil, "md:SPSSODescriptor"+gosaml.SigningCertQuery) // actual signing key is always first

		// no pem so no pem.Decode
		key, err := base64.StdEncoding.DecodeString(whitespace.ReplaceAllString(cert, ""))
		pk, err := x509.ParseCertificate(key)
		if err != nil {
			return err
		}
		publickey := pk.PublicKey.(*rsa.PublicKey)
		keyname := fmt.Sprintf("%x", sha1.Sum([]byte(fmt.Sprintf("Modulus=%X\n", publickey.N))))
		privatekey, err := ioutil.ReadFile(keyname + ".key")
		if err != nil {
			return err
		}

		json, err := json.Marshal(attrs)
		if err != nil {
			return err
		}

		payload := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." + base64.RawURLEncoding.EncodeToString(json)

		signature, err := sign([]byte(payload), privatekey, []byte(""))
		tokenString := payload + "." + base64.RawURLEncoding.EncodeToString(signature)

		//		var app []byte
		//		err = authnRequestCookie.Decode("app", relayState, &app)
		//		if err != nil {
		//			return err
		//		}
		//
		//		w.Header().Set("X-Accel-Redirect", string(app))
		w.Header().Set("Authorization", "Bearer "+tokenString)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, tokenString)
		return err
	} else if idpentityid != "" {
		idpMd, _, err := gosaml.FindInMetadataSets(gosaml.MdSets{mdHub, &MDQ{Mdq: MdSetExternalSP + eid}}, idpentityid)
		if err != nil {
			return err
		}

		/*
			relayState, err := authnRequestCookie.Encode("app", []byte(app))
			if err != nil {
				return err
			}
		*/

		request, err := gosaml.NewAuthnRequest(nil, spMd, idpMd, strings.Split(r.Form.Get("idplist"), ","))
		if err != nil {
			return err
		}

		//request.QueryDashP(nil, "@Destination", "https://birk.wayf.dk/birk.php/idp.entity.test:8080", nil)
		relayState := ""
		u, err := gosaml.SAMLRequest2Url(request, relayState, "", "", "")
		if err != nil {
			return err
		}
		fmt.Println("redirect", u)
		http.Redirect(w, r, u.String(), http.StatusFound)
		return err
	} else {
		http.Redirect(w, r, "https://wayf.wayf.dk/ds/?returnIDParam=idpentityid&entityID="+entityID+"&return="+acs, http.StatusFound)
	}
	return
}

func verify(cert, payload, signature string) ( bool) {

	digest := sha256.Sum256([]byte(payload))
	sign, _ := base64.RawURLEncoding.DecodeString(signature)

	key, err := base64.StdEncoding.DecodeString(whitespace.ReplaceAllString(cert, ""))
	pk, err := x509.ParseCertificate(key)
	if err != nil {
		return false
	}
	pub := pk.PublicKey.(*rsa.PublicKey)

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sign)
	if err != nil {
		return false
	}
	return true
}

func sign(plaintext, privatekeypem, pw []byte) (signature []byte, err error) {
	digest := sha256.Sum256(plaintext)

	var privateKey *rsa.PrivateKey

	block, _ := pem.Decode(privatekeypem) // not used rest
	derbytes := block.Bytes
	if string(pw) != "" {
		if derbytes, err = x509.DecryptPEMBlock(block, pw); err != nil {
			return nil, err
		}
	}
	if privateKey, err = x509.ParsePKCS1PrivateKey(derbytes); err != nil {
		var pk interface{}
		if pk, err = x509.ParsePKCS8PrivateKey(derbytes); err != nil {
			return nil, err
		}
		privateKey = pk.(*rsa.PrivateKey)
	}

	signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	return
}
