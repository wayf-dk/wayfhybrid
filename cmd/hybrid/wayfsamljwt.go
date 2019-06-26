package main

import (
	"errors"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/wayfhybrid"
	"github.com/y0ssar1an/q"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
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
		Lock  sync.RWMutex
	}

	xmapElement struct {
		key, xpath string
	}
)

const (
	postformTemplate = `<html>
<style>input { font-size: 500%; }</style>
<body xonload="document.forms[0].submit()">
<form action="{{.Acs}}" method="POST">
<input type="hidden" name="SAMLResponse" value="{{.Samlresponse}}">
{{if .RelayState }}
<input type="hidden" name="RelayState" value="{{.RelayState}}">
{{end}}
<input type="submit" value="Login">
</form>
</body>
</html>
`
	discoveryURLTemplate = `https://wayf.wayf.dk/ds/?returnIDParam=idpentityid&entityID={{.EntityID}}&return={{.ACS}}`
	mdCert               = `MIIDBTCCAe2gAwIBAgIBBzANBgkqhkiG9w0BAQsFADA8MQswCQYDVQQGEwJESzEN MAsGA1UEChMEV0FZRjEeMBwGA1UEAxMVbWV0YWRhdGEuMjAxNi5zaWduaW5nMB4X DTE1MDEwMTAwMDAwMFoXDTI1MTIzMTAwMDAwMFowPDELMAkGA1UEBhMCREsxDTAL BgNVBAoTBFdBWUYxHjAcBgNVBAMTFW1ldGFkYXRhLjIwMTYuc2lnbmluZzCCASIw DQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8csKphZWfERIcorQzodVnR9vUS LzxXI0DGL98afvJvEfsbqy5WHhS1Sl1CnYoKSl6NtO7UC6wix3gxa0OasB6vsUe0 LDsXndLhyKziZIsu0D/sHvaz6jucs6Q7gvuyUztohtzSEu2iIyCzUQMSwwAJwtY3 AVNssxJaG+CF6bwU8ARQxUqlpB8Ufx2knFLnL8NJcZcXKz+ZpnNZtEWu5cIRPSiI pWkc4efwk78pqFdLr14fPBo9jgfzunq71TjnP0G2wYD15dq9ShWGKNm6sT6xs29i BNjI/MZzD7Srp6GWdMjEVcbWSlA7YBc0FpdwWZpDUDwj6D2l/8FRSNjqyTUCAwEA AaMSMBAwDgYDVR0PAQH/BAQDAgIEMA0GCSqGSIb3DQEBCwUAA4IBAQAXkE3WqIly NAeHXjDvJPDy8JBWeHOt7CpLJ8mDvD3Ev7uTiM2I5Mh/arMAH6T2aMxiCrk4k1qF ibX0wIlWDfCCvCUfDELaCcpSjHFmumbt0cI1SBhYh6Kt0kWYsEdyzpGm0gPl+YID Rg6VNKINJeOBM6r/avh3aRzmh2pGz1M1DAucEXz6L0caCkxU3RXFRzvvakW01qKO 2hc6WhxfqMUmSIxi+SAPlLN3L2kS0ItTJ3RSxVPA2zF7yVgoI0yrLBhR2AQgWCS2 eW2q8fSxpyb0sDCGVV/AAsunKYSO8i2Hjvu13lcRx/JxLwdlm8+NNNGX52qwz0Lo i1lLXSO09bfw`

	MdSetHub         = "https://wayf.wayf.dk/MDQ/hub/"
	MdSetInternal    = "https://wayf.wayf.dk/MDQ/int/"
	MdSetExternalIdP = "https://wayf.wayf.dk/MDQ/idp/"
	MdSetExternalSP  = "https://wayf.wayf.dk/MDQ/sp/"
)

var (
	_ = q.Q
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	postForm, discoveryURL *template.Template

	mdHub, mdInternal, mdExternalIdP, mdExternalSP *MDQ
	mdqCache                                       = MdqCache{Cache: map[string]*goxml.Xp{}}
	whitespace                                     = regexp.MustCompile("\\s")
	allowedInFeds                                  = regexp.MustCompile("[^\\w\\.-]")
)

func main() {
	gosaml.PostForm = template.Must(template.New("PostForm").Parse(postformTemplate))
	discoveryURL = template.Must(template.New("discoveryURL").Parse(discoveryURLTemplate))

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
	mdqCache.Lock.RLock()
	cacheKey := mdq.Mdq + key
	xp, ok := mdqCache.Cache[cacheKey]
	if ok {
		if xp != nil {
			xp = xp.CpXp()
		} else {
			err = errors.New("No md found")
		}
		mdqCache.Lock.RUnlock()
		fmt.Println("from cache", cacheKey, err)
		return
	}
	mdqCache.Lock.RUnlock()

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

func jwt2saml(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Jwt2saml(w, r, mdHub, mdInternal, mdExternalIdP, mdExternalSP, wayfhybrid.RequestHandler, nil)
}

func saml2jwt(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Saml2jwt(w, r, mdHub, mdInternal, mdExternalIdP, mdExternalSP, wayfhybrid.RequestHandler, "", false)
}

