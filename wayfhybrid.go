package wayfhybrid

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml"
	"github.com/wayf-dk/godiscoveryservice"
	"github.com/wayf-dk/goeleven/src/goeleven"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lmdq"
	"github.com/y0ssar1an/q"
)

var (
	_ = q.Q
)

const (
	authnRequestTTL = 180
	sloInfoTTL      = 8 * 3600
	xprefix         = "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:"
)

const (
	saml = iota
	wsfed
	oauth
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	mddb struct {
		db, table string
	}

	goElevenConfig struct {
		Hsmlib       string
		Usertype     string
		Serialnumber string
		Slot         string
		SlotPassword string
		KeyLabel     string
		Maxsessions  string
	}

	Conf struct {
		DiscoveryService                                                                         string
		Domain                                                                                   string
		HubEntityID                                                                              string
		EptidSalt                                                                                string
		SecureCookieHashKey                                                                      string
		Intf, SsoService, HTTPSKey, HTTPSCert, Acs, Vvpmss                                       string
		Birk, Krib, Dsbackend, Dstiming, Public, Discopublicpath, Discometadata, Discospmetadata string
		TestSP, TestSPAcs, TestSPSlo, TestSP2, TestSP2Acs, TestSP2Slo, MDQ                       string
		NemloginAcs, CertPath, SamlSchema, ConsentAsAService                                     string
		Idpslo, Birkslo, Spslo, Kribslo, Nemloginslo, Saml2jwt, Jwt2saml, SaltForHashedEppn      string
		Oauth                                                                                    string
		ElementsToSign                                                                           []string
		NotFoundRoutes                                                                           []string
		Hub, Internal, ExternalIDP, ExternalSP                                                   struct{ Path, Table string }
		MetadataFeeds                                                                            []struct{ Path, URL string }
		GoEleven                                                                                 goElevenConfig
	}

	logWriter struct {
	}
	// AttributeReleaseData - for the attributerelease template
	AttributeReleaseData struct {
		Values             map[string][]string
		IDPDisplayName     map[string]string
		IDPLogo            string
		IDPEntityID        string
		SPDisplayName      map[string]string
		SPDescription      map[string]string
		SPLogo             string
		SPEntityID         string
		Key                string
		Hash               string
		BypassConfirmation bool
		ForceConfirmation  bool
		ConsentAsAService  string
	}
	// HybridSession - for session handling - pt. only cookies
	HybridSession interface {
		Set(http.ResponseWriter, *http.Request, string, []byte) error
		Get(http.ResponseWriter, *http.Request, string) ([]byte, error)
		Del(http.ResponseWriter, *http.Request, string) error
		GetDel(http.ResponseWriter, *http.Request, string) ([]byte, error)
	}
	// MdSets - the available metadata sets
	mdSets struct {
		Hub, Internal, ExternalIDP, ExternalSP *lmdq.MDQ
	}

	wayfHybridSession struct{}

	// https://stackoverflow.com/questions/47475802/golang-301-moved-permanently-if-request-path-contains-additional-slash
	slashFix struct {
		mux http.Handler
	}

	attrValue struct {
		Name   string
		Must   bool
		Values []string
	}

	webMd struct {
		md, revmd *lmdq.MDQ
	}
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	config = Conf{}

	allowedInFeds                       = regexp.MustCompile("[^\\w\\.-]")
	scoped                              = regexp.MustCompile(`^([^\@]+)\@([a-zA-Z0-9][a-zA-Z0-9\.-]+[a-zA-Z0-9])$`)
	dkcprpreg                           = regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	allowedDigestAndSignatureAlgorithms = []string{"sha256", "sha384", "sha512"}
	defaultDigestAndSignatureAlgorithm  = "sha256"

	metadataUpdateGuard chan int

	session = wayfHybridSession{}

	sloInfoCookie, authnRequestCookie *gosaml.Hm
	tmpl                              *template.Template
	hostName                          string

	hubMd *goxml.Xp

	md mdSets

	intExtSP, intExtIDP, hubExtIDP, hubExtSP gosaml.MdSets

	hubIdpCerts []string

	webMdMap map[string]webMd
)

// Main - start the hybrid
func Main() {
	log.SetFlags(0) // no predefined time
	//log.SetOutput(new(logWriter))
	hostName, _ = os.Hostname()

	bypassMdUpdate := flag.Bool("nomd", false, "bypass MD update at start")
	flag.Parse()
	path := Env("WAYF_PATH", "/opt/wayf/")

	tomlConfig, err := toml.LoadFile(path + "hybrid-config/hybrid-config.toml")

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %s", err))
	}
	err = tomlConfig.Unmarshal(&config)
	if err != nil {
		panic(fmt.Errorf("fatal error %s", err))
	}

	overrideConfig(&config, []string{"EptidSalt"})
	overrideConfig(&config.GoEleven, []string{"SlotPassword"})

	if config.GoEleven.SlotPassword != "" {
		c := config.GoEleven
		goeleven.LibraryInit(map[string]string{
			"GOELEVEN_HSMLIB":        c.Hsmlib,
			"GOELEVEN_USERTYPE":      c.Usertype,
			"GOELEVEN_SERIALNUMBER":  c.Serialnumber,
			"GOELEVEN_SLOT":          c.Slot,
			"GOELEVEN_SLOT_PASSWORD": c.SlotPassword,
			"GOELEVEN_KEY_LABEL":     c.KeyLabel,
			"GOELEVEN_MAXSESSIONS":   c.Maxsessions,
		})
	}

	tmpl = template.Must(template.ParseFiles(path + "hybrid-config/templates/hybrid.tmpl"))
	gosaml.PostForm = tmpl

	metadataUpdateGuard = make(chan int, 1)

	goxml.Algos[""] = goxml.Algos[defaultDigestAndSignatureAlgorithm]

	md.Hub = &lmdq.MDQ{Path: config.Hub.Path, Table: config.Hub.Table, Rev: config.Hub.Table, Short: "hub"}
	md.Internal = &lmdq.MDQ{Path: config.Internal.Path, Table: config.Internal.Table, Rev: config.Internal.Table, Short: "int"}
	md.ExternalIDP = &lmdq.MDQ{Path: config.ExternalIDP.Path, Table: config.ExternalIDP.Table, Rev: config.ExternalSP.Table, Short: "idp"}
	md.ExternalSP = &lmdq.MDQ{Path: config.ExternalSP.Path, Table: config.ExternalSP.Table, Rev: config.ExternalIDP.Table, Short: "sp"}

	intExtSP = gosaml.MdSets{md.Internal, md.ExternalSP}
	intExtIDP = gosaml.MdSets{md.Internal, md.ExternalIDP}
	hubExtIDP = gosaml.MdSets{md.Hub, md.ExternalIDP}
	hubExtSP = gosaml.MdSets{md.Hub, md.ExternalSP}

	str, err := refreshAllMetadataFeeds(!*bypassMdUpdate)
	log.Printf("refreshAllMetadataFeeds: %s %v\n", str, err)

	webMdMap = make(map[string]webMd)
	for _, md := range []*lmdq.MDQ{md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP} {
		err := md.Open()
		if err != nil {
			panic(err)
		}
		webMdMap[md.Table] = webMd{md: md}
		webMdMap[md.Short] = webMd{md: md}
	}

	for _, md := range []*lmdq.MDQ{md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP} {
		m := webMdMap[md.Table]
		m.revmd = webMdMap[md.Rev].md
	}

	hubMd, err = md.Hub.MDQ(config.HubEntityID)
	if err != nil {
		panic(err)
	}

	hubIdpCerts = hubMd.QueryMulti(nil, "md:IDPSSODescriptor"+gosaml.SigningCertQuery) //

	godiscoveryservice.Config = godiscoveryservice.Conf{
		DiscoMetaData: config.Discometadata,
		SpMetaData:    config.Discospmetadata,
	}

	gosaml.Config = gosaml.Conf{
		SamlSchema: config.SamlSchema,
		CertPath:   config.CertPath,
	}

	hashKey, _ := hex.DecodeString(config.SecureCookieHashKey)
	authnRequestCookie = &gosaml.Hm{authnRequestTTL, sha256.New, hashKey}
	gosaml.AuthnRequestCookie = authnRequestCookie
	sloInfoCookie = &gosaml.Hm{sloInfoTTL, sha256.New, hashKey}

	httpMux := http.NewServeMux()

	for _, pattern := range config.NotFoundRoutes {
		httpMux.Handle(pattern, http.NotFoundHandler())
	}

	httpMux.Handle("/production", appHandler(OkService))
	httpMux.Handle(config.Vvpmss, appHandler(VeryVeryPoorMansScopingService))
	httpMux.Handle(config.SsoService, appHandler(SSOService))
	httpMux.Handle(config.Oauth, appHandler(SSOService))
	httpMux.Handle(config.Idpslo, appHandler(IDPSLOService))
	httpMux.Handle(config.Birkslo, appHandler(BirkSLOService))
	httpMux.Handle(config.Spslo, appHandler(SPSLOService))
	httpMux.Handle(config.Kribslo, appHandler(KribSLOService))
	httpMux.Handle(config.Nemloginslo, appHandler(SPSLOService))

	httpMux.Handle(config.Acs, appHandler(ACSService))
	httpMux.Handle(config.NemloginAcs, appHandler(ACSService))
	httpMux.Handle(config.Birk, appHandler(SSOService))
	httpMux.Handle(config.Krib, appHandler(ACSService))
	httpMux.Handle(config.Dsbackend, appHandler(godiscoveryservice.DSBackend))
	httpMux.Handle(config.Dstiming, appHandler(godiscoveryservice.DSTiming))
	httpMux.Handle(config.Public, http.FileServer(http.Dir(config.Discopublicpath)))

	httpMux.Handle(config.Saml2jwt, appHandler(saml2jwt))
	httpMux.Handle(config.Jwt2saml, appHandler(jwt2saml))
	httpMux.Handle(config.MDQ, appHandler(MDQWeb))

	httpMux.Handle(config.TestSPSlo, appHandler(testSPService))
	httpMux.Handle(config.TestSPAcs, appHandler(testSPService))
	httpMux.Handle(config.TestSP+"/", appHandler(testSPService)) // need a root "/" for routing

	httpMux.Handle(config.TestSP2Slo, appHandler(testSPService))
	httpMux.Handle(config.TestSP2Acs, appHandler(testSPService))
	httpMux.Handle(config.TestSP2+"/", appHandler(testSPService)) // need a root "/" for routing

	finish := make(chan bool)

	go func() {
		log.Println("listening on ", config.Intf)
		err = http.ListenAndServeTLS(config.Intf, config.HTTPSCert, config.HTTPSKey, &slashFix{httpMux})
		if err != nil {
			log.Printf("main(): %s\n", err)
		}
	}()

	mdUpdateMux := http.NewServeMux()
	mdUpdateMux.Handle("/", appHandler(updateMetadataService)) // need a root "/" for routing

	go func() {
		intf := regexp.MustCompile(`^(.*:).*$`).ReplaceAllString(config.Intf, "$1") + "9000"
		log.Println("listening on ", intf)
		err = http.ListenAndServe(intf, mdUpdateMux)
		if err != nil {
			log.Printf("main(): %s\n", err)
		}
	}()

	<-finish
}

func Env(name, defaultvalue string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	return defaultvalue
}

func overrideConfig(config interface{}, envvars []string) {
	for _, k := range envvars {
		envvar := strings.ToUpper("WAYF_" + k)
		log.Println(envvar)
		if val, ok := os.LookupEnv(envvar); ok {
			reflect.ValueOf(config).Elem().FieldByName(k).Set(reflect.ValueOf(val))
		}
	}
}

func (h *slashFix) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.URL.Path = strings.Replace(r.URL.Path, "//", "/", -1)
	h.mux.ServeHTTP(w, r)
}

// Set responsible for setting a cookie values
func (s wayfHybridSession) Set(w http.ResponseWriter, r *http.Request, id, domain string, data []byte, secCookie *gosaml.Hm, maxAge int) (err error) {
	cookie, err := secCookie.Encode(id, data)
	// http.SetCookie(w, &http.Cookie{Name: id, Domain: domain, Value: cookie, Path: "/", Secure: true, HttpOnly: true, MaxAge: maxAge, SameSite: http.SameSiteNoneMode})
	cc := http.Cookie{Name: id, Domain: domain, Value: cookie, Path: "/", Secure: true, HttpOnly: true, MaxAge: maxAge}
	v := cc.String() + "; SameSite=None"
	w.Header().Add("Set-Cookie", v)
	return
}

// Get responsible for getting the cookie values
func (s wayfHybridSession) Get(w http.ResponseWriter, r *http.Request, id string, secCookie *gosaml.Hm) (data []byte, err error) {
	cookie, err := r.Cookie(id)
	if err == nil && cookie.Value != "" {
		data, err = secCookie.Decode(id, cookie.Value)
		if err != nil {
			return
		}
	}
	return
}

// Del responsible for deleting a cookie values
func (s wayfHybridSession) Del(w http.ResponseWriter, r *http.Request, id string, secCookie *gosaml.Hm) (err error) {
	http.SetCookie(w, &http.Cookie{Name: id, Domain: config.Domain, Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1, Expires: time.Unix(0, 0)})
	return
}

// GetDel responsible for getting and then deleting cookie values
func (s wayfHybridSession) GetDel(w http.ResponseWriter, r *http.Request, id string, secCookie *gosaml.Hm) (data []byte, err error) {
	data, err = s.Get(w, r, id, secCookie)
	s.Del(w, r, id, secCookie)
	return
}

// Write refers to writing log data
func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprint(os.Stderr, time.Now().UTC().Format("Jan _2 15:04:05 ")+string(bytes))
}

func legacyLog(stat, tag, idp, sp, hash string) {
	log.Printf("5 %s[%d] %s %s %s %s\n", stat, time.Now().UnixNano(), tag, idp, sp, hash)
}

func legacyStatLog(tag, idp, sp, hash string) {
	legacyLog("STAT ", tag, idp, sp, hash)
}

// Mar 13 14:09:07 birk-03 birk[16805]: 5321bc0335b24 {} ...
func legacyStatJSONLog(rec map[string]string) {
	b, _ := json.Marshal(rec)
	log.Printf("%d %s\n", time.Now().UnixNano(), b)
}

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remoteAddr := r.RemoteAddr
	if ra, ok := r.Header["X-Forwarded-For"]; ok {
		remoteAddr = ra[0]
	}

	//log.Printf("%s %s %s %+v", remoteAddr, r.Method, r.Host, r.URL)
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

// updateMetadataService is service for updating metadata feed
func updateMetadataService(w http.ResponseWriter, r *http.Request) (err error) {
	if str, err := refreshAllMetadataFeeds(true); err == nil {
		io.WriteString(w, str)
	}
	return
}

// refreshAllMetadataFeeds is responsible for referishing all metadata feed(internal, external)
func refreshAllMetadataFeeds(refresh bool) (str string, err error) {
	if !refresh {
		return "bypassed", nil
	}
	select {
	case metadataUpdateGuard <- 1:
		{
			for _, mdfeed := range config.MetadataFeeds {
				if err = refreshMetadataFeed(mdfeed.Path, mdfeed.URL); err != nil {
					<-metadataUpdateGuard
					return "", err
				}
			}
			for _, md := range []gosaml.Md{md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP} {
				err := md.(*lmdq.MDQ).Open()
				if err != nil {
					panic(err)
				}
			}
			godiscoveryservice.MetadataUpdated()
			<-metadataUpdateGuard
			return "Pong", nil
		}
	default:
		{
			return "Ignored", nil
		}
	}
}

// refreshMetadataFeed is responsible for referishing a metadata feed
func refreshMetadataFeed(mddbpath, url string) (err error) {
	dir := path.Dir(mddbpath)
	tempmddb, err := ioutil.TempFile(dir, "")
	if err != nil {
		return err
	}
	defer tempmddb.Close()
	defer os.Remove(tempmddb.Name())
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(tempmddb, resp.Body)
	if err != nil {
		return err
	}
	if err = os.Rename(tempmddb.Name(), mddbpath); err != nil {
		return err
	}
	return
}

func testSPService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	type testSPFormData struct {
		Protocol, RelayState, ResponsePP, Issuer, Destination, External, ScopedIDP string
		Messages                                                                   string
		AttrValues, DebugValues                                                    []attrValue
	}

	spMd, err := md.Internal.MDQ("https://" + r.Host)
	pk, _, _ := gosaml.GetPrivateKey(spMd)
	idp := r.Form.Get("idpentityid")
	idpList := r.Form.Get("idplist")
	login := r.Form.Get("login") == "1"

	if login || idp != "" || idpList != "" {

		if err != nil {
			return err
		}
		idpMd, err := md.Hub.MDQ(config.HubEntityID)
		if err != nil {
			return err
		}

		if idp == "" {
			data := url.Values{}
			data.Set("return", "https://"+r.Host+r.RequestURI)
			data.Set("returnIDParam", "idpentityid")
			data.Set("entityID", "https://"+r.Host)
			http.Redirect(w, r, config.DiscoveryService+data.Encode(), http.StatusFound)
			return err
		}

		http.SetCookie(w, &http.Cookie{Name: "idpentityID", Value: idp, Path: "/", Secure: true, HttpOnly: false})

		scopedIDP := r.Form.Get("scopedidp") + r.Form.Get("entityID")
		scoping := []string{}
		if r.Form.Get("scoping") == "scoping" {
			scoping = strings.Split(scopedIDP, ",")
		}

		if r.Form.Get("scoping") == "birk" {
			idpMd, err = md.ExternalIDP.MDQ(scopedIDP)
			if err != nil {
				return err
			}
		}

		newrequest, _ := gosaml.NewAuthnRequest(nil, spMd, idpMd, "", scoping, "", false, 0, 0)

		options := []struct{ name, path, value string }{
			{"isPassive", "./@IsPassive", "true"},
			{"forceAuthn", "./@ForceAuthn", "true"},
			{"persistent", "./samlp:NameIDPolicy/@Format", gosaml.Persistent},
		}

		for _, option := range options {
			if r.Form.Get(option.name) != "" {
				newrequest.QueryDashP(nil, option.path, option.value, nil)
			}
		}

		u, err := gosaml.SAMLRequest2URL(newrequest, "", string(pk), "-", "") // not signed so blank key, pw and algo
		if err != nil {
			return err
		}

		q := u.Query()

		if gosaml.DebugSetting(r, "signingError") == "1" {
			signature := q.Get("Signature")
			q.Set("Signature", signature[:len(signature)-4]+"QEBA")
		}

		if idpList != "" {
			q.Set("idplist", idpList)
		}
		if r.Form.Get("scoping") == "param" {
			idp = scopedIDP
		}
		if idp != "" {
			q.Set("idplist", idp)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	} else if r.Form.Get("logout") == "1" || r.Form.Get("logoutresponse") == "1" {
		spMd, _, err := gosaml.FindInMetadataSets(gosaml.MdSets{md.Internal, md.ExternalSP}, r.Form.Get("destination"))
		if err != nil {
			return err
		}
		idpMd, _, err := gosaml.FindInMetadataSets(gosaml.MdSets{md.Hub, md.ExternalIDP}, r.Form.Get("issuer"))
		if err != nil {
			return err
		}
		if r.Form.Get("logout") == "1" {
			gosaml.SloRequest(w, r, goxml.NewXpFromString(r.Form.Get("response")), spMd, idpMd, string(pk))
		} else {
			gosaml.SloResponse(w, r, goxml.NewXpFromString(r.Form.Get("response")), spMd, idpMd, string(pk))
		}
	} else if r.Form.Get("SAMLRequest") != "" || r.Form.Get("SAMLResponse") != "" {
		// try to decode SAML message to ourselves or just another SP
		// don't do destination check - we accept and dumps anything ...
		external := "0"
		messages := "none"
		response, issuerMd, destinationMd, relayState, _, _, err := gosaml.DecodeSAMLMsg(r, hubExtIDP, gosaml.MdSets{md.Internal}, gosaml.SPRole, []string{"Response", "LogoutRequest", "LogoutResponse"}, "https://"+r.Host+r.URL.Path, nil)
		if err != nil {
			return err
		}

		var vals, debugVals []attrValue
		incomingResponseXML := response.PP()
		protocol := response.QueryString(nil, "local-name(/*)")
		if protocol == "Response" {
			if err := gosaml.CheckDigestAndSignatureAlgorithms(response, allowedDigestAndSignatureAlgorithms, issuerMd.QueryMulti(nil, xprefix+"SigningMethod")); err != nil {
				return err
			}
			vals = attributeValues(response, destinationMd, hubMd)
			Attributesc14n(response, response, issuerMd, destinationMd)
			err = wayfScopeCheck(response, issuerMd)
			if err != nil {
				messages = err.Error()
			}
			debugVals = attributeValues(response, destinationMd, hubMd)
		}

		data := testSPFormData{RelayState: relayState, ResponsePP: incomingResponseXML, Destination: destinationMd.Query1(nil, "./@entityID"), Messages: messages,
			Issuer: issuerMd.Query1(nil, "./@entityID"), External: external, Protocol: protocol, AttrValues: vals, DebugValues: debugVals, ScopedIDP: response.Query1(nil, "//saml:AuthenticatingAuthority")}
		return tmpl.ExecuteTemplate(w, "testSPForm", data)
	} else if r.Form.Get("ds") != "" {
		data := url.Values{}
		data.Set("return", "https://"+r.Host+r.RequestURI+"?previdplist="+r.Form.Get("scopedidp"))
		data.Set("returnIDParam", "scopedidp")
		data.Set("entityID", "https://"+r.Host)
		http.Redirect(w, r, config.DiscoveryService+data.Encode(), http.StatusFound)
	} else {
		data := testSPFormData{ScopedIDP: strings.Trim(r.Form.Get("scopedidp")+","+r.Form.Get("previdplist"), " ,")}
		return tmpl.ExecuteTemplate(w, "testSPForm", data)
	}
	return
}

// attributeValues returns all the attribute values
func attributeValues(response, destinationMd, hubMd *goxml.Xp) (values []attrValue) {
	seen := map[string]bool{}
	requestedAttributes := destinationMd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		name := destinationMd.Query1(requestedAttribute, "@Name")
		friendlyName := destinationMd.Query1(requestedAttribute, "@FriendlyName")
		seen[name] = true
		seen[friendlyName] = true

		must := hubMd.Query1(nil, `.//md:RequestedAttribute[@Name=`+strconv.Quote(name)+`]/@must`) == "true"

		// accept attributes in both uri and basic format
		attrValues := response.QueryMulti(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+` or @Name=`+strconv.Quote(friendlyName)+`]/saml:AttributeValue`)
		values = append(values, attrValue{Name: friendlyName, Must: must, Values: attrValues})
	}

	for _, name := range response.QueryMulti(nil, ".//saml:Attribute/@Name") {
		if seen[name] {
			continue
		}
		attrValues := response.QueryMulti(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+`]/saml:AttributeValue`)
		friendlyName := response.Query1(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+`]/@FriendlyName`)
		if friendlyName != "" {
			name = friendlyName
		}
		values = append(values, attrValue{Name: name, Must: false, Values: attrValues})
	}
	return
}

// checkForCommonFederations checks for common federation in sp and idp
func checkForCommonFederations(response *goxml.Xp) (err error) {
	if response.Query1(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='commonfederations']/saml:AttributeValue[1]") != "true" {
		err = fmt.Errorf("no common federations")
	}
	return
}

func wayfScopeCheck(response, idpMd *goxml.Xp) (err error) {
	as := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
	if response.QueryBool(as, "count(saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue) != 1") {
		err = fmt.Errorf("isRequired: eduPersonPrincipalName")
		return
	}

	eppn := response.Query1(as, "saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
	securitydomain := response.Query1(as, "./saml:Attribute[@Name='securitydomain']/saml:AttributeValue")
	if securitydomain == "" {
		err = fmt.Errorf("not a scoped value: %s", eppn)
		return
	}

	if idpMd.QueryBool(nil, "count(//shibmd:Scope[.="+strconv.Quote(securitydomain)+"]) = 0") {
		err = fmt.Errorf("security domain '%s' does not match any scopes", securitydomain)
		return
	}

	subsecuritydomain := response.Query1(as, "./saml:Attribute[@Name='subsecuritydomain']/saml:AttributeValue")
	for _, epsa := range response.QueryMulti(as, "./saml:Attribute[@Name='eduPersonScopedAffiliation']/saml:AttributeValue") {
		epsaparts := scoped.FindStringSubmatch(epsa)
		if len(epsaparts) != 3 {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", epsa)
			return
		}
		domain := epsaparts[2]
		if domain != subsecuritydomain && !strings.HasSuffix(domain, "."+subsecuritydomain) {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s has not '%s' as security sub domain", epsa, subsecuritydomain)
			return
		}
	}
	return
}

func wayfACSServiceHandler(idpMd, hubMd, spMd, request, response *goxml.Xp, birk bool) (ard AttributeReleaseData, err error) {
	ard = AttributeReleaseData{IDPDisplayName: make(map[string]string), SPDisplayName: make(map[string]string), SPDescription: make(map[string]string)}
	idp := idpMd.Query1(nil, "@entityID")

	if err = wayfScopeCheck(response, idpMd); err != nil {
		return
	}

	arp := spMd.QueryMulti(nil, "md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute/@Name")
	arpmap := make(map[string]bool)
	for _, attrName := range arp {
		arpmap[attrName] = true
	}

	ard.IDPDisplayName["en"] = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.IDPDisplayName["da"] = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.IDPLogo = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.IDPEntityID = idp
	ard.SPDisplayName["en"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.SPDisplayName["da"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.SPDescription["en"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]`)
	ard.SPDescription["da"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="da"]`)
	ard.SPLogo = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.SPEntityID = spMd.Query1(nil, "@entityID")
	ard.BypassConfirmation = idpMd.QueryBool(nil, `count(`+xprefix+`consent.disable[.= `+strconv.Quote(ard.SPEntityID)+`]) > 0`)
	ard.BypassConfirmation = ard.BypassConfirmation || spMd.QueryXMLBool(nil, xprefix+`consent.disable`)
	ard.ConsentAsAService = config.ConsentAsAService

	if birk {
		//Jun 19 09:42:58 birk-06 birk[18847]: 1529401378 {"action":"send","type":"samlp:Response","us":"https:\/\/birk.wayf.dk\/birk.php\/nemlogin.wayf.dk","destination":"https:\/\/europe.wiseflow.net","ip":"109.105.112.132","ts":1529401378,"host":"birk-06","logtag":1529401378}
		var jsonlog = map[string]string{
			"action":      "send",
			"type":        "samlp:Response",
			"us":          ard.IDPEntityID,
			"destination": ard.SPEntityID,
			"ip":          "0.0.0.0",
			"ts":          strconv.FormatInt(time.Now().Unix(), 10),
			"host":        hostName,
			"logtag":      strconv.FormatInt(time.Now().UnixNano(), 10),
		}
		legacyStatJSONLog(jsonlog)
	}
	eppn := response.Query1(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
	hashedEppn := fmt.Sprintf("%x", goxml.Hash(crypto.SHA256, config.SaltForHashedEppn+eppn))
	legacyStatLog("saml20-idp-SSO", ard.SPEntityID, idp, hashedEppn)
	return
}

func wayfKribHandler(idpMd, spMd, request, response *goxml.Xp) (ard AttributeReleaseData, err error) {
	// we ignore the qualifiers and use the idp and sp entityIDs
	as := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
	securitydomain := response.Query1(as, "./saml:Attribute[@Name='securitydomain']/saml:AttributeValue")
	eppn := response.Query1(as, "./saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
	if eppn != "" && idpMd.QueryBool(nil, "count(//shibmd:Scope[.="+strconv.Quote(securitydomain)+"]) = 0") {
		err = fmt.Errorf("security domain '%s' does not match any scopes", securitydomain)
		return
	}

	for _, epsa := range response.QueryMulti(as, "./saml:Attribute[@Name='eduPersonScopedAffiliation']/saml:AttributeValue") {
		epsaparts := scoped.FindStringSubmatch(epsa)
		if len(epsaparts) != 3 {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", epsa)
			return
		}
		domain := epsaparts[2]
		if idpMd.QueryBool(nil, "count(//shibmd:Scope[.="+strconv.Quote(domain)+"]) = 0") {
			err = fmt.Errorf("security domain '%s' does not match any scopes", securitydomain)
			return
		}
	}
	ard = AttributeReleaseData{BypassConfirmation: true}
	return
}

// OkService - exits with eror of HSM is unavailable
func OkService(w http.ResponseWriter, r *http.Request) (err error) {
	err = goeleven.HSMStatus()
	if err != nil {
		os.Exit(1)
	}
	return
}

// VeryVeryPoorMansScopingService handles poor man's scoping
func VeryVeryPoorMansScopingService(w http.ResponseWriter, r *http.Request) (err error) {
	http.SetCookie(w, &http.Cookie{Name: "vvpmss", Value: r.URL.Query().Get("idplist"), Path: "/", Secure: true, HttpOnly: true, MaxAge: 10})
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, hostName+"\n")
	return
}

func wayf(w http.ResponseWriter, r *http.Request, request, spMd, idpMd *goxml.Xp) (idp string) {
	if idp = idpMd.Query1(nil, "@entityID"); idp != config.HubEntityID { // no need for wayf if idp is birk entity - ie. not the hub
		return
	}
	sp := spMd.Query1(nil, "@entityID") // real entityID == KRIB entityID
	data := url.Values{}
	vvpmss := ""
	if tmp, _ := r.Cookie("vvpmss"); tmp != nil {
		vvpmss = tmp.Value
		http.SetCookie(w, &http.Cookie{Name: "vvpmss", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	}

	testidp := ""
	if tmp, _ := r.Cookie("testidp"); tmp != nil {
		testidp = tmp.Value
		http.SetCookie(w, &http.Cookie{Name: "testidp", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	}

	idpLists := [][]string{
		{testidp},
		spMd.QueryMulti(nil, xprefix+"IDPList"),
		request.QueryMulti(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID"),
		{r.URL.Query().Get("idpentityid")},
		strings.Split(r.URL.Query().Get("idplist"), ","),
		strings.Split(vvpmss, ",")}

	for _, idpList := range idpLists {
		switch len(idpList) {
		case 0:
			continue
		case 1:
			if idpList[0] != "" {
				return idpList[0]
			}
		default:
			data.Set("idplist", strings.Join(idpList, ","))
			break
		}
	}

	data.Set("return", "https://"+r.Host+r.RequestURI)
	data.Set("returnIDParam", "idpentityid")
	data.Set("entityID", sp)
	http.Redirect(w, r, config.DiscoveryService+data.Encode(), http.StatusFound)
	return "" // needed to tell our caller to return for discovery ...
}

// SSOService handles single sign on requests
func SSOService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	request, spMd, hubBirkMd, relayState, spIndex, hubBirkIndex, err := gosaml.ReceiveAuthnRequest(r, intExtSP, hubExtIDP, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}

	VirtualIDPID := wayf(w, r, request, spMd, hubBirkMd)
	if VirtualIDPID == "" {
		return
	}
	virtualIDPMd, virtualIDPIndex, err := gosaml.FindInMetadataSets(intExtIDP, VirtualIDPID) // find in internal also if birk
	if err != nil {
		return
	}
	VirtualIDPID = virtualIDPMd.Query1(nil, "./@entityID") // wayf might return domain or hash ...

	// check for common feds before remapping!
	if _, err = RequestHandler(request, virtualIDPMd, spMd); err != nil {
		return
	}

	realIDPMd := virtualIDPMd
	var hubKribSPMd *goxml.Xp
	if virtualIDPIndex == 0 { // to internal IDP - also via BIRK
		hubKribSP := config.HubEntityID
		if tmp := virtualIDPMd.Query1(nil, xprefix+"map2SP"); tmp != "" {
			hubKribSP = tmp
		}

		if hubKribSPMd, err = md.Hub.MDQ(hubKribSP); err != nil {
			return
		}

		realIDP := virtualIDPMd.Query1(nil, xprefix+"map2IdP")

		if realIDP != "" {
			realIDPMd, err = md.Internal.MDQ(realIDP)
			if err != nil {
				return
			}
		}
	} else { // to external IDP - send as KRIB
		hubKribSPMd, err = md.ExternalSP.MDQ(spMd.Query1(nil, "@entityID"))
		if err != nil {
			return
		}
	}

	err = sendRequestToIDP(w, r, request, spMd, hubKribSPMd, realIDPMd, VirtualIDPID, relayState, "SSO-", "", config.Domain, spIndex, hubBirkIndex, nil)
	return
}

func sendRequestToIDP(w http.ResponseWriter, r *http.Request, request, spMd, hubKribSPMd, realIDPMd *goxml.Xp, virtualIDPID, relayState, prefix, altAcs, domain string, spIndex, hubBirkIndex uint8, idPList []string) (err error) {
	// why not use orig request?
	newrequest, err := gosaml.NewAuthnRequest(request, hubKribSPMd, realIDPMd, virtualIDPID, idPList, altAcs, realIDPMd.QueryXMLBool(nil, xprefix+`wantRequesterID`), spIndex, hubBirkIndex)
	if err != nil {
		return
	}

	var privatekey []byte
	if realIDPMd.QueryXMLBool(nil, `./md:IDPSSODescriptor/@WantAuthnRequestsSigned`) || hubKribSPMd.QueryXMLBool(nil, `./md:SPSSODescriptor/@AuthnRequestsSigned`) {
		privatekey, _, err = gosaml.GetPrivateKey(hubKribSPMd)
		if err != nil {
			return
		}
	}

	algo := realIDPMd.Query1(nil, xprefix+"SigningMethod")

	if sigAlg := gosaml.DebugSetting(r, "idpSigAlg"); sigAlg != "" {
		algo = sigAlg
	}

	u, err := gosaml.SAMLRequest2URL(newrequest, relayState, string(privatekey), "-", algo)
	if err != nil {
		return
	}

	legacyLog("", "SAML2.0 - IDP.SSOService: Incomming Authentication request:", "'"+request.Query1(nil, "./saml:Issuer")+"'", "", "")
	if hubBirkIndex == 1 {
		var jsonlog = map[string]string{
			"action": "receive",
			"type":   "samlp:AuthnRequest",
			"src":    request.Query1(nil, "./saml:Issuer"),
			"us":     virtualIDPID,
			"ip":     r.RemoteAddr,
			"ts":     strconv.FormatInt(time.Now().Unix(), 10),
			"host":   hostName,
			"logtag": strconv.FormatInt(time.Now().UnixNano(), 10),
		}

		legacyStatJSONLog(jsonlog)
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func getOriginalRequest(w http.ResponseWriter, r *http.Request, response *goxml.Xp, issuerMdSets, destinationMdSets gosaml.MdSets, prefix string) (spMd, hubBirkIDPMd, virtualIDPMd, request *goxml.Xp, sRequest gosaml.SamlRequest, err error) {
	gosaml.DumpFileIfTracing(r, response)
	inResponseTo := response.Query1(nil, "./@InResponseTo")[1:]
	// value, err := session.GetDel(w, r, prefix+gosaml.IDHash(inResponseTo), authnRequestCookie)
	// extract the original request from @inResponseTo
	value := []byte{}
	value, err = authnRequestCookie.SpcDecode("id", inResponseTo, gosaml.SRequestPrefixLength)
	if err != nil {
		return
	}

	sRequest.Unmarshal(value)

	// we need to disable the replay attack mitigation based on the cookie - we are now fully dependent on the ttl on the data - pt. 3 mins
	//	if inResponseTo != sRequest.Nonce {
	//		err = fmt.Errorf("response.InResponseTo != request.ID")
	//		return
	//	}

	if sRequest.RequestID == "" { // This is a non-hub request - no original actual original request - just checking if response/@InResponseTo == request/@ID
		return nil, nil, nil, nil, sRequest, nil
	}

	if spMd, err = issuerMdSets[sRequest.SPIndex].MDQ(sRequest.SP); err != nil {
		return
	}

	if virtualIDPMd, err = md.ExternalIDP.MDQ(sRequest.VirtualIDPID); err != nil {
		return
	}

	hubBirkIDPMd = virtualIDPMd     // who to send the response as - BIRK
	if sRequest.HubBirkIndex == 0 { // or hub is request was to the hub
		if hubBirkIDPMd, err = md.Hub.MDQ(config.HubEntityID); err != nil {
			return
		}
	}

	request = goxml.NewXpFromString("")
	request.QueryDashP(nil, "/samlp:AuthnRequest/@ID", sRequest.RequestID, nil)
	//request.QueryDashP(nil, "./@Destination", sRequest.De, nil)

	acs := spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+gosaml.POST+`" and @index=`+strconv.Quote(sRequest.AssertionConsumerIndex)+`]/@Location`)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", acs, nil)
	request.QueryDashP(nil, "./saml:Issuer", sRequest.SP, nil)
	request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", gosaml.NameIDList[sRequest.NameIDFormat], nil)
	return
}

// ACSService handles all the stuff related to receiving response and attribute handling
func ACSService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, hubKribSpMd, relayState, _, hubKribSpIndex, err := gosaml.ReceiveSAMLResponse(r, intExtIDP, hubExtSP, "https://"+r.Host+r.URL.Path, hubIdpCerts)
	if err != nil {
		return
	}
	spMd, hubBirkIDPMd, virtualIDPMd, request, sRequest, err := getOriginalRequest(w, r, response, intExtSP, hubExtIDP, "SSO-")
	if err != nil {
		return
	}

	if err = gosaml.CheckDigestAndSignatureAlgorithms(response, allowedDigestAndSignatureAlgorithms, virtualIDPMd.QueryMulti(nil, xprefix+"SigningMethod")); err != nil {
		return
	}

	signingMethod := spMd.Query1(nil, xprefix+"SigningMethod")

	var newresponse *goxml.Xp
	var ard AttributeReleaseData
	if response.Query1(nil, `samlp:Status/samlp:StatusCode/@Value`) == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		Attributesc14n(request, response, virtualIDPMd, spMd)
		if err = checkForCommonFederations(response); err != nil {
			return
		}
		if hubKribSpIndex == 0 { // to the hub itself
			ard, err = wayfACSServiceHandler(virtualIDPMd, hubMd, spMd, request, response, sRequest.HubBirkIndex == 1)
		} else { // krib
			ard, err = wayfKribHandler(virtualIDPMd, spMd, request, response)
		}
		if err != nil {
			return goxml.Wrap(err)
		}

		if gosaml.DebugSetting(r, "scopingError") != "" {
			eppnPath := `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`
			response.QueryDashP(nil, eppnPath, response.Query1(nil, eppnPath)+"1", nil)
		}

		newresponse = gosaml.NewResponse(hubBirkIDPMd, spMd, request, response)

		// add "front-end" IDP if it maps to another IDP
		if virtualIDPMd.Query1(nil, xprefix+"map2IdP") != "" {
			newresponse.QueryDashP(nil, "./saml:Assertion/saml:AuthnStatement/saml:AuthnContext/saml:AuthenticatingAuthority[0]", virtualIDPMd.Query1(nil, "@entityID"), nil)
		}

		ard.Values, ard.Hash = CopyAttributes(response, newresponse, spMd)

		nameidElement := newresponse.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
		nameidformat := request.Query1(nil, "./samlp:NameIDPolicy/@Format")
		nameid := response.Query1(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="nameID"]/saml:AttributeValue`)

		newresponse.QueryDashP(nameidElement, "@Format", nameidformat, nil)
		newresponse.QueryDashP(nameidElement, ".", nameid, nil)

		if sRequest.Protocol == "oauth" {
			/* 	payload := map[string]interface{}{}
			payload["aud"] = newresponse.Query1(nil, "//saml:Audience")
			payload["iss"] = newresponse.Query1(nil, "./saml:Issuer")
			payload["iat"] = gosaml.SamlTime2JwtTime(newresponse.Query1(nil, "./@IssueInstant"))
			payload["exp"] = gosaml.SamlTime2JwtTime(newresponse.Query1(nil, "//@SessionNotOnOrAfter"))
			payload["sub"] = newresponse.Query1(nil, "//saml:NameID")
			payload["appid"] = newresponse.Query1(nil, "./saml:Issuer")
			payload["apptype"] = "Public"
			payload["authmethod"] = newresponse.Query1(nil, "//saml:AuthnContextClassRef")
			payload["auth_time"] = newresponse.Query1(nil, "//@AuthnInstant")
			payload["ver"] = "1.0"
			payload["scp"] = "openid profile"
			for _, attr := range newresponse.Query(nil, "//saml:Attribute") {
				payload[newresponse.Query1(attr, "@Name")] = newresponse.QueryMulti(attr, "./saml:AttributeValue")
			}

			privatekey, _, err := gosaml.GetPrivateKey(virtualIDPMd)
			if err != nil {
				return err
			}

			body, err := json.Marshal(payload)
			if err != nil {
				return err
			}
			privatekey = []byte("8Bw5iJEpH2XaD7Bw2H3iPsRhISBsQ3IipFko8YJ6vIiq4e27SKTDa7MAnrP5PwjT")
			accessToken, atHash, err := gosaml.JwtSign(body, privatekey, "HS256")
			if err != nil {
				return err
			}

			payload["nonce"] = sRequest.RequestID
			payload["at_hash"] = atHash
			body, err = json.Marshal(payload)
			if err != nil {
				return err
			}

			idToken, _, err := gosaml.JwtSign(body, privatekey, "HS256")
			if err != nil {
				return err
			}

			u := url.Values{}
			// do not use a parametername that sorts before access_token !!!

			//u.Set("access_token", accessToken)
			//u.Set("id_token", idToken) */
			u := url.Values{}

			u.Set("state", relayState)
			//u.Set("token_type", "bearer")
			//u.Set("expires_in", "3600")
			u.Set("scope", "openid group")
			u.Set("code", "ABCDEFHIJKLMNOPQ")
			//http.Redirect(w, r, fmt.Sprintf("%s#%s", newresponse.Query1(nil, "@Destination"), u.Encode()), http.StatusFound)
			http.Redirect(w, r, newresponse.Query1(nil, "@Destination")+"?"+u.Encode(), http.StatusFound)
			return nil
		}

		// gosaml.NewResponse only handles simple attr values so .. send correct eptid to eduGAIN entities
		if spMd.QueryBool(nil, "count("+xprefix+"feds[.='eduGAIN']) > 0") {
			if eptidAttr := newresponse.Query(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.10"]`); eptidAttr != nil {
				value := newresponse.Query1(eptidAttr[0], "./saml:AttributeValue")
				newresponse.Rm(eptidAttr[0], "./saml:AttributeValue")
				newresponse.QueryDashP(eptidAttr[0], "./saml:AttributeValue/saml:NameID", value, nil)
			}
		}

		if sigAlg := gosaml.DebugSetting(r, "spSigAlg"); sigAlg != "" {
			signingMethod = sigAlg
		}

		elementsToSign := config.ElementsToSign
		if spMd.QueryXMLBool(nil, xprefix+"saml20.sign.response") {
			elementsToSign = []string{"/samlp:Response"}
		}

		// We don't mark ws-fed RPs in md - let the request decide - use the same attributenameformat for all attributes
		signingType := gosaml.SAMLSign
		if sRequest.Protocol == "wsfed" {
			newresponse = gosaml.NewWsFedResponse(hubBirkIDPMd, spMd, newresponse)
			ard.Values, ard.Hash = CopyAttributes(response, newresponse, spMd)

			signingType = gosaml.WSFedSign
			elementsToSign = []string{"./t:RequestedSecurityToken/saml1:Assertion"}
		}

		for _, q := range elementsToSign {
			err = gosaml.SignResponse(newresponse, q, hubBirkIDPMd, signingMethod, signingType)
			if err != nil {
				return err
			}
		}
		SLOInfoHandler(w, r, response, hubKribSpMd, newresponse, spMd, gosaml.SPRole)

		if gosaml.DebugSetting(r, "signingError") == "1" {
			newresponse.QueryDashP(nil, `./saml:Assertion/@ID`, newresponse.Query1(nil, `./saml:Assertion/@ID`)+"1", nil)
		}

		if spMd.QueryXMLBool(nil, xprefix+"assertion.encryption ") || gosaml.DebugSetting(r, "encryptAssertion") == "1" {
			gosaml.DumpFileIfTracing(r, newresponse)
			cert := spMd.Query1(nil, "./md:SPSSODescriptor"+gosaml.EncryptionCertQuery) // actual encryption key is always first
			_, publicKey, _ := gosaml.PublicKeyInfo(cert)
			ea := goxml.NewXpFromString(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
			assertion := newresponse.Query(nil, "saml:Assertion[1]")[0]
			newresponse.Encrypt(assertion, publicKey, ea)
		}
	} else {
		newresponse = gosaml.NewErrorResponse(hubBirkIDPMd, spMd, request, response)

		err = gosaml.SignResponse(newresponse, "/samlp:Response", hubBirkIDPMd, signingMethod, gosaml.SAMLSign)
		if err != nil {
			return
		}
		ard = AttributeReleaseData{BypassConfirmation: true}
	}

	// when consent as a service is ready - we will post to that
	// acs := newresponse.Query1(nil, "@Destination")

	ardjson, err := json.Marshal(ard)
	if err != nil {
		return goxml.Wrap(err)
	}

	gosaml.DumpFileIfTracing(r, newresponse)

	var samlResponse string
	if sRequest.Protocol == "wsfed" {
		samlResponse = string(newresponse.Dump())
	} else {
		samlResponse = base64.StdEncoding.EncodeToString(newresponse.Dump())
	}
	data := gosaml.Formdata{WsFed: sRequest.Protocol == "wsfed", Acs: request.Query1(nil, "./@AssertionConsumerServiceURL"), Samlresponse: samlResponse, RelayState: relayState, Ard: template.JS(ardjson)}
	return tmpl.ExecuteTemplate(w, "attributeReleaseForm", data)
}

// IDPSLOService refers to idp single logout service. Takes request as a parameter and returns an error if any
func IDPSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, md.Internal, md.Hub, []gosaml.Md{md.ExternalSP, md.Hub}, []gosaml.Md{md.Internal, md.ExternalIDP}, gosaml.IDPRole, "SLO")
}

// SPSLOService refers to SP single logout service. Takes request as a parameter and returns an error if any
func SPSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, md.Internal, md.Hub, []gosaml.Md{md.ExternalIDP, md.Hub}, []gosaml.Md{md.Internal, md.ExternalSP}, gosaml.SPRole, "SLO")
}

// BirkSLOService refers to birk single logout service. Takes request as a parameter and returns an error if any
func BirkSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, md.ExternalSP, md.ExternalIDP, []gosaml.Md{md.Hub}, []gosaml.Md{md.Internal}, gosaml.IDPRole, "SLO")
}

// KribSLOService refers to krib single logout service. Takes request as a parameter and returns an error if any
func KribSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, md.ExternalIDP, md.ExternalSP, []gosaml.Md{md.Hub}, []gosaml.Md{md.Internal}, gosaml.SPRole, "SLO")
}

func jwt2saml(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Jwt2saml(w, r, md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP, RequestHandler, hubMd)
}

func saml2jwt(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Saml2jwt(w, r, md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP, RequestHandler, config.HubEntityID, allowedDigestAndSignatureAlgorithms, xprefix+"SigningMethod")
}

// SLOService refers to single logout service. Takes request and issuer and destination metadata sets, role refers to if it as IDP or SP.
func SLOService(w http.ResponseWriter, r *http.Request, issuerMdSet, destinationMdSet gosaml.Md, finalIssuerMdSets, finalDestinationMdSets []gosaml.Md, role int, tag string) (err error) {
	defer r.Body.Close()
	r.ParseForm()
	request, _, destination, relayState, _, _, err := gosaml.ReceiveLogoutMessage(r, gosaml.MdSets{issuerMdSet}, gosaml.MdSets{destinationMdSet}, role)
	if err != nil {
		return err
	}
	var issMD, destMD, msg *goxml.Xp
	var binding string
	sloinfo, returnResponse := SLOInfoHandler(w, r, request, destination, request, nil, role)
    iss, dest := sloinfo.IDP, sloinfo.SP
    if sloinfo.HubRole == gosaml.SPRole {
        dest, iss = iss, dest
    }
	if returnResponse {
		//legacyStatLog("saml20-idp-SLO "+res[role], issuer.Query1(nil, "@entityID"), destination.Query1(nil, "@entityID"), "")

		issMD, _, err = gosaml.FindInMetadataSets(finalIssuerMdSets, iss)
		if err != nil {
			return err
		}
		destMD, _, err = gosaml.FindInMetadataSets(finalDestinationMdSets, dest)
		if err != nil {
			return err
		}

		msg, binding, err = gosaml.NewLogoutResponse(issMD, destMD, sloinfo.ID, int((sloinfo.HubRole+1)%2))
		if err != nil {
			return err
		}
		msg.QueryDashP(nil, "@InResponseTo", sloinfo.ID, nil)
	} else {
		issMD, _, err = gosaml.FindInMetadataSets(finalIssuerMdSets, iss)
		if err != nil {
			return err
		}
		destMD, _, err = gosaml.FindInMetadataSets(finalDestinationMdSets, dest)
		if err != nil {
			return err
		}
		msg, binding, err = gosaml.NewLogoutRequest(destMD, sloinfo, role)
		if err != nil {
			return err
		}
		//async := request.QueryBool(nil, "boolean(./samlp:Extensions/aslo:Asynchronous)")

		//legacyStatLog("saml20-idp-SLO "+req[role], issuer.Query1(nil, "@entityID"), destination.Query1(nil, "@entityID"), sloinfo.NameID+fmt.Sprintf(" async:%t", async))

	}

	privatekey, _, err := gosaml.GetPrivateKey(issMD)

	if err != nil {
		return err
	}

	algo := destMD.Query1(nil, xprefix+"SigningMethod")

	if sigAlg := gosaml.DebugSetting(r, "idpSigAlg"); sigAlg != "" {
		algo = sigAlg
	}
	switch binding {
	case gosaml.REDIRECT:
		u, _ := gosaml.SAMLRequest2URL(msg, relayState, string(privatekey), "-", algo)
		http.Redirect(w, r, u.String(), http.StatusFound)
	case gosaml.POST:
		data := gosaml.Formdata{Acs: msg.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(msg.Dump())}
		return gosaml.PostForm.ExecuteTemplate(w, "postForm", data)

	}
	return
}

// SLOInfoHandler Saves or retrieves the SLO info relevant to the contents of the samlMessage
// For now uses cookies to keep the SLOInfo
func SLOInfoHandler(w http.ResponseWriter, r *http.Request, samlIn, destinationInMd, samlOut, destinationOutMd *goxml.Xp, role int) (sloinfo *gosaml.SLOInfo, sendResponse bool) {
	sil := gosaml.SLOInfoList{}
	data, _ := session.Get(w, r, "SLO", sloInfoCookie)
	_ = json.Unmarshal(data, &sil)

	switch samlIn.QueryString(nil, "local-name(/*)") {
	case "LogoutRequest":
		sloinfo = sil.LogoutRequest(samlIn, destinationInMd.Query1(nil, "@entityID"), uint8(role))
	case "LogoutResponse":
		sloinfo, sendResponse = sil.LogoutResponse(samlIn)
	case "Response":
		sil.Response(samlIn, destinationInMd.Query1(nil, "@entityID"), gosaml.SPRole)
		sil.Response(samlOut, destinationOutMd.Query1(nil, "@entityID"), gosaml.IDPRole)
	}
	bytes, _ := json.Marshal(sil)
	session.Set(w, r, "SLO", config.Domain, bytes, sloInfoCookie, sloInfoTTL)
	return
}

// MDQWeb - thin MDQ web layer on top of lmdq
func MDQWeb(w http.ResponseWriter, r *http.Request) (err error) {
	var rawPath string
	if rawPath = r.URL.RawPath; rawPath == "" {
		rawPath = r.URL.Path
	}
	path := strings.Split(rawPath, "/")[2:] // need a way to do this automatically
	var xml []byte
	var en1, en2 string
	var xp1, xp2 *goxml.Xp
	switch len(path) {
	case 3:
		md, ok := webMdMap[path[1]]
		if !ok {
			return fmt.Errorf("Metadata set not found")
		}
		en1, _ = url.PathUnescape(path[0])
		en2, _ = url.PathUnescape(path[2])
		xp1, _, err = md.md.WebMDQ(en1)
		if err != nil {
			return
		}
		if en1 == en2 { // hack to allow asking for a specific entity, by using the same entity twice
			xp2, xml, err = md.md.WebMDQ(en2)
		} else {
			xp2, xml, err = md.revmd.WebMDQ(en2)
		}
		if err != nil {
			return err
		}
		if !intersectionNotEmpty(xp1.QueryMulti(nil, xprefix+"feds"), xp2.QueryMulti(nil, xprefix+"feds")) {
			return fmt.Errorf("no common federations")
		}
	default:
		return fmt.Errorf("invalid MDQ path")
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	//w.Header().Set("Content-Encoding", "deflate")
	//w.Header().Set("ETag", "abcdefg")
	xml = gosaml.Inflate(xml)
	w.Header().Set("Content-Length", strconv.Itoa(len(xml)))
	w.Write(xml)
	return
}

func intersectionNotEmpty(s1, s2 []string) (res bool) {
	hash := make(map[string]bool)
	for _, e := range s1 {
		hash[e] = true
	}
	for _, e := range s2 {
		if hash[e] {
			return true
		}
	}
	return
}
