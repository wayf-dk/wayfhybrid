package wayfhybrid

import (
	"crypto"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/gorilla/securecookie"
	toml "github.com/pelletier/go-toml"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/godiscoveryservice"
	"github.com/wayf-dk/goeleven/src/goeleven"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lMDQ"
	"github.com/y0ssar1an/q"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	//"net/http/pprof"
	"net/url"
	"os"
	"path"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	_ = q.Q
)

const (
	authnRequestTTL = 180
	sloInfoTTL      = 8 * 3600
	basic           = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
	claims          = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
	unspecified     = "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
	xprefix         = "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:"
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	mddb struct {
		db, table string
	}

	goElevenConfig struct {
		Hsmlib        string
		Usertype      string
		Serialnumber  string
		Slot          string
		Slot_password string
		Key_label     string
		Maxsessions   string
	}

	WayfHybridConfig struct {
		Path                                                                                     string
		DiscoveryService                                                                         string
		Domain                                                                                   string
		HubEntityID                                                                              string
		EptidSalt                                                                                string
		SecureCookieHashKey                                                                      string
		PostFormTemplate                                                                         string
		AttributeReleaseTemplate, WayfSPTestServiceTemplate                                      string
		Certpath                                                                                 string
		Intf, Hubrequestedattributes, Sso_Service, Https_Key, Https_Cert, Acs, Vvpmss            string
		Birk, Krib, Dsbackend, Dstiming, Public, Discopublicpath, Discometadata, Discospmetadata string
		Testsp, Testsp_Acs, Testsp_Slo, Testsp2, Testsp2_Acs, Testsp2_Slo, MDQ                   string
		Eidas_Acs, Nemlogin_Acs, CertPath, SamlSchema, ConsentAsAService                         string
		Idpslo, Birkslo, Spslo, Kribslo, Nemloginslo, Saml2jwt, Jwt2saml, SaltForHashedEppn      string
		ElementsToSign                                                                           []string
		NotFoundRoutes                                                                           []string
		Hub, Internal, ExternalIdP, ExternalSP                                                   struct{ Path, Table string }
		MetadataFeeds                                                                            []struct{ Path, URL string }
		GoEleven                                                                                 goElevenConfig
		IdpRemapSource                                                                           []struct{ Key, Idp, Sp string }
	}

	idpsppair struct {
		Idp string
		Sp  string
	}

	logWriter struct {
	}

	AttributeReleaseData struct {
		Values             map[string][]string
		IdPDisplayName     map[string]string
		IdPLogo            string
		IdPEntityID        string
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

	HybridSession interface {
		Set(http.ResponseWriter, *http.Request, string, []byte) error
		Get(http.ResponseWriter, *http.Request, string) ([]byte, error)
		Del(http.ResponseWriter, *http.Request, string) error
		GetDel(http.ResponseWriter, *http.Request, string) ([]byte, error)
	}

	MdSets struct {
		Hub, Internal, ExternalIdP, ExternalSP *lMDQ.MDQ
	}

	wayfHybridSession struct{}

	// https://stackoverflow.com/questions/47475802/golang-301-moved-permanently-if-request-path-contains-additional-slash
	slashFix struct {
		mux http.Handler
	}

	attrName struct {
		uri, basic, AttributeName string
	}

	attrValue struct {
		Name   string
		Must   bool
		Values []string
	}

	samlRequest struct {
		Nid, Id, Is, De, Acs string
		Fo, SPi, Hubi        int
		WsFed                bool
	}

	webMd struct {
		md, revmd *lMDQ.MDQ
	}
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	config = WayfHybridConfig{Path: "/opt/wayf/"}
    X      = &config

	remap = map[string]idpsppair{}

	bify          = regexp.MustCompile("^(https?://)(.*)$")
	debify        = regexp.MustCompile("^((?:https?://)?)(?:(?:(?:birk|krib)\\.wayf\\.dk/(?:birk\\.php|[a-f0-9]{40})/)|(?:urn:oid:1.3.6.1.4.1.39153:42:))(.+)$")
	allowedInFeds = regexp.MustCompile("[^\\w\\.-]")
	scoped        = regexp.MustCompile(`^([^\@]+)\@([a-zA-Z0-9][a-zA-Z0-9\.-]+[a-zA-Z0-9])(@aau\.dk)?$`)
	aauscope      = regexp.MustCompile(`[@\.]aau\.dk$`)
	dkcprpreg     = regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	allowedDigestAndSignatureAlgorithms = []string{"sha256", "sha384", "sha512"}
	defaultDigestAndSignatureAlgorithm = "sha256"

	metadataUpdateGuard chan int

	session = wayfHybridSession{}

	sloInfoCookie, authnRequestCookie *securecookie.SecureCookie
	attributeReleaseForm    *template.Template
	hashKey                           []byte
	hostName                          string

	hubRequestedAttributes, hubMd *goxml.Xp

	Md        MdSets
	basic2uri map[string]attrName

	intExtSP, intExtIdP, hubExtIdP, hubExtSP gosaml.MdSets

	hubIdpCerts []string

	webMdMap map[string]webMd
)

func Main() {
	log.SetFlags(0) // no predefined time
	//log.SetOutput(new(logWriter))

	bypassMdUpdate := flag.Bool("nomd", false, "bypass MD update at start")
	flag.Parse()

	hostName, _ = os.Hostname()

	overrideConfig(&config, []string{"Path"})

	tomlConfig, err := toml.LoadFile(config.Path + "hybrid-config/hybrid-config.toml")

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s\n", err))
	}
	err = tomlConfig.Unmarshal(&config)
	if err != nil {
		panic(fmt.Errorf("Fatal error %s\n", err))
	}

	overrideConfig(&config, []string{"EptidSalt"})
	overrideConfig(&config.GoEleven, []string{"Slot_password"})

	if config.GoEleven.Slot_password != "" {
		c := config.GoEleven
		goeleven.LibraryInit(map[string]string{
			"GOELEVEN_HSMLIB":        c.Hsmlib,
			"GOELEVEN_USERTYPE":      c.Usertype,
			"GOELEVEN_SERIALNUMBER":  c.Serialnumber,
			"GOELEVEN_SLOT":          c.Slot,
			"GOELEVEN_SLOT_PASSWORD": c.Slot_password,
			"GOELEVEN_KEY_LABEL":     c.Key_label,
			"GOELEVEN_MAXSESSIONS":   c.Maxsessions,
		})
	}

	for _, r := range config.IdpRemapSource { // toml does not allow arbitrary chars in keys for mapss
		remap[r.Key] = idpsppair{Idp: r.Idp, Sp: r.Sp}
	}

	metadataUpdateGuard = make(chan int, 1)
	goxml.Algos[""] = goxml.Algos[defaultDigestAndSignatureAlgorithm]
	gosaml.PostForm = template.Must(template.New("PostForm").Parse(config.PostFormTemplate))
	attributeReleaseForm = template.Must(template.New("AttributeRelease").Parse(config.AttributeReleaseTemplate))

	hubRequestedAttributes = goxml.NewXpFromString(config.Hubrequestedattributes)
	prepareTables(hubRequestedAttributes)

	Md.Hub = &lMDQ.MDQ{Path: config.Hub.Path, Table: config.Hub.Table, Rev: config.Hub.Table, Short: "hub"}
	Md.Internal = &lMDQ.MDQ{Path: config.Internal.Path, Table: config.Internal.Table, Rev: config.Internal.Table, Short: "int"}
	Md.ExternalIdP = &lMDQ.MDQ{Path: config.ExternalIdP.Path, Table: config.ExternalIdP.Table, Rev: config.ExternalSP.Table, Short: "idp"}
	Md.ExternalSP = &lMDQ.MDQ{Path: config.ExternalSP.Path, Table: config.ExternalSP.Table, Rev: config.ExternalIdP.Table, Short: "sp"}

	intExtSP = gosaml.MdSets{Md.Internal, Md.ExternalSP}
	intExtIdP = gosaml.MdSets{Md.Internal, Md.ExternalIdP}
	hubExtIdP = gosaml.MdSets{Md.Hub, Md.ExternalIdP}
	hubExtSP = gosaml.MdSets{Md.Hub, Md.ExternalSP}

	str, err := refreshAllMetadataFeeds(!*bypassMdUpdate)
	log.Printf("refreshAllMetadataFeeds: %s %s\n", str, err)

	webMdMap = make(map[string]webMd)
	for _, md := range []*lMDQ.MDQ{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		err := md.Open()
		if err != nil {
			panic(err)
		}
		webMdMap[md.Table] = webMd{md: md}
		webMdMap[md.Short] = webMd{md: md}
	}

	for _, md := range []*lMDQ.MDQ{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		m := webMdMap[md.Table]
		m.revmd = webMdMap[md.Rev].md
		webMdMap[md.Table] = m
		webMdMap[md.Short] = m
	}

	hubMd, err = Md.Hub.MDQ(config.HubEntityID)
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
	sloInfoCookie = securecookie.New(hashKey, nil)
	sloInfoCookie.SetSerializer(securecookie.NopEncoder{})
	sloInfoCookie.MaxAge(sloInfoTTL)
	authnRequestCookie = securecookie.New(hashKey, nil)
	authnRequestCookie.SetSerializer(securecookie.NopEncoder{})
	authnRequestCookie.MaxAge(authnRequestTTL)
    gosaml.AuthnRequestCookie = authnRequestCookie

	httpMux := http.NewServeMux()

	for _, pattern := range config.NotFoundRoutes {
		httpMux.Handle(pattern, http.NotFoundHandler())
	}

	httpMux.Handle("/production", appHandler(OkService))
	httpMux.Handle("/hsmstatus", appHandler(HSMStatus))
	httpMux.Handle(config.Vvpmss, appHandler(VeryVeryPoorMansScopingService))
	httpMux.Handle(config.Sso_Service, appHandler(SSOService))
	httpMux.Handle(config.Idpslo, appHandler(IdPSLOService))
	httpMux.Handle(config.Birkslo, appHandler(BirkSLOService))
	httpMux.Handle(config.Spslo, appHandler(SPSLOService))
	httpMux.Handle(config.Kribslo, appHandler(KribSLOService))
	httpMux.Handle(config.Nemloginslo, appHandler(SPSLOService))

	httpMux.Handle(config.Acs, appHandler(ACSService))
	httpMux.Handle(config.Nemlogin_Acs, appHandler(ACSService))
	httpMux.Handle(config.Eidas_Acs, appHandler(ACSService))
	httpMux.Handle(config.Birk, appHandler(SSOService))
	httpMux.Handle(config.Krib, appHandler(ACSService))
	httpMux.Handle(config.Dsbackend, appHandler(godiscoveryservice.DSBackend))
	httpMux.Handle(config.Dstiming, appHandler(godiscoveryservice.DSTiming))
	httpMux.Handle(config.Public, http.FileServer(http.Dir(config.Discopublicpath)))

	httpMux.Handle(config.Saml2jwt, appHandler(saml2jwt))
	httpMux.Handle(config.Jwt2saml, appHandler(jwt2saml))
	httpMux.Handle(config.MDQ, appHandler(MDQWeb))

	httpMux.Handle(config.Testsp_Slo, appHandler(testSPService))
	httpMux.Handle(config.Testsp_Acs, appHandler(testSPService))
	httpMux.Handle(config.Testsp+"/", appHandler(testSPService)) // need a root "/" for routing

	httpMux.Handle(config.Testsp2+"/XXO", appHandler(saml2jwt))
	httpMux.Handle(config.Testsp2_Slo, appHandler(testSPService))
	httpMux.Handle(config.Testsp2_Acs, appHandler(testSPService))
	httpMux.Handle(config.Testsp2+"/", appHandler(testSPService)) // need a root "/" for routing

	finish := make(chan bool)

	go func() {
		log.Println("listening on ", config.Intf)
		err = http.ListenAndServeTLS(config.Intf, config.Https_Cert, config.Https_Key, &slashFix{httpMux})
		if err != nil {
			log.Printf("main(): %s\n", err)
		}
	}()

	mdUpdateMux := http.NewServeMux()
	mdUpdateMux.Handle("/", appHandler(updateMetadataService)) // need a root "/" for routing

	go func() {
		log.Println("listening on 0.0.0.0:9000")
		err = http.ListenAndServe(":9000", mdUpdateMux)
		if err != nil {
			log.Printf("main(): %s\n", err)
		}
	}()

	<-finish
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
func (s wayfHybridSession) Set(w http.ResponseWriter, r *http.Request, id, domain string, data []byte, secCookie *securecookie.SecureCookie, maxAge int) (err error) {
	cookie, err := secCookie.Encode(id, gosaml.Deflate(data))
//	http.SetCookie(w, &http.Cookie{Name: id, Domain: domain, Value: cookie, Path: "/", Secure: true, HttpOnly: true, MaxAge: maxAge})
    cc := http.Cookie{Name: id, Domain: domain, Value: cookie, Path: "/", Secure: true, HttpOnly: true, MaxAge: maxAge}
    v := cc.String() // + "; SameSite=None"
    w.Header().Add("Set-Cookie", v)
	return
}

// Get responsible for getting the cookie values
func (s wayfHybridSession) Get(w http.ResponseWriter, r *http.Request, id string, secCookie *securecookie.SecureCookie) (data []byte, err error) {
	cookie, err := r.Cookie(id)
	if err == nil && cookie.Value != "" {
		err = secCookie.Decode(id, cookie.Value, &data)
	}
	data = gosaml.Inflate(data)
	return
}

// Del responsible for deleting a cookie values
func (s wayfHybridSession) Del(w http.ResponseWriter, r *http.Request, id string, secCookie *securecookie.SecureCookie) (err error) {
	http.SetCookie(w, &http.Cookie{Name: id, Domain: config.Domain, Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	return
}

// GetDel responsible for getting and then deleting cookie values
func (s wayfHybridSession) GetDel(w http.ResponseWriter, r *http.Request, id string, secCookie *securecookie.SecureCookie) (data []byte, err error) {
	data, err = s.Get(w, r, id, secCookie)
	s.Del(w, r, id, secCookie)
	return
}

// Write refers to writing log data
func (writer logWriter) Write(bytes []byte) (int, error) {
	return fmt.Fprint(os.Stderr, time.Now().UTC().Format("Jan _2 15:04:05 ")+string(bytes))
}

func birkify(idp string) (birk string) {
    birk = idp
    return
}

func legacyLog(stat, tag, idp, sp, hash string) {
	log.Printf("5 %s[%d] %s %s %s %s\n", stat, time.Now().UnixNano(), tag, idp, sp, hash)
}

func legacyStatLog(tag, idp, sp, hash string) {
	legacyLog("STAT ", tag, idp, sp, hash)
}

// Mar 13 14:09:07 birk-03 birk[16805]: 5321bc0335b24 {} ...
func legacyStatJsonLog(rec map[string]string) {
	b, _ := json.Marshal(rec)
	log.Printf("%d %s\n", time.Now().UnixNano(), b)
}

func prepareTables(attrs *goxml.Xp) {
	basic2uri = make(map[string]attrName)
	for _, attr := range attrs.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute") {
		friendlyName := attrs.Query1(attr, "@FriendlyName")
		uri := attrs.Query1(attr, "@Name")
		attributeName := attrs.Query1(attr, "@AttributeName")
		if attributeName == "" {
			attributeName = friendlyName
		}
		attributeNameMap := attrName{uri: uri, basic: friendlyName, AttributeName: attributeName}
		basic2uri[friendlyName] = attributeNameMap
		basic2uri[uri] = attributeNameMap
		basic2uri[attributeName] = attributeNameMap
	}
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
			for _, md := range []gosaml.Md{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
				err := md.(*lMDQ.MDQ).Open()
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

	testSPForm := template.Must(template.New("Test").Parse(config.WayfSPTestServiceTemplate))

	spMd, err := Md.Internal.MDQ("https://" + r.Host)
	pk, _ := gosaml.GetPrivateKey(spMd)
	idp := r.Form.Get("idpentityid")
	idpList := r.Form.Get("idplist")
	login := r.Form.Get("login") == "1"

	if login || idp != "" || idpList != "" {

		if err != nil {
			return err
		}
		idpMd, err := Md.Hub.MDQ(config.HubEntityID)
		if err != nil {
			return err
		}

        scopedIdP := r.Form.Get("scopedidp") + r.Form.Get("entityID")
		scoping := []string{}
		if r.Form.Get("scoping") == "scoping" {
			scoping = strings.Split(scopedIdP, ",")
		}

		if r.Form.Get("scoping") == "birk" {
			idpMd, err = Md.ExternalIdP.MDQ(scopedIdP)
			if err != nil {
				return err
			}
		}

		newrequest, _ := gosaml.NewAuthnRequest(nil, spMd, idpMd, scoping, "")

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

		u, err := gosaml.SAMLRequest2Url(newrequest, "", string(pk), "-", "") // not signed so blank key, pw and algo
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
			idp = scopedIdP
		}
		if idp != "" {
			q.Set("idplist", idp)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	} else if r.Form.Get("logout") == "1" || r.Form.Get("logoutresponse") == "1" {
		spMd, _, err := gosaml.FindInMetadataSets(gosaml.MdSets{Md.Internal, Md.ExternalSP}, r.Form.Get("destination"))
		if err != nil {
		    return err
		}
		idpMd, _, err := gosaml.FindInMetadataSets(gosaml.MdSets{Md.Hub, Md.ExternalIdP}, r.Form.Get("issuer"))
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
		response, issuerMd, destinationMd, relayState, _, _, err := gosaml.DecodeSAMLMsg(r, hubExtIdP, gosaml.MdSets{Md.Internal}, gosaml.SPRole, []string{"Response", "LogoutRequest", "LogoutResponse"}, "https://"+r.Host+r.URL.Path, nil)
		//		if err == lMDQ.MetaDataNotFoundError {
		//			response, issuerMd, destinationMd, relayState, err = gosaml.DecodeSAMLMsg(r, Md.ExternalIdP, Md.ExternalSP, gosaml.SPRole, []string{"Response", "LogoutRequest", "LogoutResponse"}, "")
		//			external = "1"
		//		}
		if err != nil {
			return err
		}

		var vals, debugVals []attrValue
		protocol := response.QueryString(nil, "local-name(/*)")
		if protocol == "Response" {
            if err := gosaml.CheckDigestAndSignatureAlgorithms(response, allowedDigestAndSignatureAlgorithms, issuerMd.QueryMulti(nil, xprefix+"SigningMethod")); err != nil {
                return err
            }
			vals = attributeValues(response, destinationMd, hubRequestedAttributes)
			Attributesc14n(response, response, issuerMd, destinationMd)
			err = wayfScopeCheck(response, issuerMd)
			if err != nil {
				messages = err.Error()
			}
            debugVals = attributeValues(response, destinationMd, hubRequestedAttributes)
		}

		data := testSPFormData{RelayState: relayState, ResponsePP: response.PP(), Destination: destinationMd.Query1(nil, "./@entityID"), Messages: messages,
			Issuer: issuerMd.Query1(nil, "./@entityID"), External: external, Protocol: protocol, AttrValues: vals, DebugValues: debugVals, ScopedIDP: response.Query1(nil, "//saml:AuthenticatingAuthority")}
		testSPForm.Execute(w, data)
	} else if r.Form.Get("ds") != "" {
		data := url.Values{}
		data.Set("return", "https://"+r.Host+r.RequestURI+"?previdplist="+r.Form.Get("scopedidp"))
		data.Set("returnIDParam", "scopedIDP")
		data.Set("entityID", "https://"+r.Host)
		http.Redirect(w, r, config.DiscoveryService+data.Encode(), http.StatusFound)
	} else {
		data := testSPFormData{ScopedIDP: strings.Trim(r.Form.Get("scopedIDP")+","+r.Form.Get("previdplist"), " ,")}
		testSPForm.Execute(w, data)
	}
	return
}

// attributeValues returns all the attribute values
func attributeValues(response, destinationMd, hubMd *goxml.Xp) (values []attrValue) {
	seen := map[string]bool{}
	requestedAttributes := hubMd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		name := destinationMd.Query1(requestedAttribute, "@Name")
		seen[name] = true
		friendlyName := destinationMd.Query1(requestedAttribute, "@FriendlyName")
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
		if len(epsaparts) != 4 {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", epsa)
			return
		}
		domain := epsaparts[2] + epsaparts[3]
		if domain != subsecuritydomain && !strings.HasSuffix(domain, "."+subsecuritydomain) {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s has not '%s' as security sub domain", epsa, subsecuritydomain)
			return
		}
	}
	return
}

func WayfACSServiceHandler(idpMd, hubMd, spMd, request, response *goxml.Xp, birk bool) (ard AttributeReleaseData, err error) {
	ard = AttributeReleaseData{IdPDisplayName: make(map[string]string), SPDisplayName: make(map[string]string), SPDescription: make(map[string]string)}
	idp := idpMd.Query1(nil, "@entityID")

	if err = wayfScopeCheck(response, idpMd); err != nil {
		return
	}

	arp := spMd.QueryMulti(nil, "md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute/@Name")
	arpmap := make(map[string]bool)
	for _, attrName := range arp {
		arpmap[attrName] = true
	}

	ard.IdPDisplayName["en"] = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.IdPDisplayName["da"] = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.IdPLogo = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.IdPEntityID = idp
	ard.SPDisplayName["en"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.SPDisplayName["da"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.SPDescription["en"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]`)
	ard.SPDescription["da"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="da"]`)
	ard.SPLogo = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.SPEntityID = spMd.Query1(nil, "@entityID")
	ard.BypassConfirmation = idpMd.QueryBool(nil, `count(`+xprefix+`consent.disable[.= `+strconv.Quote(ard.SPEntityID)+`]) > 0`)
	ard.BypassConfirmation = ard.BypassConfirmation || spMd.QueryXMLBool(nil, xprefix+`consent.disable`)
	ard.ForceConfirmation = ard.SPEntityID == "https://wayfsp2.wayf.dk"
	ard.ConsentAsAService = config.ConsentAsAService

	if birk {
		//Jun 19 09:42:58 birk-06 birk[18847]: 1529401378 {"action":"send","type":"samlp:Response","us":"https:\/\/birk.wayf.dk\/birk.php\/nemlogin.wayf.dk","destination":"https:\/\/europe.wiseflow.net","ip":"109.105.112.132","ts":1529401378,"host":"birk-06","logtag":1529401378}
		var jsonlog = map[string]string{
			"action":      "send",
			"type":        "samlp:Response",
			"us":          ard.IdPEntityID,
			"destination": ard.SPEntityID,
			"ip":          "0.0.0.0",
			"ts":          strconv.FormatInt(time.Now().Unix(), 10),
			"host":        hostName,
			"logtag":      strconv.FormatInt(time.Now().UnixNano(), 10),
		}
		legacyStatJsonLog(jsonlog)
	}
	eppn := response.Query1(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
	hashedEppn := fmt.Sprintf("%x", goxml.Hash(crypto.SHA256, config.SaltForHashedEppn+eppn))
	legacyStatLog("saml20-idp-SSO", ard.SPEntityID, idp, hashedEppn)
	return
}

func WayfKribHandler(idpMd, spMd, request, response *goxml.Xp) (ard AttributeReleaseData, err error) {
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
		if len(epsaparts) != 4 {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", epsa)
			return
		}
		domain := epsaparts[2] + epsaparts[3]
	    if idpMd.QueryBool(nil, "count(//shibmd:Scope[.="+strconv.Quote(domain)+"]) = 0") {
		    err = fmt.Errorf("security domain '%s' does not match any scopes", securitydomain)
		    return
		}
	}
	ard = AttributeReleaseData{BypassConfirmation: true}
	return
}

/* see http://www.cpr.dk/cpr_artikler/Files/Fil1/4225.pdf or http://da.wikipedia.org/wiki/CPR-nummer for algorithm */
// yearfromyearandcifferseven returns a year for CPR
func yearfromyearandcifferseven(year, c7 int) int {
	cpr2year := [][]int{
		{99, 1900},
		{99, 1900},
		{99, 1900},
		{99, 1900},
		{36, 2000, 1900},
		{57, 2000, 1800},
		{57, 2000, 1800},
		{57, 2000, 1800},
		{57, 2000, 1800},
		{36, 2000, 1900},
	}
	century := cpr2year[c7]
	if year <= century[0] {
		year += century[1]
	} else {
		year += century[2]
	}
	return year
}

func setAttribute(name, value string, response *goxml.Xp, element types.Node) {
	attr := response.QueryDashP(element, `/saml:Attribute[@Name="`+name+`"]`, "", nil)
	values := len(response.Query(attr, `./saml:AttributeValue`)) + 1
	response.QueryDashP(attr, `./saml:AttributeValue[`+strconv.Itoa(values)+`]`, value, nil)
}

func OkService(w http.ResponseWriter, r *http.Request) (err error) {
	return
}

func HSMStatus(w http.ResponseWriter, r *http.Request) (err error) {
	return goeleven.HSMStatus()
}

// VeryVeryPoorMansScopingService handles poors man scoping
func VeryVeryPoorMansScopingService(w http.ResponseWriter, r *http.Request) (err error) {
	http.SetCookie(w, &http.Cookie{Name: "vvpmss", Value: r.URL.Query().Get("idplist"), Path: "/", Secure: true, HttpOnly: true, MaxAge: 10})
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, hostName+"\n")
	return
}

func wayf(w http.ResponseWriter, r *http.Request, request, spMd, idpMd *goxml.Xp) (idp string) {
    defer func () { idp = debify.ReplaceAllString(idp, "$1$2") }()
	if idp = idpMd.Query1(nil, "@entityID"); idp != config.HubEntityID {
		return
	}
	sp := spMd.Query1(nil, "@entityID") // real entityID == KRIB entityID
	data := url.Values{}
	vvpmss := ""
	if tmp, _ := r.Cookie("vvpmss"); tmp != nil {
		vvpmss = tmp.Value
	    http.SetCookie(w, &http.Cookie{Name: "vvpmss", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	}

	idpLists := [][]string{
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
            for i, idp := range idpList {
                idpList[i] = birkify(idp)
            }
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
	request, spMd, hubBirkMd, relayState, spIndex, hubBirkIndex, err := gosaml.ReceiveAuthnRequest(r, intExtSP, hubExtIdP, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}

	idp := wayf(w, r, request, spMd, hubBirkMd)
	if idp == "" {
		return
	}
	idpMd, idpIndex, err := gosaml.FindInMetadataSets(intExtIdP, idp) // find internal if birk'ified
	if err != nil {
		return
	}

	// check for common feds before remapping!
    if _, err = RequestHandler(request, idpMd, spMd); err != nil {
        return
    }

    var hubSPMd *goxml.Xp
	if idpIndex == 0 { // to internal IdP - also via BIRK
		mappedSP := idpMd.Query1(nil, xprefix+"map2SP")
		if mappedSP == "" {
			mappedSP = config.HubEntityID
		}

		hubSPMd, err = Md.Hub.MDQ(mappedSP)
		if err != nil {
			return
		}

		mappedIdP := idpMd.Query1(nil, xprefix+"map2IdP")
		if mappedIdP != "" {
			idpMd, err = Md.Internal.MDQ(mappedIdP)
			if err != nil {
				return
			}
		}
	} else { // to external IdP - send as KRIB
		hubSPMd, err = Md.ExternalSP.MDQ(spMd.Query1(nil, "@entityID"))
		if err != nil {
			return
		}
	}

	err = sendRequestToIdP(w, r, request, spMd, hubSPMd, idpMd, idp, relayState, "SSO-", "", config.Domain, spIndex, hubBirkIndex, nil)
	return
}

func sendRequestToIdP(w http.ResponseWriter, r *http.Request, request, issuerSpMd, spMd, idpMd *goxml.Xp, idp, relayState, prefix, altAcs, domain string, spIndex, hubIdpIndex int, idPList []string) (err error) {
	// why not use orig request?
	newrequest, err := gosaml.NewAuthnRequest(request, spMd, idpMd, idPList, altAcs)
	if err != nil {
		return
	}

	if idpMd.QueryXMLBool(nil, xprefix+`wantRequesterID`) {
		newrequest.QueryDashP(nil, "./samlp:Scoping/samlp:RequesterID", request.Query1(nil, "./saml:Issuer"), nil)
	}

	// Save the request in a session for when the response comes back
	id := newrequest.Query1(nil, "./@ID")

	if request == nil {
		request = goxml.NewXpFromString("") // an empty one to allow get "" for all the fields below ....
	}

	sRequest := samlRequest{
		Nid:   id,
		Id:    request.Query1(nil, "./@ID"),
		Is:    request.Query1(nil, "./saml:Issuer"),
		De:    idp,
		Fo:    gosaml.NameIDMap[request.Query1(nil, "./samlp:NameIDPolicy/@Format")],
		Acs:   request.Query1(nil, "./@AssertionConsumerServiceIndex"),
		SPi:   spIndex,
		Hubi:  hubIdpIndex,
		WsFed: r.Form.Get("wa") == "wsignin1.0",
	}
	bytes, err := json.Marshal(&sRequest)
	session.Set(w, r, prefix+idHash(id), domain, bytes, authnRequestCookie, authnRequestTTL)

	var privatekey []byte
	if idpMd.QueryXMLBool(nil, `./md:IDPSSODescriptor/@WantAuthnRequestsSigned`) || spMd.QueryXMLBool(nil, `./md:SPSSODescriptor/@AuthnRequestsSigned`) {
		privatekey, err = gosaml.GetPrivateKey(spMd)
		if err != nil {
			return
		}
	}

	algo := idpMd.Query1(nil, xprefix+"SigningMethod")

	if sigAlg := gosaml.DebugSetting(r, "idpSigAlg"); sigAlg != "" {
		algo = sigAlg
	}

	u, err := gosaml.SAMLRequest2Url(newrequest, relayState, string(privatekey), "-", algo)
	if err != nil {
		return
	}

	legacyLog("", "SAML2.0 - IdP.SSOService: Incomming Authentication request:", "'"+request.Query1(nil, "./saml:Issuer")+"'", "", "")
	if hubIdpIndex == 1 {
		var jsonlog = map[string]string{
			"action": "receive",
			"type":   "samlp:AuthnRequest",
			"src":    request.Query1(nil, "./saml:Issuer"),
			"us":     idp,
			"ip":     r.RemoteAddr,
			"ts":     strconv.FormatInt(time.Now().Unix(), 10),
			"host":   hostName,
			"logtag": strconv.FormatInt(time.Now().UnixNano(), 10),
		}

		legacyStatJsonLog(jsonlog)
	}

	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func getOriginalRequest(w http.ResponseWriter, r *http.Request, response *goxml.Xp, issuerMdSets, destinationMdSets gosaml.MdSets, prefix string) (spMd, hubIdp, idpMd, request *goxml.Xp, sRequest samlRequest, err error) {
	gosaml.DumpFileIfTracing(r, response)
	inResponseTo := response.Query1(nil, "./@InResponseTo")
	value, err := session.GetDel(w, r, prefix+idHash(inResponseTo), authnRequestCookie)
	if err != nil {
		return
	}
	// to minimize the size of the cookies we have saved the original request in a json'ed struct
	err = json.Unmarshal(value, &sRequest)

	if inResponseTo != sRequest.Nid {
		err = fmt.Errorf("response.InResponseTo != request.ID")
		return
	}

	if sRequest.Id == "" { // This is a non-hub request - no original actual original request - just checking if response/@InResponseTo == request/@ID
		return nil, nil, nil, nil, sRequest, nil
	}

	if spMd, err = issuerMdSets[sRequest.SPi].MDQ(sRequest.Is); err != nil {
		return
	}

	if idpMd, err = Md.ExternalIdP.MDQ(sRequest.De); err != nil { // Always BIRK - for getting the right cert,  contains same info as internal - try first with std. name
        if idpMd, err = Md.ExternalIdP.MDQ(birkify(sRequest.De)); err != nil {
		    return
		}
	}
	hubIdp = idpMd          // who to send the response as - BIRK
	if sRequest.Hubi == 0 { // or hub is request was to the hub
		if hubIdp, err = Md.Hub.MDQ(config.HubEntityID); err != nil {
			return
		}
	}

	request = goxml.NewXpFromString("")
	request.QueryDashP(nil, "/samlp:AuthnRequest/@ID", sRequest.Id, nil)
	//request.QueryDashP(nil, "./@Destination", sRequest.De, nil)

	acs := spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@Binding="`+gosaml.POST+`" and @index=`+strconv.Quote(sRequest.Acs)+`]/@Location`)

	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", acs, nil)
	request.QueryDashP(nil, "./saml:Issuer", sRequest.Is, nil)
	request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", gosaml.NameIDList[sRequest.Fo], nil)

	return
}

// ACSService handles all the stuff related to receiving response and attribute handling
func ACSService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, hubSpMd, relayState, _, hubSpIndex, err := gosaml.ReceiveSAMLResponse(r, intExtIdP, hubExtSP, "https://"+r.Host+r.URL.Path, hubIdpCerts)
	if err != nil {
		return
	}
	spMd, hubIdpMd, idpMd, request, sRequest, err := getOriginalRequest(w, r, response, intExtSP, hubExtIdP, "SSO-")
	if err != nil {
		return
	}

	if err = gosaml.CheckDigestAndSignatureAlgorithms(response, allowedDigestAndSignatureAlgorithms, idpMd.QueryMulti(nil, xprefix+"SigningMethod")); err != nil {
	    return
	}

	signingMethod := spMd.Query1(nil, xprefix+"SigningMethod")

	var newresponse *goxml.Xp
	var ard AttributeReleaseData
	if response.Query1(nil, `samlp:Status/samlp:StatusCode/@Value`) == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		Attributesc14n(request, response, idpMd, spMd)
        if err = checkForCommonFederations(response); err != nil {
           return
        }
		if hubSpIndex == 0 { // to the hub itself
			ard, err = WayfACSServiceHandler(idpMd, hubRequestedAttributes, spMd, request, response, sRequest.Hubi == 1)
		} else { // krib
			ard, err = WayfKribHandler(idpMd, spMd, request, response)
		}
		if err != nil {
			return goxml.Wrap(err)
		}

		if gosaml.DebugSetting(r, "scopingError") != "" {
			eppnPath := `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`
			response.QueryDashP(nil, eppnPath, response.Query1(nil, eppnPath)+"1", nil)
		}

		newresponse = gosaml.NewResponse(hubIdpMd, spMd, request, response)
		ard.Values, ard.Hash = CopyAttributes(response, newresponse, spMd)

		nameidElement := newresponse.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
		nameidformat := request.Query1(nil, "./samlp:NameIDPolicy/@Format")
        nameid := response.Query1(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name="nameID"]/saml:AttributeValue`)

		newresponse.QueryDashP(nameidElement, "@Format", nameidformat, nil)
		newresponse.QueryDashP(nameidElement, ".", nameid, nil)

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
		if sRequest.WsFed {
			newresponse = gosaml.NewWsFedResponse(hubIdpMd, spMd, newresponse)
			ard.Values, ard.Hash = CopyAttributes(response, newresponse, spMd)

			signingType = gosaml.WSFedSign
			elementsToSign = []string{"./t:RequestedSecurityToken/saml1:Assertion"}
		}

		for _, q := range elementsToSign {
			err = gosaml.SignResponse(newresponse, q, hubIdpMd, signingMethod, signingType)
			if err != nil {
				return err
			}
		}
		if _, err = SLOInfoHandler(w, r, response, hubSpMd, newresponse, spMd, gosaml.SPRole, "SLO"); err != nil {
			return
		}

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
		newresponse = gosaml.NewErrorResponse(hubIdpMd, spMd, request, response)

		err = gosaml.SignResponse(newresponse, "/samlp:Response", hubIdpMd, signingMethod, gosaml.SAMLSign)
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
	if sRequest.WsFed {
		samlResponse = string(newresponse.Dump())
	} else {
		samlResponse = base64.StdEncoding.EncodeToString(newresponse.Dump())
	}
	data := gosaml.Formdata{WsFed: sRequest.WsFed, Acs: request.Query1(nil, "./@AssertionConsumerServiceURL"), Samlresponse: samlResponse, RelayState: relayState, Ard: template.JS(ardjson)}
	attributeReleaseForm.Execute(w, data)
	return
}

// SPSLOService refers to SP single logout service. Takes request as a parameter and returns an error if any
func SPSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.Internal, Md.Hub, []gosaml.Md{Md.ExternalIdP, Md.Hub}, []gosaml.Md{Md.Internal, Md.ExternalSP}, gosaml.SPRole, "SLO")
}

// BirkSLOService refers to birk single logout service. Takes request as a parameter and returns an error if any
func BirkSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.ExternalSP, Md.ExternalIdP, []gosaml.Md{Md.Hub}, []gosaml.Md{Md.Internal}, gosaml.IdPRole, "SLO")
}

// KribSLOService refers to krib single logout service. Takes request as a parameter and returns an error if any
func KribSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.ExternalIdP, Md.ExternalSP, []gosaml.Md{Md.Hub}, []gosaml.Md{Md.Internal}, gosaml.SPRole, "SLO")
}

func jwt2saml(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Jwt2saml(w, r, Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP, RequestHandler, hubMd)
}

func saml2jwt(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Saml2jwt(w, r, Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP, RequestHandler, config.HubEntityID, true, allowedDigestAndSignatureAlgorithms, xprefix+"SigningMethod")
}

// IdPSLOService refers to idp single logout service. Takes request as a parameter and returns an error if any
func IdPSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.Internal, Md.Hub, []gosaml.Md{Md.ExternalSP, Md.Hub}, []gosaml.Md{Md.ExternalIdP, Md.Internal}, gosaml.IdPRole, "SLO")
}

// SLOService refers to single logout service. Takes request and issuer and destination metadata sets, role refers to if it as IDP or SP.
func SLOService(w http.ResponseWriter, r *http.Request, issuerMdSet, destinationMdSet gosaml.Md, finalIssuerMdSets, finalDestinationMdSets []gosaml.Md, role int, tag string) (err error) {
	req := []string{"idpreq", "spreq"}
	res := []string{"idpres", "spres"}
	defer r.Body.Close()
	r.ParseForm()
	if _, ok := r.Form["SAMLRequest"]; ok {
		request, issuer, destination, relayState, _, _, err := gosaml.ReceiveLogoutMessage(r, gosaml.MdSets{issuerMdSet}, gosaml.MdSets{destinationMdSet}, role)
		if err != nil {
			return err
		}
		md := destination
		if role == gosaml.SPRole {
			md = issuer
		}
		sloinfo, _ := SLOInfoHandler(w, r, request, md, request, md, role, tag)
		if sloinfo.Na != "" {
			if role == gosaml.IdPRole { // reverse if we are getting the request from a SP
				sloinfo.Is, sloinfo.De = sloinfo.De, sloinfo.Is
			}

			finalIssuer, _, err := gosaml.FindInMetadataSets(finalIssuerMdSets, "{sha1}"+sloinfo.Is)
			if err != nil {
				return err
			}
			finalDestination, _, err := gosaml.FindInMetadataSets(finalDestinationMdSets, "{sha1}"+sloinfo.De)
			if err != nil {
				return err
			}

			sloinfo.Is = finalIssuer.Query1(nil, "./@entityID")
			sloinfo.De = finalDestination.Query1(nil, "./@entityID")

			newRequest, binding, err := gosaml.NewLogoutRequest(finalDestination, sloinfo, role)
			if err != nil {
				return err
			}
			async := request.QueryBool(nil, "boolean(./samlp:Extensions/aslo:Asynchronous)")
			if !async {
				session.Set(w, r, "SLO-"+idHash(sloinfo.Is), config.Domain, request.Dump(), authnRequestCookie, 60)
			}
			// send LogoutRequest to sloinfo.EntityID med sloinfo.NameID as nameid
			legacyStatLog("saml20-idp-SLO "+req[role], issuer.Query1(nil, "@entityID"), destination.Query1(nil, "@entityID"), sloinfo.Na+fmt.Sprintf(" async:%t", async))
			// always sign if a private key is available - ie. ignore missing keys
			privatekey, err := gosaml.GetPrivateKey(finalIssuer)

			if err != nil {
				return err
			}

			algo := finalDestination.Query1(nil, xprefix+"SigningMethod")

			if sigAlg := gosaml.DebugSetting(r, "idpSigAlg"); sigAlg != "" {
				algo = sigAlg
			}
			switch binding {
			case gosaml.REDIRECT:
				u, _ := gosaml.SAMLRequest2Url(newRequest, relayState, string(privatekey), "-", algo)
				http.Redirect(w, r, u.String(), http.StatusFound)
			case gosaml.POST:
				data := gosaml.Formdata{Acs: newRequest.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(newRequest.Dump())}
				gosaml.PostForm.Execute(w, data)
			}
		} else {
			err = fmt.Errorf("no Logout info found")
			return err
		}
	} else if _, ok := r.Form["SAMLResponse"]; ok {
		_, issuer, destination, relayState, _, _, err := gosaml.ReceiveLogoutMessage(r, gosaml.MdSets{issuerMdSet}, gosaml.MdSets{destinationMdSet}, role)
		if err != nil {
			return err
		}
		destID := destination.Query1(nil, "./@entityID")
		value, err := session.Get(w, r, "SLO-"+idHash(destID), authnRequestCookie)
		if err != nil {
			return err
		}
		legacyStatLog("saml20-idp-SLO "+res[role], issuer.Query1(nil, "@entityID"), destination.Query1(nil, "@entityID"), "")

		request := goxml.NewXp(value)

		issuerMd, _, err := gosaml.FindInMetadataSets(finalIssuerMdSets, request.Query1(nil, "@Destination"))
		if err != nil {
			return err
		}
		destinationMd, _, err := gosaml.FindInMetadataSets(finalDestinationMdSets, request.Query1(nil, "./saml:Issuer"))
		if err != nil {
			return err
		}

		err = session.Del(w, r, "SLO-"+idHash(destID), authnRequestCookie)
		if err != nil {
			return err
		}

		newResponse, binding, err := gosaml.NewLogoutResponse(issuerMd, destinationMd, request, role)
		if err != nil {
			return err
		}

		privatekey, err := gosaml.GetPrivateKey(issuerMd)

		if err != nil {
			return err
		}

		algo := destinationMd.Query1(nil, xprefix+"SigningMethod")

		if sigAlg := gosaml.DebugSetting(r, "idpSigAlg"); sigAlg != "" {
			algo = sigAlg
		}
		// forward the LogoutResponse to orig sender
		switch binding {
		case gosaml.REDIRECT:
			u, _ := gosaml.SAMLRequest2Url(newResponse, relayState, string(privatekey), "-", algo)
			http.Redirect(w, r, u.String(), http.StatusFound)
		case gosaml.POST:
			data := gosaml.Formdata{Acs: newResponse.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(newResponse.Dump())}
			gosaml.PostForm.Execute(w, data)
		}
	} else {
		err = fmt.Errorf("no LogoutRequest/logoutResponse found")
		return err
	}
	return
}

// Saves or retrieves the SLO info relevant to the contents of the samlMessage
// For now uses cookies to keep the SLOInfo
func SLOInfoHandler(w http.ResponseWriter, r *http.Request, samlIn, destinationInMd, samlOut, destinationOutMd *goxml.Xp, role int, tag string) (sloinfo *gosaml.SLOInfo, err error) {
	type touple struct {
		HashIn, HashOut string
	}
	var key, idp, sp, spIdPHash string
	hashIn := fmt.Sprintf("%s-%d-%s", tag, gosaml.SPRole, idHash(samlIn.Query1(nil, "//saml:NameID")))
	hashOut := fmt.Sprintf("%s-%d-%s", tag, gosaml.IdPRole, idHash(samlOut.Query1(nil, "//saml:NameID")))
	switch samlIn.QueryString(nil, "local-name(/*)") {
	case "LogoutRequest":
		switch role {
		case gosaml.IdPRole: // request from a SP
			key = hashOut
		case gosaml.SPRole: // reguest from an IdP
			key = hashIn
		}
		sloinfo = &gosaml.SLOInfo{}
		data, err := session.Get(w, r, key, sloInfoCookie)
		if err == nil {
			err = json.Unmarshal(data, &sloinfo)
		}
		session.Del(w, r, key, sloInfoCookie)
		key = fmt.Sprintf("%s-%d-%s", tag, (role+1)%2, idHash(sloinfo.Na))
		sloinfo2 := &gosaml.SLOInfo{}
		data, err = session.Get(w, r, key, sloInfoCookie)
		if err == nil {
			err = json.Unmarshal(data, &sloinfo2)
		}
		session.Del(w, r, key, sloInfoCookie)
		switch role {
		case gosaml.IdPRole: // request from a SP
			idp = sloinfo2.Is
			sp = sloinfo2.De
		case gosaml.SPRole: // reguest from an IdP
			idp = sloinfo.Is
			sp = sloinfo.De
		}
		spIdPHash = idHash(tag + "#" + idp + "#" + sp)
		session.Del(w, r, spIdPHash, sloInfoCookie)
	case "LogoutResponse":
		// needed at all ???
	case "Response":
		idp = samlOut.Query1(nil, "./saml:Issuer")
		sp = destinationOutMd.Query1(nil, "./@entityID")
		idpHash := idHash(idp)
		spHash := idHash(sp)
		spIdPHash = idHash(tag + "#" + idpHash + "#" + spHash)
		// 1st delete any SLO info for the same idp-sp pair
		unique := &touple{}
		data, err := session.Get(w, r, spIdPHash, sloInfoCookie)
		if err == nil {
			err = json.Unmarshal(data, &unique)
		}
		session.Del(w, r, unique.HashIn, sloInfoCookie)
		session.Del(w, r, unique.HashOut, sloInfoCookie)
		// 2nd create 2 new SLO info recs and save them under the hash of the opposite
		unique.HashIn = hashIn
		unique.HashOut = hashOut
		bytes, err := json.Marshal(&unique)
		session.Set(w, r, spIdPHash, config.Domain, bytes, sloInfoCookie, sloInfoTTL)

		slo := gosaml.NewSLOInfo(samlIn, destinationInMd.Query1(nil, "@entityID"))
		slo.Is = idHash(slo.Is)
		slo.De = idHash(slo.De)
		bytes, _ = json.Marshal(&slo)
		session.Set(w, r, hashOut, config.Domain, bytes, sloInfoCookie, sloInfoTTL)

		slo = gosaml.NewSLOInfo(samlOut, destinationOutMd.Query1(nil, "@entityID"))
		slo.Is = idHash(slo.Is)
		slo.De = idHash(slo.De)
		bytes, _ = json.Marshal(&slo)
		session.Set(w, r, hashIn, config.Domain, bytes, sloInfoCookie, sloInfoTTL)

	}
	return
}

// idHash to create hash of the id
func idHash(data string) string {
	return fmt.Sprintf("%.5x", sha1.Sum([]byte(data)))
}

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
