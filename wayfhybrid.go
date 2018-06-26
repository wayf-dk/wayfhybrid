package wayfhybrid

import (
	"crypto"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/dgrijalva/jwt-go"
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
	_ "net/http/pprof"
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

	wayfHybridConfig struct {
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
		Testsp, Testsp_Acs, Testsp_Slo, Testsp2, Testsp2_Acs, Testsp2_Slo                        string
		Eidas_Acs, Nemlogin_Acs, CertPath, SamlSchema, ConsentAsAService                         string
		Idpslo, Birkslo, Spslo, Kribslo, Nemloginslo, Saml2jwt, SaltForHashedEppn                string
		ElementsToSign                                                                           []string
		NotFoundRoutes                                                                           []string
		Hub, Internal, ExternalIdP, ExternalSP                                                   struct{ Path, Table string }
		MetadataFeeds                                                                            []struct{ Path, URL string }
		GoEleven                                                                                 goElevenConfig
		SpBackendTenants                                                                         map[string]struct{ EntityID, Secret string }
		IdpRemapSource                                                                           []struct{ Key, IdP, Sp string }
	}

	idpsppair struct {
		Idp string
		Sp  string
	}

	logWriter struct {
	}

	formdata struct {
		Acs          string
		Samlresponse string
		RelayState   string
		Ard          template.JS
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
		Hub, Internal, ExternalIdP, ExternalSP gosaml.Md
	}

	wayfHybridSession struct{}

	// https://stackoverflow.com/questions/47475802/golang-301-moved-permanently-if-request-path-contains-additional-slash
	slashFix struct {
		mux http.Handler
	}

	attrName struct {
		uri, basic, claim string
	}

	attrValue struct {
		Name   string
		Must   bool
		Values []string
	}

	samlRequest struct {
		Nid, Id, Is, De, Acs string
		Fo                   int
		DtS, Brk             bool
	}
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	config = wayfHybridConfig{Path: "/opt/wayf/"}
    remap = map[string]idpsppair{}

	bify          = regexp.MustCompile("^(https?://)(.*)$")
	debify        = regexp.MustCompile("^(https?://)(?:(?:birk|krib)\\.wayf.dk/(?:birk\\.php|[a-f0-9]{40})/)(.+)$")
	allowedInFeds = regexp.MustCompile("[^\\w\\.-]")
	scoped        = regexp.MustCompile(`^[^\@]+\@([a-zA-Z0-9][a-zA-Z0-9\.-]+[a-zA-Z0-9])(@aau\.dk)?$`)
	aauscope      = regexp.MustCompile(`[@\.]aau\.dk$`)

	metadataUpdateGuard chan int

	session = wayfHybridSession{}

	sloInfoCookie, authnRequestCookie *securecookie.SecureCookie
	postForm, attributeReleaseForm    *template.Template
	hashKey                           []byte
	hostName                          string

	hubRequestedAttributes *goxml.Xp

	Md                 MdSets
	basic2uri          map[string]attrName
	aCSServiceHandler  func(*goxml.Xp, *goxml.Xp, *goxml.Xp, *goxml.Xp, *goxml.Xp, bool) (AttributeReleaseData, error)
	kribServiceHandler func(*goxml.Xp, *goxml.Xp, *goxml.Xp) (string, error)
)

func Main() {
	log.SetFlags(0) // no predefined time
	//log.SetOutput(new(logWriter))

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
        remap[r.Key] = idpsppair{Idp: r.IdP, Sp: r.Sp}
    }

	metadataUpdateGuard = make(chan int, 1)
	postForm = template.Must(template.New("PostForm").Parse(config.PostFormTemplate))
	attributeReleaseForm = template.Must(template.New("AttributeRelease").Parse(config.AttributeReleaseTemplate))

	hubRequestedAttributes = goxml.NewXpFromString(config.Hubrequestedattributes)
	prepareTables(hubRequestedAttributes)

	Md.Hub = &lMDQ.MDQ{Path: config.Hub.Path, Table: config.Hub.Table}
	Md.Internal = &lMDQ.MDQ{Path: config.Internal.Path, Table: config.Internal.Table}
	Md.ExternalIdP = &lMDQ.MDQ{Path: config.ExternalIdP.Path, Table: config.ExternalIdP.Table}
	Md.ExternalSP = &lMDQ.MDQ{Path: config.ExternalSP.Path, Table: config.ExternalSP.Table}

	str, err := refreshAllMetadataFeeds()
	log.Printf("refreshAllMetadataFeeds: %s %s\n", str, err)

	for _, md := range []gosaml.Md{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		err := md.(*lMDQ.MDQ).Open()
		if err != nil {
			panic(err)
		}
	}

	/*
	   wayfsp2, _ := Md.Internal.MDQ("https://wayfsp2.wayf.dk")
	   wayfsp2.QueryDashP(nil, "/md:SPSSODescriptor/md:AssertionConsumerService/@Location", "http://localhost:32361", nil)
	   kribwayfsp2, _ := Md.ExternalSP.MDQ("https://wayfsp2.wayf.dk")
	   kribwayfsp2.QueryDashP(nil, "/md:SPSSODescriptor/md:AssertionConsumerService/@Location", "https://krib.wayf.dk/76ae4bd1a482918378e0617993684344c2cd95bd/localhost:32361", nil)
	   q.Q(kribwayfsp2.PP()) //
	*/

	aCSServiceHandler = WayfACSServiceHandler
	kribServiceHandler = WayfKribHandler

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

	httpMux := http.NewServeMux()

	//http.HandleFunc("/status", statushandler)
	//http.Handle(config["hybrid_public_prefix"], http.FileServer(http.Dir(config["hybrid_public"])))
	for _, pattern := range config.NotFoundRoutes {
		httpMux.Handle(pattern, http.NotFoundHandler())
	}

	httpMux.Handle("/production", appHandler(OkService))
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
	httpMux.Handle(config.Birk, appHandler(BirkService))
	httpMux.Handle(config.Krib, appHandler(KribService))
	httpMux.Handle(config.Dsbackend, appHandler(godiscoveryservice.DSBackend))
	httpMux.Handle(config.Dstiming, appHandler(godiscoveryservice.DSTiming))
	httpMux.Handle(config.Public, http.FileServer(http.Dir(config.Discopublicpath)))

	httpMux.Handle(config.Saml2jwt, appHandler(saml2jwt))

	httpMux.Handle(config.Testsp_Slo, appHandler(testSPService))
	httpMux.Handle(config.Testsp_Acs, appHandler(testSPService))
	httpMux.Handle(config.Testsp+"/", appHandler(testSPService)) // need a root "/" for routing

	httpMux.Handle(config.Testsp2+"/XXO", appHandler(saml2jwt))
	httpMux.Handle(config.Testsp2_Slo, appHandler(testSPService))
	httpMux.Handle(config.Testsp2_Acs, appHandler(testSPService))
	httpMux.Handle(config.Testsp2+"/", appHandler(testSPService)) // need a root "/" for routing

	//id.wayf.dk tests ...
	httpMux.Handle("id.wayf.dk/SSO", appHandler(IdWayfDkSSOService))
	httpMux.Handle("id.wayf.dk/ACS", appHandler(IdWayfDkACSService))

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

func (s wayfHybridSession) Set(w http.ResponseWriter, r *http.Request, id, domain string, data []byte, secCookie *securecookie.SecureCookie, maxAge int) (err error) {
	cookie, err := secCookie.Encode(id, gosaml.Deflate(data))
	http.SetCookie(w, &http.Cookie{Name: id, Domain: domain, Value: cookie, Path: "/", Secure: true, HttpOnly: true, MaxAge: maxAge})
	return
}

func (s wayfHybridSession) Get(w http.ResponseWriter, r *http.Request, id string, secCookie *securecookie.SecureCookie) (data []byte, err error) {
	cookie, err := r.Cookie(id)
	if err == nil && cookie.Value != "" {
		err = secCookie.Decode(id, cookie.Value, &data)
	}
	data = gosaml.Inflate(data)
	return
}

func (s wayfHybridSession) Del(w http.ResponseWriter, r *http.Request, id string, secCookie *securecookie.SecureCookie) (err error) {
	http.SetCookie(w, &http.Cookie{Name: id, Domain: config.Domain, Value: "", Path: "/", Secure: true, HttpOnly: true, MaxAge: -1})
	return
}

func (s wayfHybridSession) GetDel(w http.ResponseWriter, r *http.Request, id string, secCookie *securecookie.SecureCookie) (data []byte, err error) {
	data, err = s.Get(w, r, id, secCookie)
	s.Del(w, r, id, secCookie)
	return
}

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
func legacyStatJsonLog(rec map[string]string) {
	b, _ := json.Marshal(rec)
	log.Printf("%d %s\n", time.Now().UnixNano(), b)
}

func prepareTables(attrs *goxml.Xp) {
	basic2uri = make(map[string]attrName)
	for _, attr := range attrs.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute") {
		friendlyName := attrs.Query1(attr, "@FriendlyName")
		uri := attrs.Query1(attr, "@Name")
		basic2uri[friendlyName] = attrName{uri: uri, basic: friendlyName, claim: friendlyName} // attrs.Query1(attr, "@AttributeName")
		basic2uri[uri] = attrName{uri: uri, basic: friendlyName, claim: friendlyName}          // attrs.Query1(attr, "@AttributeName")
	}
}

func (m mddb) MDQ(key string) (xp *goxml.Xp, err error) {
	db, err := sql.Open("sqlite3", m.db)
	if err != nil {
		return
	}
	defer db.Close()
	//ent := hex.EncodeToString(goxml.Hash(crypto.SHA1, key))
	hash := sha1.Sum([]byte(key))
	ent := hex.EncodeToString(append(hash[:]))
	var md []byte
	var query = "select e.md md from entity_" + m.table + " e, lookup_" + m.table + " l where l.hash = ? and l.entity_id_fk = e.id"
	err = db.QueryRow(query, ent).Scan(&md)
	switch {
	case err == sql.ErrNoRows:
		err = goxml.Wrap(err, "err:Metadata not found", "key:"+key, "table:"+m.table)
		return
	case err != nil:
		return
	default:
		md = gosaml.Inflate(md)
		xp = goxml.NewXp(md)
	}
	return
}

func (m mddb) Open(db, table string) (err error) {
	m.db = db
	m.table = table
	return
}

/* how to get the status ...
type statusLoggingResponseWriter struct {
   status int
   http.ResponseWriter
}

func (w *statusLoggingResponseWriter) WriteHeader(code int) {
  w.status = code
  w.ResponseWriter.WriteHeader(code)
}

type WrapHTTPHandler struct {
	m *http.Handler
}

func (h *WrapHTTPHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
        myW := StatusLoggingResponseWriter{-1, w}
	h.m.ServeHTTP(myW, r)
	log.Printf("[%s] %s %d\n", r.RemoteAddr, r.URL, w.status)
}
*/

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/*	ctx := make(map[string]string)
		contextmutex.Lock()
		context[r] = ctx
		contextmutex.Unlock()
		w.Header().Set("content-Security-Policy", "referrer no-referrer;")
	*/

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

	log.Printf("%s %s %s %+v %1.3f %d %s", r.RemoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)
	switch x := err.(type) {
	case goxml.Werror:
		log.Print(x.FullError())
		log.Print(x.Stack(5))
	}

	/*	contextmutex.Lock()
		delete(context, r)
		contextmutex.Unlock()
	*/
}

func updateMetadataService(w http.ResponseWriter, r *http.Request) (err error) {
	if str, err := refreshAllMetadataFeeds(); err == nil {
		io.WriteString(w, str)
	}
	return
}

func refreshAllMetadataFeeds() (str string, err error) {
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
			<-metadataUpdateGuard
			return "Pong", nil
		}
	default:
		{
			return "Ignored", nil
		}
	}
}

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

func samlTime2JwtTime(xmlTime string) int64 {
	samlTime, _ := time.Parse(gosaml.XsDateTime, xmlTime)
	return samlTime.Unix()
}

func saml2jwt(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	spMd, err := Md.Internal.MDQ(config.SpBackendTenants[r.Header.Get("X-Token")].EntityID)
	if err != nil {
		return
	}

	if _, ok := r.Form["SAMLResponse"]; ok {
		response, _, _, relayState, err := gosaml.ReceiveSAMLResponse(r, Md.Hub, Md.Internal, r.Header.Get("X-Acs"))
		if err != nil {
			return err
		}
		_, _, _, err = getOriginalRequest(w, r, response, nil, nil, "JWT-")
		if err != nil {
			return err
		}

		attrs := jwt.MapClaims{}

		names := response.QueryMulti(nil, "//saml:Attribute/@Name")
		for _, name := range names {
			basic := basic2uri[name].basic
			attrs[basic] = response.QueryMulti(nil, "//saml:Attribute[@Name="+strconv.Quote(basic)+"]/saml:AttributeValue")
		}

		type claim struct {
			name, xpath string
			conv        func(string) int64
		}

		claims := []claim{
			{"iss", "./saml:Issuer", nil},
			{"aud", "./saml:Conditions/saml:AudienceRestriction/saml:Audience", nil},
			{"nbf", "./saml:Conditions/@NotBefore", samlTime2JwtTime},
			{"exp", "./saml:Conditions/@NotOnOrAfter", samlTime2JwtTime},
			{"iat", "@IssueInstant", samlTime2JwtTime},
		}

		assertion := response.Query(nil, "/samlp:Response/saml:Assertion")[0]
		for _, c := range claims {
			attrs[c.name] = response.Query1(assertion, c.xpath)
			if c.conv != nil {
				attrs[c.name] = c.conv(attrs[c.name].(string))
			}
		}

		// https://godoc.org/github.com/dgrijalva/jwt-go#example-New--Hmac
		// Create a new token object, specifying signing method and the claims
		// you would like it to contain.
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, attrs)

		// Sign and get the complete encoded token as a string using the secret
		tokenString, err := token.SignedString([]byte(config.SpBackendTenants[r.Header.Get("X-Token")].Secret))
		if err != nil {
			return err
		}

		var app []byte
		err = authnRequestCookie.Decode("app", relayState, &app)
		if err != nil {
			return err
		}

		w.Header().Set("Authorization", "Bearer "+tokenString)
		w.Header().Set("X-Accel-Redirect", string(app))
		return err
	}

	hubMd, err := Md.Hub.MDQ(config.HubEntityID)
	if err != nil {
		return err
	}

	relayState, err := authnRequestCookie.Encode("app", []byte(r.Header.Get("X-App")))
	if err != nil {
		return err
	}

	q.Q(r)
	err = sendRequestToIdP(w, r, nil, spMd, hubMd, "", relayState, "JWT-", r.Header.Get("X-Acs"), "", true, false, strings.Split(r.Form.Get("idplist"), ","))
	return err
}

func testSPService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	type testSPFormData struct {
		Protocol, RelayState, ResponsePP, Issuer, Destination, External, ScopedIDP string
		AttrValues                                                                 []attrValue
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
		hubMd, err := Md.Hub.MDQ(config.HubEntityID)
		if err != nil {
			return err
		}

		scoping := []string{}
		if r.Form.Get("scoping") == "scoping" {
			scoping = strings.Split(r.Form.Get("scopedidp"), ",")
		}

		newrequest, _ := gosaml.NewAuthnRequest(nil, spMd, hubMd, scoping)

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
		if idpList != "" {
			q.Set("idplist", idpList)
		}
		if r.Form.Get("scoping") == "param" {
			idp = r.Form.Get("scopedidp")
		}
		if idp != "" {
			q.Set("idplist", idp)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	} else if r.Form.Get("logout") == "1" || r.Form.Get("logoutresponse") == "1" {
		destinationMdSet := Md.Internal
		issuerMdSet := Md.Hub
		if r.Form.Get("external") == "1" {
			destinationMdSet = Md.ExternalSP
			issuerMdSet = Md.ExternalIdP
		}
		destination, _ := destinationMdSet.MDQ(r.Form.Get("destination"))
		issuer, _ := issuerMdSet.MDQ(r.Form.Get("issuer"))
		if r.Form.Get("logout") == "1" {
			SloRequest(w, r, goxml.NewXpFromString(r.Form.Get("response")), destination, issuer, string(pk))
		} else {
			SloResponse(w, r, goxml.NewXpFromString(r.Form.Get("response")), destination, issuer)
		}

	} else if r.Form.Get("SAMLResponse") != "" {
		// try to decode SAML message to ourselves or just another SP
		// don't do destination check - we accept and dumps anything ...
		external := "0"
		response, issuerMd, destinationMd, relayState, err := gosaml.DecodeSAMLMsg(r, Md.Hub, Md.Internal, gosaml.SPRole, []string{"Response", "LogoutRequest", "LogoutResponse"}, "")
		if err == lMDQ.MetaDataNotFoundError {
			response, issuerMd, destinationMd, relayState, err = gosaml.DecodeSAMLMsg(r, Md.ExternalIdP, Md.ExternalSP, gosaml.SPRole, []string{"Response", "LogoutRequest", "LogoutResponse"}, "")
			external = "1"
		}
		if err != nil {
			return err
		}

		_, _, _, _, err = checkScope(response, issuerMd, response.Query(nil, `./saml:Assertion/saml:AttributeStatement`)[0], false)

		if err != nil {
			return err
		}

		protocol := response.QueryString(nil, "local-name(/*)")
		vals := attributeValues(response, destinationMd, hubRequestedAttributes)

		data := testSPFormData{RelayState: relayState, ResponsePP: response.PP(), Destination: destinationMd.Query1(nil, "./@entityID"),
			Issuer: issuerMd.Query1(nil, "./@entityID"), External: external, Protocol: protocol, AttrValues: vals, ScopedIDP: response.Query1(nil, "//saml:AuthenticatingAuthority")}
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

func SloRequest(w http.ResponseWriter, r *http.Request, response, issuer, destination *goxml.Xp, pk string) {
	template := `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                     xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                     ID=""
                     Version="2.0"
                     IssueInstant=""
                     Destination=""
                     >
    <saml:Issuer></saml:Issuer>
    <saml:NameID>
    </saml:NameID>
</samlp:LogoutRequest>
`
	request := goxml.NewXpFromString(template)
	slo := destination.Query1(nil, `./md:IDPSSODescriptor/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`)
	request.QueryDashP(nil, "./@IssueInstant", time.Now().Format(gosaml.XsDateTime), nil)
	request.QueryDashP(nil, "./@ID", gosaml.Id(), nil)
	request.QueryDashP(nil, "./@Destination", slo, nil)
	request.QueryDashP(nil, "./saml:Issuer", issuer.Query1(nil, `/md:EntityDescriptor/@entityID`), nil)
	request.QueryDashP(nil, "./saml:NameID/@SPNameQualifier", response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@SPNameQualifier"), nil)
	request.QueryDashP(nil, "./saml:NameID/@Format", response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID/@Format"), nil)
	request.QueryDashP(nil, "./saml:NameID", response.Query1(nil, "/samlp:Response/saml:Assertion/saml:Subject/saml:NameID"), nil)
	u, _ := gosaml.SAMLRequest2Url(request, "", pk, "-", "")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func SloResponse(w http.ResponseWriter, r *http.Request, request, issuer, destination *goxml.Xp) {
	template := `<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                      xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                      ID="_7e3ee93a09570edc9bb85a2d300e6f701dc74393"
                      Version="2.0"
                      IssueInstant="2018-01-31T14:01:19Z"
                      Destination="https://wayfsp.wayf.dk/ss/module.php/saml/sp/saml2-logout.php/default-sp"
                      InResponseTo="_7645977ce3d668e7ef9d650f4361e350f612a178eb">
    <saml:Issuer>
     https://wayf.wayf.dk
    </saml:Issuer>
    <samlp:Status>
        <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
    </samlp:Status>
</samlp:LogoutResponse>
`
	response := goxml.NewXpFromString(template)
	slo := destination.Query1(nil, `./md:IDPSSODescriptor/md:SingleLogoutService[@Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"]/@Location`)
	response.QueryDashP(nil, "./@IssueInstant", time.Now().Format(gosaml.XsDateTime), nil)
	response.QueryDashP(nil, "./@ID", gosaml.Id(), nil)
	response.QueryDashP(nil, "./@Destination", slo, nil)
	response.QueryDashP(nil, "./@InResponseTo", request.Query1(nil, "./@ID"), nil)
	response.QueryDashP(nil, "./saml:Issuer", issuer.Query1(nil, `/md:EntityDescriptor/@entityID`), nil)
	u, _ := gosaml.SAMLRequest2Url(response, "", "", "", "")
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func attributeValues(response, destinationMd, hubMd *goxml.Xp) (values []attrValue) {
	requestedAttributes := hubMd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		name := destinationMd.Query1(requestedAttribute, "@Name")
		friendlyName := destinationMd.Query1(requestedAttribute, "@FriendlyName")

		must := hubMd.Query1(nil, `.//md:RequestedAttribute[@FriendlyName=`+strconv.Quote(friendlyName)+`]/@must`) == "true"

		// accept attributes in both uri and basic format
		attrValues := response.QueryMulti(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+` or @Name=`+strconv.Quote(friendlyName)+`]/saml:AttributeValue`)
		values = append(values, attrValue{Name: friendlyName, Must: must, Values: attrValues})
	}
	return
}

func checkForCommonFederations(idpMd, spMd *goxml.Xp) (err error) {
	idpFeds := idpMd.QueryMulti(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:feds")
	tmp := idpFeds[:0]
	for _, federation := range idpFeds {
		fed := allowedInFeds.ReplaceAllLiteralString(strings.TrimSpace(federation), "")
		tmp = append(tmp, strconv.Quote(fed))
	}
	idpFedsQuery := strings.Join(idpFeds, " or .=")
	commonFeds := spMd.QueryMulti(nil, `/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:feds[.=`+idpFedsQuery+`]`)
	if len(commonFeds) == 0 {
		err = fmt.Errorf("no common federations")
		return
	}
	return
}

func WayfACSServiceHandler(idpMd, hubMd, spMd, request, response *goxml.Xp, birk bool) (ard AttributeReleaseData, err error) {
	ard = AttributeReleaseData{Values: make(map[string][]string), IdPDisplayName: make(map[string]string), SPDisplayName: make(map[string]string), SPDescription: make(map[string]string)}
	idp := response.Query1(nil, "/samlp:Response/saml:Issuer")

	base64encodedIn := idpMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:base64attributes") == "1"

	switch idp {
	case "https://saml.nemlog-in.dk", "https://saml.test-nemlog-in.dk/":
		base64encodedIn = false
		nemloginAttributeHandler(response)
	case "https://eidasconnector.test.eid.digst.dk/idp":
		eidasAttributeHandler(response)
	default:
	}

	if err = checkForCommonFederations(idpMd, spMd); err != nil {
		return
	}

	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement[1]`)[0]
	destinationAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[2]`, "", nil)
	//response.QueryDashP(destinationAttributes, "@xmlns:xs", "http://www.w3.org/2001/XMLSchema", nil)

	attCS := hubMd.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

	// First check for required and multiplicity
	requestedAttributes := hubMd.Query(attCS, `md:RequestedAttribute[not(@computed)]`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		name := hubMd.Query1(requestedAttribute, "@Name")
		friendlyName := hubMd.Query1(requestedAttribute, "@FriendlyName")
		singular := hubMd.QueryBool(requestedAttribute, "@singular")
		isRequired := hubMd.QueryBool(requestedAttribute, "@isRequired")

		// accept attributes in both uri and basic format
		attributesValues := response.QueryMulti(sourceAttributes, `saml:Attribute[@Name=`+strconv.Quote(name)+` or @Name=`+strconv.Quote(friendlyName)+`]/saml:AttributeValue`)
		if len(attributesValues) == 0 && isRequired {
			err = fmt.Errorf("isRequired: %s", friendlyName)
			return
		}
		if len(attributesValues) > 1 && singular {
			err = fmt.Errorf("multiple values for singular attribute: %s", name)
			return
		}
		if len(attributesValues) == 0 {
			continue
		}
		attr := response.QueryDashP(destinationAttributes, `saml:Attribute[@Name=`+strconv.Quote(name)+`]`, "", nil)
		response.QueryDashP(attr, `@FriendlyName`, friendlyName, nil)
		response.QueryDashP(attr, `@NameFormat`, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", nil)

		index := 1
		for _, value := range attributesValues {
			if base64encodedIn {
				v, _ := base64.StdEncoding.DecodeString(value)
				value = string(v)
			}
			response.QueryDashP(attr, "saml:AttributeValue["+strconv.Itoa(index)+"]", value, nil)
			index++
		}
	}

	parent, _ := sourceAttributes.ParentNode()
	parent.RemoveChild(sourceAttributes)
	//defer sourceAttributes.Free()

	// check that the security domain of eppn is one of the domains in the shib:scope list
	// we just check that everything after the (leftmost|rightmost) @ is in the scope list and save the value for later
	eppn, eppnForEptid, securitydomain, epsaList, err := checkScope(response, idpMd, destinationAttributes, true)
	if err != nil {
		return
	}

	val := idpMd.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganizationType")
	setAttribute("schacHomeOrganizationType", val, response, destinationAttributes)

	val = idpMd.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganization")
	setAttribute("schacHomeOrganization", val, response, destinationAttributes)

	if response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="displayName"]/saml:AttributeValue`) == "" {
		if cn := response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="cn"]/saml:AttributeValue`); cn != "" {
			setAttribute("displayName", cn, response, destinationAttributes)
		}
	}

	// Use kribified?, use birkified?
	idpPEID := idp
	if tmp := idpMd.Query1(nil, "./md:Extensions/wayf:wayf/wayf:persistentEntityID"); tmp != "" {
		idpPEID = tmp
	}

	sp := spMd.Query1(nil, "@entityID")
	spPEID := sp
	if tmp := spMd.Query1(nil, "./md:Extensions/wayf:wayf/wayf:persistentEntityID"); tmp != "" {
		spPEID = tmp
	}

	uidhashbase := "uidhashbase" + config.EptidSalt
	uidhashbase += strconv.Itoa(len(idpPEID)) + ":" + idpPEID
	uidhashbase += strconv.Itoa(len(spPEID)) + ":" + spPEID
	uidhashbase += strconv.Itoa(len(eppnForEptid)) + ":" + eppnForEptid
	uidhashbase += config.EptidSalt

	hash := sha1.Sum([]byte(uidhashbase))
	eptid := "WAYF-DK-" + hex.EncodeToString(append(hash[:]))
	setAttribute("eduPersonTargetedID", eptid, response, destinationAttributes)

	dkcprpreg := regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	for _, cpr := range response.QueryMulti(destinationAttributes, `saml:Attribute[@FriendlyName="schacPersonalUniqueID"]`) {
		// schacPersonalUniqueID is multi - use the first DK cpr found
		if matches := dkcprpreg.FindStringSubmatch(cpr); len(matches) > 0 {
			cpryear, _ := strconv.Atoi(matches[3])
			c7, _ := strconv.Atoi(matches[4])
			year := strconv.Itoa(yearfromyearandcifferseven(cpryear, c7))
			if response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="schacDateOfBirth"]`) == "" {
				setAttribute("schacDateOfBirth", year+matches[2]+matches[1], response, destinationAttributes)
			}
			if response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="schacYearOfBirth"]`) == "" {
				setAttribute("schacYearOfBirth", year, response, destinationAttributes)
			}
			break
		}
	}

	epsas := make(map[string]bool)
	// scopes are checked for legality above
	for _, epsa := range epsaList {
		epsas[epsa] = true
	}

	// primaryaffiliation => affiliation
	eppa := response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonPrimaryAffiliation"]/saml:AttributeValue`)
	epas := response.QueryMulti(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]/saml:AttributeValue`)
	epaset := make(map[string]bool)
	for _, epa := range epas {
		epaset[epa] = true
	}
	if !epaset[eppa] {
		epaset[eppa] = true
	}
	// 'student', 'faculty', 'staff', 'employee' => member
	if epaset["student"] || epaset["faculty"] || epaset["staff"] || epaset["employee"] {
		epaset["member"] = true
	}

	i := 1
	for epa := range epaset {
		name := hubMd.Query1(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonAffiliation"]/@Name`)
		response.QueryDashP(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]/@Name`, name, nil)
		response.QueryDashP(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]/saml:AttributeValue[`+strconv.Itoa(i+1)+`]`, epa, nil)
		response.QueryDashP(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]/@NameFormat`, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", nil)
	}
	i = 1
	for epa := range epaset {
		if epsas[epa] {
			continue
		}
		name := hubMd.Query1(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonScopedAffiliation"]/@Name`)
		response.QueryDashP(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonScopedAffiliation"]/@Name`, name, nil)
		response.QueryDashP(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonScopedAffiliation"]/saml:AttributeValue[`+strconv.Itoa(i)+`]`, epa+"@"+securitydomain, nil)
		response.QueryDashP(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonScopedAffiliation"]/@NameFormat`, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", nil)
		i += 1
	}
	// legal affiliations 'student', 'faculty', 'staff', 'affiliate', 'alum', 'employee', 'library-walk-in', 'member'
	// affiliations => scopedaffiliations
	// Fill out the info needed for AttributeReleaseData
	// to-do add value filtering
	arp := spMd.QueryMulti(nil, "md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute/@Name")
	arpmap := make(map[string]bool)
	for _, attrName := range arp {
		arpmap[attrName] = true
	}

	h := sha1.New()
	for _, attrNode := range response.Query(destinationAttributes, `saml:Attribute`) {
		friendlyName := response.Query1(attrNode, "@FriendlyName")
		name := response.Query1(attrNode, "@Name")
		if arpmap[name] || arpmap[friendlyName] {
			io.WriteString(h, name)
			for _, attrValue := range response.QueryMulti(attrNode, "saml:AttributeValue") {
				io.WriteString(h, attrValue)
				ard.Values[friendlyName] = append(ard.Values[friendlyName], attrValue)
			}
		}
	}

	ard.IdPDisplayName["en"] = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.IdPDisplayName["da"] = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.IdPLogo = idpMd.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.IdPEntityID = birkify(idp)
	ard.SPDisplayName["en"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.SPDisplayName["da"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.SPDescription["en"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]`)
	ard.SPDescription["da"] = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="da"]`)
	ard.SPLogo = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.SPEntityID = spMd.Query1(nil, "@entityID")
	ard.BypassConfirmation = idpMd.QueryBool(nil, `count(./md:Extensions/wayf:wayf/wayf:consent.disable[.= `+strconv.Quote(ard.SPEntityID)+`]) > 0`)
	ard.BypassConfirmation = ard.BypassConfirmation || spMd.QueryBool(nil, `count(./md:Extensions/wayf:wayf/wayf:consent.disable[.='1']) > 0`)
	ard.ForceConfirmation = ard.SPEntityID == "https://wayfsp2.wayf.dk"
	ard.Key = idHash(ard.SPEntityID)
	io.WriteString(h, ard.Key+config.SaltForHashedEppn+eppn+ard.SPDescription["en"]+ard.SPDescription["da"])

	ard.Hash = fmt.Sprintf("%x", h.Sum(nil))
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
	hashedEppn := fmt.Sprintf("%x", goxml.Hash(crypto.SHA256, config.SaltForHashedEppn+eppn))
	legacyStatLog("saml20-idp-SSO", ard.SPEntityID, idp, hashedEppn)
	return
}

func WayfKribHandler(response, birkMd, kribMd *goxml.Xp) (destination string, err error) {
	destination = debify.ReplaceAllString(response.Query1(nil, "@Destination"), "$1$2")

	if err = checkForCommonFederations(birkMd, kribMd); err != nil {
		return
	}

	legacyStatLog("saml20-idp-SSO", kribMd.Query1(nil, "@entityID"), birkMd.Query1(nil, "@entityID"), "na")

	//	destination = "https://" + config.ConsentAsAService
	return
}

func nemloginAttributeHandler(response *goxml.Xp) {
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
	value := response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:2.5.4.3"]/saml:AttributeValue`)
	names := strings.Split(value, " ")
	l := len(names) - 1
	//setAttribute("cn", value, response, sourceAttributes) // already there
	setAttribute("gn", strings.Join(names[0:l], " "), response, sourceAttributes)
	// sn seems to be empty from from Nemlog-in - remove it
	response.Rm(sourceAttributes, `./saml:Attribute[@Name="urn:oid:2.5.4.4"]`)
	setAttribute("sn", names[l], response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:0.9.2342.19200300.100.1.1"]/saml:AttributeValue`)
	setAttribute("eduPersonPrincipalName", value+"@sikker-adgang.dk", response, sourceAttributes)
	//value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:0.9.2342.19200300.100.1.3"]/saml:AttributeValue`)
	//setAttribute("mail", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:attribute:AssuranceLevel"]/saml:AttributeValue`)
	setAttribute("eduPersonAssurance", value, response, sourceAttributes)
	if value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:attribute:CprNumberIdentifier"]/saml:AttributeValue`); value != "" {
		setAttribute("schacPersonalUniqueID", "urn:mace:terena.org:schac:personalUniqueID:dk:CPR:"+value, response, sourceAttributes)
	}
	setAttribute("eduPersonPrimaryAffiliation", "member", response, sourceAttributes)
	setAttribute("organizationName", "NemLogin", response, sourceAttributes)
}

func eidasAttributeHandler(response *goxml.Xp) {
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
	value := response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:attribute:eidas:naturalperson:CurrentFamilyName"]/saml:AttributeValue`)
	setAttribute("gn", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:attribute:eidas:naturalperson:CurrentGivenName"]/saml:AttributeValue`)
	setAttribute("sn", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:attribute:eidas:naturalperson:PersonIdentifier"]/saml:AttributeValue`)
	setAttribute("eduPersonPrincipalName", value+"@eidasconnector.test.eid.digst.dk", response, sourceAttributes)
	setAttribute("schacPersonalUniqueID", "urn:mace:terena.org:schac:personalUniqueID:dk:PersonIdentifier:"+value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:attribute:eidas:naturalperson:DateOfBirth"]/saml:AttributeValue`)
	setAttribute("schacDateOfBirth", value, response, sourceAttributes)
	setAttribute("organizationName", "eIDAS", response, sourceAttributes)
}

/* see http://www.cpr.dk/cpr_artikler/Files/Fil1/4225.pdf or http://da.wikipedia.org/wiki/CPR-nummer for algorithm */

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
	attr := response.QueryDashP(element, `/saml:Attribute[@Name=`+strconv.Quote(basic2uri[name].uri)+`]`, "", nil)
	response.QueryDashP(attr, `./@NameFormat`, "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", nil)
	response.QueryDashP(attr, `./@FriendlyName`, name, nil)
	values := len(response.Query(attr, `./saml:AttributeValue`)) + 1
	response.QueryDashP(attr, `./saml:AttributeValue[`+strconv.Itoa(values)+`]`, value, nil)
}

func OkService(w http.ResponseWriter, r *http.Request) (err error) {
	return
}

func VeryVeryPoorMansScopingService(w http.ResponseWriter, r *http.Request) (err error) {
	http.SetCookie(w, &http.Cookie{Name: "vvpmss", Value: r.URL.Query().Get("idplist"), Path: "/", Secure: true, HttpOnly: true, MaxAge: 10})
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "text/plain")
	io.WriteString(w, hostName+"\n")
	return
}

func birkify(idp string) string {
	if _, err := Md.Internal.MDQ(idp); err == nil {
		idp = bify.ReplaceAllString(idp, "${1}birk.wayf.dk/birk.php/$2")
	}
	return idp
}

func wayf(w http.ResponseWriter, r *http.Request, request, spMd *goxml.Xp, idpLists [][]string) (idp string) {
	sp := spMd.Query1(nil, "@entityID") // real entityID == KRIB entityID
	data := url.Values{}

	for _, idpList := range idpLists {
		for i, idp := range idpList {
			idpList[i] = birkify(idp)
		}
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
	return
}

func SSOService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	request, spMd, _, relayState, err := gosaml.ReceiveAuthnRequest(r, Md.Internal, Md.Hub)
	if err != nil {
		return
	}

	vvpmss := ""
	if tmp, _ := r.Cookie("vvpmss"); tmp != nil {
		vvpmss = tmp.Value
	}

	idpLists := [][]string{
		spMd.QueryMulti(nil, "./md:Extensions/wayf:wayf/wayf:IDPList"),
		request.QueryMulti(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID"),
		{r.URL.Query().Get("idpentityid")},
		strings.Split(r.URL.Query().Get("idplist"), ","),
		strings.Split(vvpmss, ",")}

	if idp2 := wayf(w, r, request, spMd, idpLists); idp2 != "" {
		idp2Md, err := Md.ExternalIdP.MDQ(idp2)
		if err != nil {
			return err
		}

		sp2 := spMd.Query1(nil, "@entityID") // real entityID == KRIB entityID
		sp2Md, _ := Md.ExternalSP.MDQ(sp2)

		altIdp := debify.ReplaceAllString(idp2, "$1$2")
		if idp2 != altIdp { // an internal IdP
			sp2Md, idp2Md, err = remapper(idp2)
			if err != nil {
				return err
			}
			sp2 = config.HubEntityID
		}

		if err = checkForCommonFederations(spMd, idp2Md); err != nil {
			return err
		}

		err = sendRequestToIdP(w, r, request, sp2Md, idp2Md, sp2, relayState, "SSO-", "", config.Domain, true, false, nil)
		return err
	}
	return
}

func BirkService(w http.ResponseWriter, r *http.Request) (err error) {
	// use incoming request for crafting the new one
	// remember to add the Scoping element to inform the IdP of requesterID - if stated in metadata for the IdP
	// check ad-hoc feds overlap
	defer r.Body.Close()
	var directToSp bool

	request, spMd, birkIdpMd, relayState, err := gosaml.ReceiveAuthnRequest(r, Md.Internal, Md.ExternalIdP)
	if err != nil {
		var err2 error
		e, ok := err.(goxml.Werror)
		if ok && (e.Cause == gosaml.ACSError || e.Cause == lMDQ.MetaDataNotFoundError) {
			// or is it coming directly from a SP
			request, spMd, birkIdpMd, relayState, err2 = gosaml.ReceiveAuthnRequest(r, Md.ExternalSP, Md.ExternalIdP)
			if err2 != nil {
				// we need the original error for a SP that use an invalid ACS, but is in the external feed
				return goxml.Wrap(err)
			}
		} else {
			return err
		}
		// If we get here we need to tag the request as a direct BIRK to SP - otherwise we will end up sending the response to KRIB

	} else {
		directToSp = true
	}

	var hubMd, idpMd *goxml.Xp

	birkIdp := birkIdpMd.Query1(nil, "@entityID")
	hubMd, idpMd, err = remapper(birkIdp)
	if err != nil {
		return
	}

	if err = checkForCommonFederations(idpMd, spMd); err != nil {
		return
	}

	err = sendRequestToIdP(w, r, request, hubMd, idpMd, birkIdp, relayState, "SSO-", "", config.Domain, directToSp, true, nil)
	if err != nil {
		return
	}
	return
}

func remapper(idp string) (hubMd, idpMd *goxml.Xp, err error) {
	idp = debify.ReplaceAllString(idp, "$1$2")
q.Q(remap, idp)
	if rm, ok := remap[idp]; ok {
		idpMd, err = Md.Internal.MDQ(rm.Idp)
		if err != nil {
			return
		}
		hubMd, err = Md.Hub.MDQ(rm.Sp)
		if err != nil {
			return
		}
	} else {
		idpMd, err = Md.Internal.MDQ(idp)
		if err != nil {
			return
		}
		hubMd, err = Md.Hub.MDQ(config.HubEntityID)
		if err != nil {
			return
		}
	}
	return
}

func sendRequestToIdP(w http.ResponseWriter, r *http.Request, request, spMd, idpMd *goxml.Xp, destination, relayState, prefix, altAcs, domain string, directToSP, birk bool, idPList []string) (err error) {
	// why not use orig request?
	newrequest, err := gosaml.NewAuthnRequest(request, spMd, idpMd, idPList)
	if err != nil {
		return
	}
	if altAcs != "" {
		newrequest.QueryDashP(nil, "./@AssertionConsumerServiceURL", altAcs, nil)
	}

	// Save the request in a session for when the response comes back
	id := newrequest.Query1(nil, "./@ID")

	if request == nil {
		request = goxml.NewXpFromString("") // an empty one to allow get "" for all the fields below ....
	}

	sRequest := samlRequest{
		Nid: id,
		Id:  request.Query1(nil, "./@ID"),
		Is:  request.Query1(nil, "./saml:Issuer"),
		De:  destination,
		Fo:  gosaml.NameIDMap[request.Query1(nil, "./samlp:NameIDPolicy/@Format")],
		Acs: request.Query1(nil, "./@AssertionConsumerServiceIndex"),
		DtS: directToSP,
		Brk: birk,
	}
	bytes, err := json.Marshal(&sRequest)
	session.Set(w, r, prefix+idHash(id), domain, bytes, authnRequestCookie, authnRequestTTL)

	var privatekey []byte
	wars := idpMd.Query1(nil, `./md:IDPSSODescriptor/@WantAuthnRequestsSigned`) + idpMd.Query1(nil, `./md:Extensions/wayf:wayf/wayf:redirect.sign`)
	switch wars {
	case "true", "1":
		privatekey, err = gosaml.GetPrivateKey(spMd)
		if err != nil {
			return
		}
	}

	algo := idpMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:SigningMethod")

    if sigAlg := gosaml.DebugSetting(r, "idpSigAlg"); sigAlg != "" {
        algo = sigAlg
    }

	if idpMd.Query1(nil, "@entityID") == "https://eidasconnector.test.eid.digst.dk/idp" {
        eIdasExtras(newrequest)
    }

	u, err := gosaml.SAMLRequest2Url(newrequest, relayState, string(privatekey), "-", algo)
	if err != nil {
		return
	}

	legacyLog("", "SAML2.0 - IdP.SSOService: Incomming Authentication request:", "'"+request.Query1(nil, "./saml:Issuer")+"'", "", "")
	if birk {
		var jsonlog = map[string]string{
			"action": "receive",
			"type":   "samlp:AuthnRequest",
			"src":    request.Query1(nil, "./saml:Issuer"),
			"us":     destination,
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

func eIdasExtras(request *goxml.Xp) {
    request.QueryDashP(nil, "@ForceAuthn", "true", nil)
    request.QueryDashP(nil, "@IsPassive", "false", nil)
    request.Rm(nil, "@ProtocolBinding")
    request.Rm(nil, "@AssertionConsumerServiceURL")
    //        nameIDPolicyNode := request.Query(nil, "./samlp:NameIDPolicy")[0]
    //        extensions := request.QueryDashP(nil, "./samlp:Extensions", "", nameIDPolicyNode)
    //        request.QueryDashP(extensions, "./eidas:SPType", "public", nil)
    //        ras := request.QueryDashP(extensions, "./eidas:RequestedAttributes", "", nil)
    //        for i, n := range []string{"CurrentFamilyName", "CurrentGivenName", "DateOfBirth", "PersonIdentifier"} {
    //            ra := request.QueryDashP(ras, "eidas:RequestedAttribute["+strconv.Itoa(i+1)+"]", "", nil)
    //            request.QueryDashP(ra, "./@FriendlyName", n, nil)
    //            request.QueryDashP(ra, "@Name", "dk:gov:saml:attribute:eidas:naturalperson:"+n, nil)
    //            request.QueryDashP(ra, "@NameFormat", "urn:oasis:names:tc:SAML:2.0:attrname-format:basic", nil)
    //            request.QueryDashP(ra, "@isRequired", "true", nil)
    //        }
    request.Rm(nil, "./samlp:NameIDPolicy")
    //request.QueryDashP(nil, "samlp:NameIDPolicy/@Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", nil)
    request.QueryDashP(nil, `samlp:RequestedAuthnContext[@Comparison="minimum"]/saml:AuthnContextClassRef`, "http://eidas.europa.eu/LoA/high", nil)
	return
}

func getOriginalRequest(w http.ResponseWriter, r *http.Request, response *goxml.Xp, md1, md2 gosaml.Md, prefix string) (spMd, request *goxml.Xp, sRequest samlRequest, err error) {
	gosaml.DumpFile(r, response)
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
		return nil, nil, sRequest, nil
	}

	if sRequest.DtS {
		spMd, err = md1.MDQ(sRequest.Is)
	} else {
		spMd, err = md2.MDQ(sRequest.Is)
	}
	if err != nil {
		return
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

func ACSService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, idpMd, hubMd, relayState, err := gosaml.ReceiveSAMLResponse(r, Md.Internal, Md.Hub, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}
	spMd, request, sRequest, err := getOriginalRequest(w, r, response, Md.Internal, Md.ExternalSP, "SSO-")
	if err != nil {
		return
	}

	signingMethod := spMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:SigningMethod")

	birkMd, err := Md.ExternalIdP.MDQ(sRequest.De)
	issuerMd := birkMd
	if err != nil {
		birkMd = idpMd
		issuerMd, err = Md.Hub.MDQ(config.HubEntityID)
	}
	if err != nil {
		return
	}

	var newresponse *goxml.Xp
	var ard AttributeReleaseData
	if response.Query1(nil, `samlp:Status/samlp:StatusCode/@Value`) == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		ard, err = aCSServiceHandler(birkMd, hubRequestedAttributes, spMd, request, response, sRequest.Brk)
		if err != nil {
			return goxml.Wrap(err)
		}

		if gosaml.DebugSetting(r, "scopingError") != "" {
			eppnPath := `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@FriendlyName="eduPersonPrincipalName"]/saml:AttributeValue`
			response.QueryDashP(nil, eppnPath, response.Query1(nil, eppnPath)+"1", nil)
		}

		newresponse = gosaml.NewResponse(issuerMd, spMd, request, response)

		nameid := newresponse.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
		// respect nameID in req, give persistent id + all computed attributes + nameformat conversion
		// The response at this time contains a full attribute set
		nameidformat := request.Query1(nil, "./samlp:NameIDPolicy/@Format")
		if nameidformat == gosaml.Persistent {
			newresponse.QueryDashP(nameid, "@Format", gosaml.Persistent, nil)
			eptid := newresponse.Query1(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@FriendlyName="eduPersonTargetedID"]/saml:AttributeValue`)
			newresponse.QueryDashP(nameid, ".", eptid, nil)
		} else { // if nameidformat == gosaml.Transient
			newresponse.QueryDashP(nameid, ".", gosaml.Id(), nil)
		}

		handleAttributeNameFormat(newresponse, spMd)

		// gosaml.NewResponse only handles simple attr values so .. send correct eptid to eduGAIN entities
		if spMd.QueryBool(nil, "count(/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:feds[.='eduGAIN']) > 0") {
			if eptidAttr := newresponse.Query(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@FriendlyName="eduPersonTargetedID"]`); eptidAttr != nil {
				value := newresponse.Query1(eptidAttr[0], "./saml:AttributeValue")
				newresponse.Rm(eptidAttr[0], "./saml:AttributeValue")
				newresponse.QueryDashP(eptidAttr[0], "./saml:AttributeValue/saml:NameID", value, nil)
			}
		}

		if sigAlg := gosaml.DebugSetting(r, "spSigAlg"); sigAlg != "" {
			signingMethod = sigAlg
		}

		for _, q := range config.ElementsToSign {
			err = gosaml.SignResponse(newresponse, q, issuerMd, signingMethod, gosaml.SAMLSign)
			if err != nil {
				return err
			}
		}
		if _, err = SLOInfoHandler(w, r, response, hubMd, newresponse, spMd, gosaml.SPRole, "SLO"); err != nil {
			return
		}

		if gosaml.DebugSetting(r, "signingError") == "1" {
			newresponse.QueryDashP(nil, `./saml:Assertion/@ID`, newresponse.Query1(nil, `./saml:Assertion/@ID`)+"1", nil)
		}

		if gosaml.DebugSetting(r, "encryptAssertion") == "1" {
			gosaml.DumpFile(r, newresponse)
			cert := spMd.Query1(nil, "./md:SPSSODescriptor"+gosaml.EncryptionCertQuery) // actual encryption key is always first
			_, publicKey, _ := gosaml.PublicKeyInfo(cert)
			ea := goxml.NewXpFromString(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
			assertion := newresponse.Query(nil, "saml:Assertion[1]")[0]
			newresponse.Encrypt(assertion, publicKey, ea)
		}
	} else {
		newresponse = gosaml.NewErrorResponse(issuerMd, spMd, request, response)

		err = gosaml.SignResponse(newresponse, "/samlp:Response", issuerMd, signingMethod, gosaml.SAMLSign)
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
	gosaml.DumpFile(r, newresponse)

	data := formdata{Acs: request.Query1(nil, "./@AssertionConsumerServiceURL"), Samlresponse: base64.StdEncoding.EncodeToString(newresponse.Dump()), RelayState: relayState, Ard: template.JS(ardjson)}
	attributeReleaseForm.Execute(w, data)
	return
}

func KribService(w http.ResponseWriter, r *http.Request) (err error) {
	// check ad-hoc feds overlap
	defer r.Body.Close()

	response, birkMd, kribMd, relayState, err := gosaml.ReceiveSAMLResponse(r, Md.ExternalIdP, Md.ExternalSP, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}

	spMd, request, sRequest, err := getOriginalRequest(w, r, response, Md.Internal, Md.Internal, "SSO-")
	if err != nil {
		return
	}

	if err = checkForCommonFederations(birkMd, kribMd); err != nil {
		return
	}

	legacyStatLog("saml20-idp-SSO", kribMd.Query1(nil, "@entityID"), birkMd.Query1(nil, "@entityID"), "na")

	destination := request.Query1(nil, "./@AssertionConsumerServiceURL")
	//	destination = "https://" + config.ConsentAsAService

	signingMethod := spMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:SigningMethod")
	origResponse := goxml.NewXpFromNode(response.DocGetRootElement())

	response.QueryDashP(nil, "@Destination", destination, nil)
	issuer := config.HubEntityID
	response.QueryDashP(nil, "./saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Issuer", issuer, nil)
	response.QueryDashP(nil, "./@InResponseTo", sRequest.Id, nil)
	response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@InResponseTo", sRequest.Id, nil)

	hubMd, err := Md.Hub.MDQ(config.HubEntityID)
	if err != nil {
		return err
	}

	if response.Query1(nil, `samlp:Status/samlp:StatusCode/@Value`) == "urn:oasis:names:tc:SAML:2.0:status:Success" {

		_, _, _, _, err = checkScope(response, birkMd, response.Query(nil, `/saml:Assertion/saml:AttributeStatement`)[0], false)
		if err != nil {
			return
		}

		if _, err = SLOInfoHandler(w, r, origResponse, kribMd, response, spMd, gosaml.SPRole, "SLO"); err != nil {
			return err
		}

		// Krib always receives attributes with nameformat=urn. Before sending to the real SP we need to look into
		// the metadata for SP to determine the actual nameformat - as WAYF supports both for Md.Internal SPs.
		response.QueryDashP(nil, "./saml:Assertion/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData/@Recipient", destination, nil)
		handleAttributeNameFormat(response, spMd)

		if sigAlg := gosaml.DebugSetting(r, "sigAlg"); sigAlg != "" {
			signingMethod = sigAlg
		}

		for _, q := range config.ElementsToSign {
			err = gosaml.SignResponse(response, q, hubMd, signingMethod, gosaml.SAMLSign)
			if err != nil {
				return err
			}
		}

		if gosaml.DebugSetting(r, "signingError") == "1" {
			response.QueryDashP(nil, `./saml:Assertion/saml:Issuer[2]`, "an extra fake issuer just to make the signature fail ...", nil)
		}

		if gosaml.DebugSetting(r, "encryptAssertion") == "1" {
			gosaml.DumpFile(r, response)
			cert := spMd.Query1(nil, "./md:SPSSODescriptor"+gosaml.EncryptionCertQuery) // actual encryption key is always first
			_, publicKey, _ := gosaml.PublicKeyInfo(cert)
			ea := goxml.NewXpFromString(`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"></saml:EncryptedAssertion>`)
			assertion := response.Query(nil, "saml:Assertion[1]")[0]
			response.Encrypt(assertion, publicKey, ea)
		}
	} else {
		newresponse := gosaml.NewErrorResponse(hubMd, spMd, request, response)

		err = gosaml.SignResponse(newresponse, "/samlp:Response", hubMd, signingMethod, gosaml.SAMLSign)
		if err != nil {
			return
		}
	}

	gosaml.DumpFile(r, response)
	data := formdata{Acs: destination, Samlresponse: base64.StdEncoding.EncodeToString(response.Dump()), RelayState: relayState}
	postForm.Execute(w, data)
	return
}

func SPSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.Internal, Md.Hub, []gosaml.Md{Md.ExternalIdP, Md.Hub}, []gosaml.Md{Md.ExternalSP, Md.Internal}, gosaml.SPRole, "SLO")
}

func BirkSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.ExternalSP, Md.ExternalIdP, []gosaml.Md{Md.Hub}, []gosaml.Md{Md.Internal}, gosaml.IdPRole, "SLO")
}

func KribSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.ExternalIdP, Md.ExternalSP, []gosaml.Md{Md.Hub}, []gosaml.Md{Md.Internal}, gosaml.SPRole, "SLO")
}

func IdPSLOService(w http.ResponseWriter, r *http.Request) (err error) {
	return SLOService(w, r, Md.Internal, Md.Hub, []gosaml.Md{Md.ExternalSP, Md.Hub}, []gosaml.Md{Md.ExternalIdP, Md.Internal}, gosaml.IdPRole, "SLO")
}

func SLOService(w http.ResponseWriter, r *http.Request, issuerMdSet, destinationMdSet gosaml.Md, finalIssuerMdSets, finalDestinationMdSets []gosaml.Md, role int, tag string) (err error) {
	req := []string{"idpreq", "spreq"}
	res := []string{"idpres", "spres"}
	defer r.Body.Close()
	r.ParseForm()
	if _, ok := r.Form["SAMLRequest"]; ok {
		request, issuer, destination, relayState, err := gosaml.ReceiveLogoutMessage(r, issuerMdSet, destinationMdSet, role)
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
			finalIssuer, finalDestination, err := findMdPair(finalIssuerMdSets, finalDestinationMdSets, "{sha1}"+sloinfo.Is, "{sha1}"+sloinfo.De)
			if err != nil {
				return err
			}

			sloinfo.Is = finalIssuer.Query1(nil, "./@entityID")
			sloinfo.De = finalDestination.Query1(nil, "./@entityID")

			newRequest, err := gosaml.NewLogoutRequest(finalIssuer, finalDestination, request, sloinfo, role)
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
			privatekey, _ := gosaml.GetPrivateKey(finalIssuer)
			u, _ := gosaml.SAMLRequest2Url(newRequest, relayState, string(privatekey), "-", "")
			http.Redirect(w, r, u.String(), http.StatusFound)
		} else {
			err = fmt.Errorf("no Logout info found")
			return err
		}
	} else if _, ok := r.Form["SAMLResponse"]; ok {
		response, issuer, destination, relayState, err := gosaml.ReceiveLogoutMessage(r, issuerMdSet, destinationMdSet, role)
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
		issuerMd, destinationMd, err := findMdPair(finalIssuerMdSets, finalDestinationMdSets, request.Query1(nil, "@Destination"), request.Query1(nil, "./saml:Issuer"))
		if err != nil {
			return err
		}

		err = session.Del(w, r, "SLO-"+idHash(destID), authnRequestCookie)
		if err != nil {
			return err
		}

		newResponse := gosaml.NewLogoutResponse(issuerMd, destinationMd, request, response)

		privatekey, err := gosaml.GetPrivateKey(issuerMd)

		if err != nil {
			return err
		}
		u, _ := gosaml.SAMLRequest2Url(newResponse, relayState, string(privatekey), "-", "")
		http.Redirect(w, r, u.String(), http.StatusFound)
		// forward the LogoutResponse to orig sender
	} else {
		err = fmt.Errorf("no LogoutRequest/logoutResponse found")
		return err
	}
	return
}

// finds a pair of metdata in the metadatasets - both must come from the corresponding paris in the sets
func findMdPair(finalIssuerMdSets, finalDestinationMdSets []gosaml.Md, issuer, destination string) (issuerMd, destinationMd *goxml.Xp, err error) {
	for i := range finalIssuerMdSets {
		issuerMd, err = finalIssuerMdSets[i].MDQ(issuer)
		if err != nil {
			continue
		}
		destinationMd, err = finalDestinationMdSets[i].MDQ(destination)
		if err != nil {
			continue
		}
		return
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

		slo := gosaml.NewSLOInfo(samlIn, destinationInMd)
		slo.Is = idHash(slo.Is)
		slo.De = idHash(slo.De)
		bytes, _ = json.Marshal(&slo)
		session.Set(w, r, hashOut, config.Domain, bytes, sloInfoCookie, sloInfoTTL)

		slo = gosaml.NewSLOInfo(samlOut, destinationOutMd)
		slo.Is = idHash(slo.Is)
		slo.De = idHash(slo.De)
		bytes, _ = json.Marshal(&slo)
		session.Set(w, r, hashIn, config.Domain, bytes, sloInfoCookie, sloInfoTTL)

	}
	return
}

func idHash(data string) string {
	return fmt.Sprintf("%.5x", sha1.Sum([]byte(data)))
}

func handleAttributeNameFormat(response, mdsp *goxml.Xp) {
	const (
		basic  = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
		claims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
	)
	requestedattributes := mdsp.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute")
	attributestatements := response.Query(nil, "(./saml:Assertion/saml:AttributeStatement | ./t:RequestedSecurityToken/saml:Assertion/saml:AttributeStatement)")
	if len(attributestatements) != 0 {
		attributestatement := attributestatements[0]
		for _, attr := range requestedattributes {
			basicname := mdsp.Query1(attr, "@FriendlyName")
			uriname := basic2uri[basicname].uri
			responseattribute := response.Query(attributestatement, "saml:Attribute[@Name="+strconv.Quote(uriname)+"]")
			if len(responseattribute) > 0 {
				switch mdsp.Query1(attr, "@NameFormat") {
				case basic:
					response.QueryDashP(responseattribute[0], "@NameFormat", basic, nil)
					response.QueryDashP(responseattribute[0], "@Name", basicname, nil)
				case claims:
					response.QueryDashP(responseattribute[0], "@AttributeNamespace", claims, nil)
					response.QueryDashP(responseattribute[0], "@AttributeName", basic2uri[basicname].claim, nil)
					responseattribute[0].(types.Element).RemoveAttribute("Name")
					responseattribute[0].(types.Element).RemoveAttribute("NameFormat")
					responseattribute[0].(types.Element).RemoveAttribute("FriendlyName")
				}
			}
		}
	}
}

func handleAttributeNameFormat2(response, mdsp *goxml.Xp) {
	const (
		basic  = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"
		claims = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims"
	)
	requestedattributes := mdsp.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute")
	attributestatements := response.Query(nil, "(./saml:Assertion/saml:AttributeStatement | ./t:RequestedSecurityToken/saml:Assertion/saml:AttributeStatement)")

	if len(attributestatements) != 0 {
		attributestatement := attributestatements[0]
		for _, attr := range requestedattributes {
			basicname := mdsp.Query1(attr, "@FriendlyName")
			uriname := basic2uri[basicname].uri
			responseattribute := response.Query(attributestatement, "saml:Attribute[@Name="+strconv.Quote(uriname)+"]")
			if len(responseattribute) > 0 {
				switch mdsp.Query1(attr, "@NameFormat") {
				default:
					response.QueryDashP(responseattribute[0], "@AttributeNamespace", claims, nil)
					response.QueryDashP(responseattribute[0], "@AttributeName", basic2uri[basicname].claim, nil)
					responseattribute[0].(types.Element).RemoveAttribute("Name")
					responseattribute[0].(types.Element).RemoveAttribute("NameFormat")
					responseattribute[0].(types.Element).RemoveAttribute("FriendlyName")
				}
			}
		}
	}
}

func checkScope(xp, md *goxml.Xp, context types.Node, requireEppn bool) (eppn, eppnForEptid, securityDomain string, eppsas []string, err error) {
	eppns := xp.QueryMulti(context, "saml:Attribute[@Name='eduPersonPrincipalName' or @Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.6']/saml:AttributeValue")
	eppsas = xp.QueryMulti(context, `saml:Attribute[@Name="eduPersonScopedAffiliation" or @Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.9']/saml:AttributeValue`)
	l := len(eppns)
	switch {
	case l == 1:
		eppn = eppns[0]
		eppnForEptid = eppn
		matches := scoped.FindStringSubmatch(eppn)
		if len(matches) != 3 {
			err = fmt.Errorf("not a scoped value: %s", eppn)
			return
		}
		securityDomain = matches[1] + matches[2]                  // rm matches[2] when @aau.dk goes away
		if matches[2] == "" && aauscope.MatchString(matches[1]) { // legacy support for old @aau.dk scopes for persistent nameid and eptid
			eppnForEptid += "@aau.dk"
		}
	case requireEppn:
		err = fmt.Errorf("Mandatory 'eduPersonPrincipalName' attribute missing")
		return
	case l == 0: // try to get a security domain from a epsa value
		if len(eppsas) > 0 {
			matches := scoped.FindStringSubmatch(eppsas[0])
			if len(matches) != 3 {
				err = fmt.Errorf("not a scoped value: %s", eppn)
				return
			}
			securityDomain = matches[1] + matches[2] // rm matches[2] when @aau.dk goes away
		}
	default: // never more than one
		err = fmt.Errorf("More than one 'eduPersonPrincipalName' value")
		return
	}

	scope := md.Query(nil, "//shibmd:Scope[.="+strconv.Quote(securityDomain)+"]")
	if len(scope) == 0 {
		err = fmt.Errorf("security domain '%s' does not match any scopes", securityDomain)
		return
	}

	subSecurityDomain := "." + securityDomain
	for _, eppsa := range eppsas {
		eppsaparts := scoped.FindStringSubmatch(eppsa)
		if len(eppsaparts) != 3 {
			err = fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", eppsa)
			return
		}
		domain := eppsaparts[1] + eppsaparts[2]
		if requireEppn {
			if domain != securityDomain && !strings.HasSuffix(domain, subSecurityDomain) {
				err = fmt.Errorf("eduPersonScopedAffiliation: %s has not '%s' as security sub domain", eppsa, securityDomain)
				return

			}
		} else {
			if domain != securityDomain {
				err = fmt.Errorf("eduPersonScopedAffiliation: %s has not '%s' as security domain", eppsa, securityDomain)
				return
			}
		}
	}
	return
}

func IdWayfDkSSOService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()

	request, spMd, idpMd, relayState, err := gosaml.ReceiveAuthnRequest(r, Md.ExternalSP, Md.ExternalIdP)
	if err != nil {
		return err
	}

	authIdP := ""
	if tmp, _ := r.Cookie("IdP"); tmp != nil {
		authIdP = tmp.Value
	}

	idpLists := [][]string{
		{authIdP},
		{r.URL.Query().Get("idpentityid")},
	}

	if idp2 := wayf(w, r, request, spMd, idpLists); idp2 != "" {
		idp2Md, err := Md.ExternalIdP.MDQ(idp2)
		if err != nil {
			return err
		}

		idp := idpMd.Query1(nil, "@entityID")
		sp2Md, err := Md.ExternalSP.MDQ("https://id.wayf.dk")
		if err != nil {
			return err
		}
		http.SetCookie(w, &http.Cookie{Name: "IdP", Value: idp2, Path: "/", Secure: true, HttpOnly: true, MaxAge: 31536000})

		err = sendRequestToIdP(w, r, request, sp2Md, idp2Md, idp, relayState, "ID-WAYF-DK-", "", "", false, false, nil)
		return err
	}
	return
}

func IdWayfDkACSService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, spMd, relayState, err := gosaml.ReceiveSAMLResponse(r, Md.ExternalIdP, Md.ExternalSP, "https://"+r.Host+r.URL.Path)
	if err != nil {
		return
	}
	spMd, request, sRequest, err := getOriginalRequest(w, r, response, Md.Internal, Md.ExternalSP, "ID-WAYF-DK-")
	if err != nil {
		return
	}

	signingMethod := spMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:SigningMethod")

	issuerMd, err := Md.ExternalIdP.MDQ(sRequest.De)
	if err != nil {
		return
	}

	var newresponse *goxml.Xp
	if response.Query1(nil, `samlp:Status/samlp:StatusCode/@Value`) == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		newresponse = gosaml.NewResponse(issuerMd, spMd, request, response)

		nameid := newresponse.Query(nil, "./saml:Assertion/saml:Subject/saml:NameID")[0]
		// respect nameID in req, give persistent id + all computed attributes + nameformat conversion
		// The response at this time contains a full attribute set
		nameidformat := request.Query1(nil, "./samlp:NameIDPolicy/@Format")
		if nameidformat == gosaml.Persistent {
			newresponse.QueryDashP(nameid, "@Format", gosaml.Persistent, nil)
			eptid := newresponse.Query1(nil, `./saml:Assertion/saml:AttributeStatement/saml:Attribute[@FriendlyName="eduPersonTargetedID"]/saml:AttributeValue`)
			newresponse.QueryDashP(nameid, ".", eptid, nil)
		} else { // if nameidformat == gosaml.Transient
			newresponse.QueryDashP(nameid, ".", gosaml.Id(), nil)
		}

		for _, q := range config.ElementsToSign {
			err = gosaml.SignResponse(newresponse, q, issuerMd, signingMethod, gosaml.SAMLSign)
			if err != nil {
				return err
			}
		}
	} else {
		newresponse = gosaml.NewErrorResponse(issuerMd, spMd, request, response)

		err = gosaml.SignResponse(newresponse, "/samlp:Response", issuerMd, signingMethod, gosaml.SAMLSign)
		if err != nil {
			return
		}
	}

	// when consent as a service is ready - we will post to that
	// acs := newresponse.Query1(nil, "@Destination")

	gosaml.DumpFile(r, newresponse)

	data := formdata{Acs: request.Query1(nil, "./@AssertionConsumerServiceURL"), Samlresponse: base64.StdEncoding.EncodeToString(newresponse.Dump()), RelayState: relayState}
	postForm.Execute(w, data)
	return
}
