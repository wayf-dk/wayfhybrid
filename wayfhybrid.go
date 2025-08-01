package wayfhybrid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path"
	"regexp"
	"runtime/pprof"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/wayf-dk/godiscoveryservice"
	"github.com/wayf-dk/goeleven"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lmdq"
	"x.config"
)

const (
	authnRequestTTL = 180
	sloInfoTTL      = 8 * 3600
	codeTTL         = 60
	xprefix         = "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:"
	ssoCookieName   = "SSO2-"
	sloCookieName   = "SLO"
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	mddb struct {
		db, table string
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
		Name, FriendlyName string
		Must               bool
		Values             []string
	}

	webMd struct {
		md, revmd *lmdq.MDQ
	}

	claimsInfo struct {
		claims    map[string]any
		client_id string
		debug     string
		eol       time.Time
	}
)

var (
	_ = log.Printf // For debugging; delete when done.
	_ = fmt.Printf

	allowedInFeds = regexp.MustCompile("[^\\w\\.-]")
	scoped        = regexp.MustCompile(`^([^\@]+)\@([a-zA-Z0-9][a-zA-Z0-9\.-]+[a-zA-Z0-9])$`)
	dkcprpreg     = regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	oldSafari     = regexp.MustCompile("iPhone.*Version/12.*Safari")
	acceptHeader  = regexp.MustCompile(`(?i)\s*([a-z]+-?(?:[a-z]+)?)\s*(?:;\s*q=(1|1\.0{0,3}|0|0\.\d{0,3}))?\s*(?:,|$)`)
	subjectuid    = regexp.MustCompile(`^[A-Za-z0-9=-]+$`)

	allowedDigestAndSignatureAlgorithms = []string{"sha256", "sha384", "sha512"}
	defaultDigestAndSignatureAlgorithm  = "sha256"

	metadataUpdateGuard chan int

	session = wayfHybridSession{}

	sloInfoCookie, authnRequestCookie *gosaml.Hm
	tmpl                              *template.Template
	hostName                          string

	md mdSets

	intExtSP, intExtIDP, hubExtIDP, hubExtSP gosaml.MdSets

	webMdMap map[string]webMd
	client   = &http.Client{}

	claimsMap = sync.Map{}
)

// Main - start the hybrid
func Main() {
	log.SetFlags(0) // no predefined time

	hostName, _ = os.Hostname()

	goeleven.Init(config.GoElevenHybrid)

	tmpl = template.Must(template.New("name").Parse(config.HybridTmpl))
	gosaml.PostForm = tmpl

	cleanUp(&claimsMap)

	metadataUpdateGuard = make(chan int, 1)

	md.Hub = &lmdq.MDQ{MdDb: config.Hub}
	md.Internal = &lmdq.MDQ{MdDb: config.Internal}
	md.ExternalIDP = &lmdq.MDQ{MdDb: config.ExternalIDP}
	md.ExternalSP = &lmdq.MDQ{MdDb: config.ExternalSP}

	intExtSP = gosaml.MdSets{md.Internal, md.ExternalSP}
	intExtIDP = gosaml.MdSets{md.Internal, md.ExternalIDP}
	hubExtIDP = gosaml.MdSets{md.Hub, md.ExternalIDP}
	hubExtSP = gosaml.MdSets{md.Hub, md.ExternalSP}

	str, err := refreshAllMetadataFeeds(!*config.BypassMdUpdate)
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
		webMdMap[md.Table] = m
		webMdMap[md.Short] = m
	}

	hashKey, _ := hex.DecodeString(config.SecureCookieHashKey)
	authnRequestCookie = &gosaml.Hm{TTL: authnRequestTTL, Hash: sha256.New, Key: hashKey}
	gosaml.AuthnRequestCookie = authnRequestCookie
	sloInfoCookie = &gosaml.Hm{TTL: sloInfoTTL, Hash: sha256.New, Key: hashKey}

	httpMux := http.NewServeMux()

	for _, pattern := range config.NotFoundRoutes {
		httpMux.Handle(pattern, http.NotFoundHandler())
	}

	httpMux.Handle("/production", appHandler(OkService))
	httpMux.Handle(config.Vvpmss, appHandler(VeryVeryPoorMansScopingService))
	httpMux.Handle(config.OidcConfigurationService, appHandler(OidcConfigurationService))
	httpMux.Handle(config.OidcConfigurationService2, appHandler(OidcConfigurationService))
	httpMux.Handle(config.SsoService, appHandler(SSOService))
	httpMux.Handle(config.SsoService2, appHandler(SSOService))
	httpMux.Handle(config.OIDCAuth, appHandler(SSOService))
	httpMux.Handle(config.OIDCToken, appHandler(OIDCTokenService))
	httpMux.Handle(config.OIDCUserinfo, appHandler(OIDCUserinfoService))

	httpMux.Handle(config.Idpslo, appHandler(IDPSLOService))
	httpMux.Handle(config.Idpslo2, appHandler(IDPSLOService))
	httpMux.Handle(config.Birkslo, appHandler(BirkSLOService))
	httpMux.Handle(config.Spslo, appHandler(SPSLOService))
	httpMux.Handle(config.Spslo2, appHandler(SPSLOService))
	httpMux.Handle(config.Kribslo, appHandler(KribSLOService))
	httpMux.Handle(config.Nemloginslo, appHandler(SPSLOService))

	httpMux.Handle(config.Acs, appHandler(ACSService))
	httpMux.Handle(config.Acs2, appHandler(ACSService))
	httpMux.Handle(config.NemloginAcs, appHandler(ACSService))
	httpMux.Handle(config.NemloginAcs3, appHandler(ACSService))
	httpMux.Handle(config.Birk, appHandler(SSOService))
	httpMux.Handle(config.Krib, appHandler(ACSService))
	httpMux.Handle(config.Dsbackend, appHandler(godiscoveryservice.DSBackend))
	httpMux.Handle(config.Dstiming, appHandler(godiscoveryservice.DSTiming))

	fs := http.FileServer(http.FS(config.PublicFiles))
	suffixes := map[string]string{".jwk": "application/jwk+json"}
	f := func(w http.ResponseWriter, r *http.Request) (err error) {
		for suffix, mimetype := range suffixes {
			if strings.HasSuffix(r.RequestURI, suffix) {
				w.Header().Set("Content-Type", mimetype)
			}
		}
		fs.ServeHTTP(w, r)
		return
	}

	httpMux.Handle(config.Public, appHandler(f))
	httpMux.Handle(config.TestSP+"/ds/", appHandler(f))
	httpMux.Handle(config.TestSP2+"/ds/", appHandler(f))

	httpMux.Handle(config.Saml2jwt, appHandler(saml2jwt))
	httpMux.Handle(config.Jwt2saml, appHandler(jwt2saml))
	httpMux.Handle(config.MDQ, appHandler(MDQWeb))

	httpMux.Handle(config.TestSPSlo, appHandler(testSPService))
	httpMux.Handle(config.TestSPAcs, appHandler(testSPService))
	httpMux.Handle(config.TestSP+"/", appHandler(testSPService)) // need a root "/" for routing

	httpMux.Handle(config.TestSP2Slo, appHandler(testSPService))
	httpMux.Handle(config.TestSP2Acs, appHandler(testSPService))
	httpMux.Handle(config.TestSP2+"/", appHandler(testSPService)) // need a root "/" for routing

	log.Println("listening on ", config.Intf)
	var s *http.Server
	go func() {
		cert, _ := tls.X509KeyPair(config.ServerCrt, config.ServerKey)
		s = &http.Server{
			Addr:    config.Intf,
			Handler: &slashFix{httpMux},
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
			},
		}
		s.SetKeepAlivesEnabled(false)
		err = s.ListenAndServeTLS("", "")
		if err != nil {
			log.Printf("main(): %s\n", err)
		} else {
			log.Println("hybrid stopped gracefully")
		}
	}()

	mdUpdateMux := http.NewServeMux()
	mdUpdateMux.Handle("/", appHandler(updateMetadataService)) // need a root "/" for routing

	intf := regexp.MustCompile(`^(.*:).*$`).ReplaceAllString(config.Intf, "$1") + "9000"
	log.Println("listening on ", intf)
	go func() {
		err = http.ListenAndServe(intf, mdUpdateMux)
		if err != nil {
			log.Printf("main(): %s\n", err)
		}
	}()

	if *config.Test && !*config.Verbose { // stop logging under test from here - functionaltest will wait a few secs so we get the listening on ...
		log.SetOutput(io.Discard)
	}

	stopCh, closeCh := createChannel()
	go func() {
		defer closeCh()
		log.Println("notified:", <-stopCh)
		log.SetOutput(os.Stderr)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := s.Shutdown(ctx); err != nil {
			panic(err)
		} else {
			log.Println("finalize nemlog")
			gosaml.NemLog.Finalize()
			log.Println("application shutdowned")
			os.Exit(5)
		}
	}()
}

func createChannel() (chan os.Signal, func()) {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	return stopCh, func() {
		close(stopCh)
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
	v := cc.String()
	if !oldSafari.MatchString(r.Header.Get("User-Agent")) {
		v = v + "; SameSite=None"
	}
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
func (s wayfHybridSession) Del(w http.ResponseWriter, r *http.Request, id, domain string, secCookie *gosaml.Hm) (err error) {
	// http.SetCookie(w, &http.Cookie{Name: id, Domain: domain, Value: "", Path: "/", Secure: true, HttpOnly: true, Expires: time.Unix(0, 0),  SameSite: http.SameSiteNoneMode})
	cc := http.Cookie{Name: id, Domain: domain, Value: "", Path: "/", Secure: true, HttpOnly: true, Expires: time.Unix(0, 0)}
	v := cc.String()
	if !oldSafari.MatchString(r.Header.Get("User-Agent")) {
		v = v + "; SameSite=None"
	}
	w.Header().Add("Set-Cookie", v)
	return
}

// GetDel responsible for getting and then deleting cookie values
func (s wayfHybridSession) GetDel(w http.ResponseWriter, r *http.Request, id, domain string, secCookie *gosaml.Hm) (data []byte, err error) {
	data, err = s.Get(w, r, id, secCookie)
	s.Del(w, r, id, domain, secCookie)
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

	w.Header().Set("X-Frame-Options", "sameorigin")
	w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

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

	//log.Printf("%s: %s", err, r.Header.Get("User-Agent"))
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

func PProf(w http.ResponseWriter, r *http.Request) (err error) {
	f, _ := os.Create("heap.pprof")
	pprof.WriteHeapProfile(f)
	return
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
				if err = refreshMetadataFeed(mdfeed); err != nil {
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
func refreshMetadataFeed(mdfeed config.MdFeed) (err error) {
	dir := path.Dir(mdfeed.Path)
	tempmddb, err := os.CreateTemp(dir, "")
	if err != nil {
		return err
	}
	defer tempmddb.Close()
	defer os.Remove(tempmddb.Name())

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: mdfeed.InsecureSkipVerify},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   30 * time.Second,
	}

	//client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(mdfeed.URL)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, err = io.Copy(tempmddb, resp.Body)
	if err != nil {
		return err
	}
	if err = os.Rename(tempmddb.Name(), mdfeed.Path); err != nil {
		return err
	}
	return
}

func testSPService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()

	type testSPFormData struct {
		Protocol, RelayState, ResponsePP, Issuer, Destination, External, ScopedIDP, Marshalled string
		Code_challenge, AssertionConsumerServiceURL                                            string
		Messages                                                                               template.HTML
		AttrValues, DebugValues                                                                []attrValue
	}

	spMd, err := md.Internal.MDQ("https://" + r.Host)
	pk, _, _ := gosaml.GetPrivateKey(spMd, "md:SPSSODescriptor"+gosaml.SigningCertQuery)
	idp := r.Form.Get("idpentityid")
	login := r.Form.Get("login") == "1"
	scoping := r.Form.Get("scoping")
	scopedIDP := r.Form.Get("scopedidp") + r.Form.Get("entityID") + idp // RI says entityID
	idpList := strings.Split(scopedIDP, ",")

	formdata := testSPFormData{
		AssertionConsumerServiceURL: "https://" + r.Host + "/ACS",
	}

	if r.Form.Get("ds") != "" {
		data := url.Values{}
		data.Set("return", "https://"+r.Host+"/?previdplist="+r.Form.Get("scopedidp"))
		data.Set("returnIDParam", "idpentityid")
		data.Set("entityID", "https://"+r.Host)
		discoService := spMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:discoveryService")
		if discoService == "" {
			discoService = config.DiscoveryService
		}
		http.Redirect(w, r, discoService+data.Encode(), http.StatusFound)
	} else if login {
		data := url.Values{}
		switch {
		case len(idpList) == 1 && idpList[0] == "":
		case len(idpList) == 1:
			data.Set("idpentityid", scopedIDP)
		default:
			data.Set("idplist", scopedIDP)
		}

		protocol := r.Form.Get("protocol")
		if protocol == "oidc" {
			data.Set("response_type", "id_token")
			data.Set("client_id", "https://"+r.Host)
			data.Set("redirect_uri", "https://"+r.Host+"/ACS")
			data.Set("nonce", gosaml.ID())
			http.Redirect(w, r, "https://"+config.SsoService+"?"+data.Encode(), http.StatusFound)
			return
		} else if protocol == "wsfed" {
			data.Set("wa", "wsignin1.0")
			data.Set("wtrealm", "https://"+r.Host)
			http.Redirect(w, r, "https://"+config.SsoService+"?"+data.Encode(), http.StatusFound)
			return
		}

		idpMd, err := md.Hub.MDQ(config.HubEntityID)
		if err != nil {
			return err
		}

		if scopedIDP == "" && idp == "" {
			data := url.Values{}
			data.Set("return", "https://"+r.Host+r.RequestURI)
			data.Set("returnIDParam", "idpentityid")
			data.Set("entityID", "https://"+r.Host)
			discoService := spMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:discoveryService")
			if discoService == "" {
				discoService = config.DiscoveryService
			}
			http.Redirect(w, r, discoService+data.Encode(), http.StatusFound)
			return err
		}

		http.SetCookie(w, &http.Cookie{Name: "idpentityID", Value: idp, Path: "/", Secure: true, HttpOnly: false})

		if scoping == "testidp" {
			http.SetCookie(w, &http.Cookie{Name: "testidp", Value: scopedIDP, Domain: "wayf.dk", Path: "/", Secure: true, HttpOnly: false})
		}

		if scoping == "birk" {
			idpMd, err = md.ExternalIDP.MDQ(scopedIDP)
			if err != nil {
				return err
			}
		}

		newrequest, _, _ := gosaml.NewAuthnRequest(nil, spMd, idpMd, "", nil, "", false, 0, 0)

		options := []struct {
			name, path string
		}{
			{"isPassive", "./@IsPassive"},
			{"forceAuthn", "./@ForceAuthn"},
			{"nameIDPolicy", "./samlp:NameIDPolicy/@Format"},
			{"requestedauthncontext", "./samlp:RequestedAuthnContext/saml:AuthnContextClassRef[0]"},
			{"requestedauthncontextcomparison", "./samlp:RequestedAuthnContext/@Comparison"},
		}

		for _, option := range options {
			for _, val := range r.Form[option.name] {
				if val != "" {
					newrequest.QueryDashP(nil, option.path, val, nil)
				}
			}
		}

		if scoping == "scoping" || scoping == "" {
			for _, scope := range idpList {
				newrequest.QueryDashP(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID", scope, nil)
			}
		}

		u, err := gosaml.SAMLRequest2URL(newrequest, "", pk, config.DefaultCryptoMethod)
		if err != nil {
			return err
		}

		q := u.Query()

		if gosaml.DebugSetting(r, "signingError") == "1" {
			signature := q.Get("Signature")
			q.Set("Signature", signature[:len(signature)-4]+"QEBA")
		}

		if scoping == "param" {
			switch len(idpList) {
			case 0:
			case 1:
				q.Set("idpentityid", scopedIDP)
			default:
				q.Set("idplist", scopedIDP)
			}
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusFound)
		return nil
	} else if r.Form.Get("logout") == "1" || r.Form.Get("logoutresponse") == "1" {
		spMd, _, err := gosaml.FindInMetadataSets(intExtSP, r.Form.Get("destination"))
		if err != nil {
			return err
		}
		idpMd, _, err := gosaml.FindInMetadataSets(hubExtIDP, r.Form.Get("issuer"))
		if err != nil {
			return err
		}
		if r.Form.Get("logout") == "1" {
			gosaml.SloRequest(w, r, goxml.NewXpFromString(r.Form.Get("response")), spMd, idpMd, pk, "")
		} else {
			gosaml.SloResponse(w, r, goxml.NewXpFromString(r.Form.Get("response")), spMd, idpMd, pk, gosaml.IDPRole)
		}
	} else if r.Form.Get("SAMLRequest") != "" || r.Form.Get("SAMLResponse") != "" {
		// try to decode SAML message to ourselves or just another SP
		// don't do destination check - we accept and dumps anything ...
		external := "0"
		messages := []string{}
		response, issuerMd, destinationMd, relayState, _, _, err := gosaml.DecodeSAMLMsg(r, hubExtIDP, gosaml.MdSets{md.Internal}, gosaml.SPRole, []string{"Response", "LogoutRequest", "LogoutResponse"}, "https://"+r.Host+r.URL.Path, nil)
		if err != nil {
			return err
		}

		var vals, debugVals []attrValue
		var marshalledResponse string
		incomingResponseXML := response.PP()
		protocol := response.QueryString(nil, "local-name(/*)")
		if protocol == "Response" {
			if err := gosaml.CheckDigestAndSignatureAlgorithms(response); err != nil {
				return err
			}
			hubMd, _ := md.Hub.MDQ(config.HubEntityID)
			vals = attributeValues(response, destinationMd, hubMd)
			s, _ := json.MarshalIndent(response2JSON(response), "", "    ")
			marshalledResponse = string(s)
			err = Attributesc14n(response, response, issuerMd, destinationMd)
			if err != nil {
				messages = append(messages, err.Error())
			}
			err = wayfScopeCheck(response, issuerMd)
			if err != nil {
				messages = append(messages, err.Error())
			}

			xpathTests, err := r.Cookie("xpathchecks")
			if err == nil && xpathTests.Value != "" {
				var tests []string
				val, _ := url.QueryUnescape(xpathTests.Value)
				if err := json.Unmarshal([]byte(val), &tests); err == nil {
					for _, test := range tests {
						if test != "" {
							res := fmt.Sprintf("%v == %v", test, response.Query1(nil, test))
							messages = append(messages, res)
						}

					}
				}
			}

			debugVals = attributeValues(response, destinationMd, hubMd)
		}

		formdata.RelayState = relayState
		formdata.ResponsePP = incomingResponseXML
		formdata.Destination = destinationMd.Query1(nil, "./@entityID")
		formdata.Messages = template.HTML(strings.Join(messages, "<br>"))
		formdata.Issuer = issuerMd.Query1(nil, "./@entityID")
		formdata.External = external
		formdata.Protocol = protocol
		formdata.AttrValues = vals
		formdata.DebugValues = debugVals
		formdata.ScopedIDP = response.Query1(nil, "//saml:AuthenticatingAuthority[last()]")
		formdata.Marshalled = marshalledResponse
		return tmpl.ExecuteTemplate(w, "testSPForm", formdata)
	} else if id_token := r.Form.Get("id_token"); id_token != "" {
		attrs, _, err := gosaml.JwtVerify(id_token, gosaml.MdSets{md.Hub}, spMd, gosaml.SPEnc, "")
		if err != nil {
			return goxml.Wrap(err)
		}
		jsonDump, _ := json.MarshalIndent(attrs, "", "    ")
		formdata.RelayState = r.Form.Get("state")
		formdata.ResponsePP = string(jsonDump)
		return tmpl.ExecuteTemplate(w, "testSPForm", formdata)
	} else if wresult := r.Form.Get("wresult"); wresult != "" {
		xp := goxml.NewXpFromString(wresult)
		formdata.ResponsePP = xp.PP()
		formdata.Protocol = xp.QueryString(nil, "local-name(/*)")
		return tmpl.ExecuteTemplate(w, "testSPForm", formdata)
	} else {
		formdata.ScopedIDP = strings.Trim(r.Form.Get("idpentityid")+","+r.Form.Get("previdplist"), " ,")
		return tmpl.ExecuteTemplate(w, "testSPForm", formdata)
	}
	return
}

func response2JSON(response *goxml.Xp) (res map[string][]string) {
	extracts := map[string]string{
		"SessionNotOnOrAfter":     "//@SessionNotOnOrAfter",
		"NameID":                  "//saml:NameID",
		"SPNameQualifier":         "//saml:NameID/@SPNameQualifier",
		"AuthenticatingAuthority": "//saml:AuthenticatingAuthority",
		//		"@FriendlyName":           "//saml:AttributeStatement/saml:Attribute",
		"eppn": "//*[@Name='eduPersonPrincipalName' or @Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.6']",
	}
	res = map[string][]string{}
	for short, xpath := range extracts {
		tp := strings.SplitN(short, "@", 2)
		if len(tp) > 1 {
			for _, x := range response.Query(nil, xpath) {
				res[tp[0]+response.Query1(x, "@"+tp[1])] = response.QueryMulti(x, ".")
			}
			continue
		}
		res[short] = response.QueryMulti(nil, xpath)
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
		if name == friendlyName {
			friendlyName = ""
		}

		must := hubMd.Query1(nil, `.//md:RequestedAttribute[@Name=`+strconv.Quote(name)+`]/@must`) == "true"

		// accept attributes in both uri and basic format
		attrValues := response.QueryMulti(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+`]/saml:AttributeValue`)
		values = append(values, attrValue{Name: name, FriendlyName: friendlyName, Must: must, Values: attrValues})
	}

	// Add a delimiter
	values = append(values, attrValue{Name: "---"})

	for _, name := range response.QueryMulti(nil, ".//saml:Attribute/@Name") {
		if seen[name] {
			continue
		}
		friendlyName := response.Query1(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+`]/@FriendlyName`)
		attrValues := response.QueryMulti(nil, `.//saml:Attribute[@Name=`+strconv.Quote(name)+`]/saml:AttributeValue`)
		if name == friendlyName {
			friendlyName = ""
		}

		values = append(values, attrValue{Name: name, FriendlyName: friendlyName, Must: false, Values: attrValues})
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

// check that the domain of configured attributes are valid according to shib:scope in md
// if lax is set checks that one of the scopes is a suffix of the domain
// do not fail if no attributes are found

func scopeCheck(values, scopes []string, lax bool) (err error) {
vals:
	for _, value := range values {
		parts := scoped.FindStringSubmatch(value)
		if len(parts) != 3 {
			err = fmt.Errorf("not a scoped value: %s", value)
			return
		}
		for _, scope := range scopes {
			if parts[2] == scope || (lax && strings.HasSuffix(parts[2], "."+scope)) {
				continue vals
			}
		}
		err = fmt.Errorf("security domain '%s' does not match any scopes", parts[2])
		return
	}
	return nil
}

func wayfScopeCheck(response, idpMd *goxml.Xp) (err error) {
	as := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
	scopes := idpMd.QueryMulti(nil, "./md:IDPSSODescriptor/md:Extensions/shibmd:Scope")
	for _, attribute := range config.StrictScopedAttributes {
		values := response.QueryMulti(as, "./saml:Attribute[@Name='"+attribute+"']/saml:AttributeValue")
		if err = scopeCheck(values, scopes, false); err != nil {
			return
		}
	}

	for _, attribute := range config.LaxScopedAttributes {
		values := response.QueryMulti(as, "./saml:Attribute[@Name='"+attribute+"']/saml:AttributeValue")
		if err = scopeCheck(values, scopes, true); err != nil {
			return
		}
	}
	return nil
}

func wayfACSServiceHandler(backendIdpMd, idpMd, hubMd, spMd, request, response *goxml.Xp, birk bool, r *http.Request) (ard AttributeReleaseData, err error) {
	ard = AttributeReleaseData{IDPDisplayName: make(map[string]string), SPDisplayName: make(map[string]string), SPDescription: make(map[string]string)}
	idp := idpMd.Query1(nil, "@entityID")

	attrList := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
	eppns := response.QueryMulti(attrList, "./saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
	if len(eppns) != 1 {
		err = fmt.Errorf("isRequired: exactly 1 eduPersonPrincipalName")
		return
	}

	if !subjectuid.MatchString(response.Query1(attrList, "./saml:Attribute[@Name='uid']/saml:AttributeValue")) && config.Prod {
		fmt.Println("subjectidproblem:", base64.RawURLEncoding.EncodeToString([]byte(eppns[0])))
	}

	if acl := idpMd.Query1(nil, xprefix+`Acl`); acl != "" {
		var verify func(rule []any) bool
		verify = func(rule []any) bool {
			op := rule[0].(string)
			switch op {
			case "or":
				return slices.ContainsFunc(rule[1:], func(x any) bool { return verify(x.([]any)) })
			case "and":
				return !slices.ContainsFunc(rule[1:], func(x any) bool { return !verify(x.([]any)) })
			default:
				return slices.ContainsFunc(rule[1:], func(x any) bool {
					val := response.Query1(attrList, "./saml:Attribute[@Name="+strconv.Quote(op)+"]/saml:AttributeValue[.="+strconv.Quote(x.(string))+"]")
					return val != ""
				})
			}
		}
		aclList := []any{}
		if err = json.Unmarshal([]byte(acl), &aclList); err != nil {
			return
		}
		if !verify(aclList) {
			return ard, fmt.Errorf("access denied. acl = %s", acl)
		}
	}

	prior := response.Query1(attrList, `./saml:Attribute[@Name="eduPersonPrincipalNamePrior"]/saml:AttributeValue`)
	if prior != "" {
		localScope := scoped.FindStringSubmatch(prior)
		if len(localScope) > 1 {
			scope := localScope[2]
			spID := response.Query1(attrList, `./saml:Attribute[@Name="spID"]/saml:AttributeValue`)
			xpx := xprefix + `eduPersonPrincipalNamePrior[wayf:ServiceProvider=` + strconv.Quote(spID) + ` and (wayf:Scope=` + strconv.Quote(scope) + ` or not(wayf:Scope))]`
			usePrior := idpMd.Query(nil, xpx)
			if len(usePrior) == 1 {
				response.QueryDashP(attrList, `./saml:Attribute[@Name="eduPersonPrincipalName"]/saml:AttributeValue`, prior, nil)
				xpx := xprefix + `eduPersonPrincipalNamePrior/wayf:Scope[.=` + strconv.Quote(scope) + `]/`
				schacHomeOrganization := idpMd.Query1(nil, xpx+"@schacHomeOrganization")
				persistentIDPEntityid := idpMd.Query1(nil, xpx+"@persistentIDPEntityID")
				if err = ChangeScope(r, response, backendIdpMd, idpMd, spMd, scope, schacHomeOrganization, persistentIDPEntityid, false); err != nil {
					return
				}
			}
		}
	}

	scope := response.Query1(attrList, "./saml:Attribute[@Name='securitydomain']/saml:AttributeValue")
	xpx := xprefix + `ChangeScope[.=` + strconv.Quote(scope) + `]/@NewScope`
	if newscope := idpMd.Query1(nil, xpx); newscope != "" {
		if err = ChangeScope(r, response, backendIdpMd, idpMd, spMd, newscope, "", "", true); err != nil {
			return
		}
	}

	if err = checkForCommonFederations(response); err != nil {
		return
	}
	if err = wayfScopeCheck(response, idpMd); err != nil {
		return
	}

	arp := spMd.QueryMulti(nil, "md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute/@Name")
	arpmap := make(map[string]bool)
	for _, attrName := range arp {
		arpmap[attrName] = true
	}

	uiinfo := idpMd.Query(nil, "./md:IDPSSODescriptor/md:Extensions/mdui:UIInfo")[0]
	ard.IDPDisplayName["en"] = idpMd.Query1(uiinfo, `/mdui:DisplayName[@xml:lang="en"]`)
	ard.IDPDisplayName["da"] = idpMd.Query1(uiinfo, `./mdui:DisplayName[@xml:lang="da"]`)
	ard.IDPLogo = idpMd.Query1(uiinfo, `./mdui:Logo`)
	ard.IDPEntityID = idp
	ard.SPDisplayName["en"] = spMd.Query1(uiinfo, `./mdui:DisplayName[@xml:lang="en"]`)
	ard.SPDisplayName["da"] = spMd.Query1(uiinfo, `./mdui:DisplayName[@xml:lang="da"]`)
	ard.SPDescription["en"] = spMd.Query1(uiinfo, `./mdui:Description[@xml:lang="en"]`)
	ard.SPDescription["da"] = spMd.Query1(uiinfo, `./mdui:Description[@xml:lang="da"]`)
	ard.SPLogo = spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.SPEntityID = spMd.Query1(nil, "@entityID")
	ard.BypassConfirmation = idpMd.QueryBool(nil, `count(`+xprefix+`consent.disable[.= `+strconv.Quote(ard.SPEntityID)+`]) > 0`)
	ard.BypassConfirmation = ard.BypassConfirmation || spMd.QueryXMLBool(nil, xprefix+`consent.disable`)
	ard.ForceConfirmation = spMd.QueryXMLBool(nil, xprefix+`consent.force`)
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
	eppn := response.Query1(attrList, "./saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
	hashedEppn := fmt.Sprintf("%x", goxml.Hash(crypto.SHA256, config.SaltForHashedEppn+eppn))
	legacyStatLog("saml20-idp-SSO", ard.SPEntityID, idp, hashedEppn)
	return
}

func wayfKribHandler(idpMd, spMd, request, response *goxml.Xp) (ard AttributeReleaseData, err error) {
	// we ignore the qualifiers and use the idp and sp entityIDs
	if err = checkForCommonFederations(response); err != nil {
		return
	}
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

func OidcConfigurationService(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	location := "https://" + r.Host + r.URL.Path
	if !strings.HasSuffix(location, ".well-known/openid-configuration") {
		err = fmt.Errorf("no .well-known/openid-configuration found")
	}
	homeorg := r.PathValue("homeorg")
	if homeorg == "" || homeorg == ".well-known" {
		homeorg = "https://wayf.wayf.dk"
	}
	md, _, err := gosaml.FindInMetadataSets(hubExtIDP, homeorg)
	if err != nil {
		return err
	}
	data := map[string]string{
		"issuer": md.Query1(nil, "@entityID"),
		"auth":   md.Query1(nil, "md:IDPSSODescriptor/md:SingleSignOnService/@Location"),
		"name":   md.Query1(nil, `md:Organization/md:OrganizationName[@xml:lang="en"]`),
	}

	w.Header().Set("Content-Type", "application/json")
	return tmpl.ExecuteTemplate(w, "openid-configuration", data)
}

// VeryVeryPoorMansScopingService handles poor man's scoping
func VeryVeryPoorMansScopingService(w http.ResponseWriter, r *http.Request) (err error) {
	r.ParseForm()
	// never both idplist and entityID at the same time ...
	cc := http.Cookie{Name: "vvpmss", Value: r.URL.Query().Get("idplist") + r.URL.Query().Get("entityID"), Path: "/", Secure: true, HttpOnly: true, MaxAge: 10}
	v := cc.String() + "; SameSite=None"
	w.Header().Add("Set-Cookie", v)
	w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
	w.Header().Set("Access-Control-Allow-Credentials", "true")
	w.Header().Set("Content-Type", "text/plain")
	if ri := r.Form.Get("ri"); ri != "" {
		http.Redirect(w, r, ri, http.StatusFound)
		return
	}
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
	r.ParseForm()
	idpLists := [][]string{
		{testidp},
		spMd.QueryMulti(nil, xprefix+"IDPList"),
		request.QueryMulti(nil, "./samlp:Scoping/samlp:IDPList/samlp:IDPEntry/@ProviderID"),
		{r.Form.Get("idpentityid")},
		strings.Split(r.Form.Get("idplist"), ","),
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

	if r.Method == "POST" {
		data.Set("return", "https://"+config.SsoService+"?SAMLRequest="+url.QueryEscape(base64.StdEncoding.EncodeToString(gosaml.Deflate(request.Dump())))+"&RelayState="+url.QueryEscape(r.Form.Get("RelayState")))
	} else {
		data.Set("return", "https://"+r.Host+r.RequestURI)
	}
	data.Set("returnIDParam", "idpentityid")
	data.Set("entityID", sp)

	discoService := spMd.Query1(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:discoveryService")
	if discoService == "" {
		discoService = config.DiscoveryService
	}

	http.Redirect(w, r, discoService+data.Encode(), http.StatusFound)
	return "" // needed to tell our caller to return for discovery ...
}

// SSOService handles single sign on requests
func SSOService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()
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

	RequestHandler(request, virtualIDPMd, spMd)

	// check for common feds before remapping!
	if !request.QueryXMLBool(nil, `//saml:AttributeStatement/saml:Attribute[@Name="commonfederations"]/saml:AttributeValue[1]`) {
		err = fmt.Errorf("no common federations")
	}

	realIDPMd := virtualIDPMd
	var hubKribSPMd *goxml.Xp
	if virtualIDPIndex == 0 { // to internal IDP - also via BIRK
		hubKribSP := config.HubEntityID
		if tmp := virtualIDPMd.Query1(nil, xprefix+"map2SP"); tmp != "" {
			hubKribSP = tmp
		}

		if request.QueryXMLBool(nil, `//*[@Name="nemlogin"]/saml:AttributeValue[1]`) {
			if tmp := spMd.Query1(nil, `//wayf:map2SP`); tmp != "" {
				hubKribSP = tmp
			}
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
	gosaml.NemLog.Log(request, realIDPMd, request.Query1(nil, "@ID"))
	err = sendRequestToIDP(w, r, request, spMd, hubKribSPMd, realIDPMd, virtualIDPMd, relayState, ssoCookieName, "", config.Domain, spIndex, hubBirkIndex, nil)
	return
}

func OIDCTokenService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	dump, dumperr := httputil.DumpRequest(r, true)
	r.ParseForm()
	if r.Form.Get("grant_type") == "authorization_code" {
		// claims, err := decrypt(r.Form.Get("code"), "")
		codein := r.Form.Get("code")
		c, ok := claimsMap.LoadAndDelete(codein)
		if !ok {
			if dumperr != nil {
				http.Error(w, fmt.Sprint(err), http.StatusInternalServerError)
				return err
			}
			return fmt.Errorf("unknown code: %s %q", codein, dump)
		}
		claims := c.(claimsInfo).claims
		debug := c.(claimsInfo).debug
		codeChallenge := claims["@codeChallenge"].(string)
		codeVerifier := r.Form.Get("code_verifier")
		hashedCodeVerifier := sha256.Sum256([]byte(codeVerifier))
		pkceOK := codeVerifier != "" && base64.RawURLEncoding.EncodeToString(hashedCodeVerifier[:]) == codeChallenge
		delete(claims, "@codeChallenge")

		clientId := r.Form.Get("client_id")
		clientSecret := r.Form.Get("client_secret")
		if authorisation := r.Header.Get("Authorization"); authorisation != "" {
			authParam := strings.Split(authorisation+" ", " ")[1] // always gets 2 elements
			basic, _ := base64.StdEncoding.DecodeString(authParam)
			parts := strings.Split(string(basic)+":", ":")
			clientId, _ = url.QueryUnescape(parts[0])
			clientSecret = parts[1]
		}

		spMd, _, err := gosaml.FindInMetadataSets(intExtSP, clientId)
		if err != nil {
			return err
		}
		mdClientSecret := spMd.Query1(nil, xprefix+"OIDC/wayf:client_secret")
		hashedClientSecret := fmt.Sprintf("%x", sha256.Sum256([]byte(clientSecret)))
		clientOK := clientId == claims["aud"].(string) && hashedClientSecret == mdClientSecret

		if !(pkceOK || clientOK) {
			return errors.New("PKCE or client_id check failed")
		}

		//if int64(claims["iat"].(float64))+60 < time.Now().Unix() { // remember if via json it is float64
		if claims["iat"].(int64)+60 < time.Now().Unix() {
			return errors.New("token timeout")
		}

		//access_token, err := encrypt(claims, "")
		//if err != nil {
		//    return err
		//}

		signed, err := signClaims(claims)
		if err != nil {
			return err
		}

		delete(claims, "nonce")
		if nonce := r.Form.Get("nonce"); nonce != "" {
			claims["nonce"] = nonce
		}
		code := hostName + rand.Text()
		claimsMap.Store(code, claimsInfo{claims: claims, debug: debug, client_id: clientId, eol: time.Now().Add(codeTTL * time.Second)})

		resp := map[string]any{
			"access_token": code,
			"token_type":   "Bearer",
			"id_token":     signed,
			"expires_in":   codeTTL,
		}

		res, err := json.Marshal(&resp)
		if err != nil {
			return err
		}
		if gosaml.DebugSetting2(debug, "trace") == "1" {
			plainJSON, _ := json.MarshalIndent(&claims, "", "    ")
			gosaml.Dump("token_id_token", plainJSON)
			gosaml.Dump("token", res)
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(res))
		return nil

	}
	return errors.New("no grant_type parameter found")
}

func OIDCUserinfoService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	r.ParseForm()
	if authorisation := r.Header.Get("Authorization"); authorisation != "" {

		parts := strings.Split(authorisation, " ")
		if parts[0] != "Bearer" {
			return errors.New("no Bearer token found")
		}

		c, ok := claimsMap.Load(parts[1])
		if !ok {
			return errors.New("unknown accesstoken")
		}
		claims := c.(claimsInfo).claims
		//claims, err := decrypt(parts[1], "")
		//if err != nil {
		//    return err
		//}

		if gosaml.DebugSetting2(c.(claimsInfo).debug, "trace") == "1" {
			plainJSON, _ := json.MarshalIndent(&claims, "", "    ")
			gosaml.Dump("userinfo_id_token", plainJSON)
		}

		//if int64(claims["iat"].(float64))+60 < time.Now().Unix() { // remember if via json it is float64
		if claims["iat"].(int64)+60 < time.Now().Unix() {
			return errors.New("token timeout")
		}

		spMd, _, err := gosaml.FindInMetadataSets(intExtSP, c.(claimsInfo).client_id)
		if err != nil {
			return err
		}

		response_alg := spMd.Query1(nil, xprefix+"OIDC/wayf:userinfo_signed_response_alg")

		if response_alg == "false" {
			plain, err := json.Marshal(&claims)
			if err != nil {
				return err
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(plain))
		} else {
			signed, err := signClaims(claims)
			if err != nil {
				return err
			}
			w.Header().Set("Content-Type", "application/jwt")
			w.Write([]byte(signed))
		}
		return nil
	}
	return errors.New("no Authorization header found")
}

func signClaims(claims map[string]any) (signed string, err error) {
	hubBirkIDPMd, err := md.Hub.MDQ(config.HubEntityID)
	if err != nil {
		return
	}

	privatekey, _, kid, err := gosaml.GetPrivateKeyByMethod(hubBirkIDPMd, "md:IDPSSODescriptor"+gosaml.SigningCertQuery, x509.RSA)
	if err != nil {
		return
	}

	plainJSON, err := json.Marshal(&claims)
	if err != nil {
		return
	}

	signed, _, err = gosaml.JwtSign(plainJSON, privatekey, "RS256", kid)
	return
}

func getAcceptHeaderItems(r *http.Request, header string, fallbacks []string) (res []string) {
	items := acceptHeader.FindAllStringSubmatch(r.Header.Get(header), -1)
	for _, item := range items {
		res = append(res, item[1])
	}
	res = append(res, fallbacks...)
	return
}

func getFirstByAttribute(xp *goxml.Xp, templ string, vals []string) (res string) {
	for _, v := range vals {
		xpath := strings.Replace(templ, "$", strconv.Quote(v), 1)
		if res = xp.Query1(nil, xpath); res != "" {
			return
		}
	}
	return
}

func sendRequestToIDP(w http.ResponseWriter, r *http.Request, request, spMd, hubKribSPMd, realIDPMd, virtualIDPMd *goxml.Xp, relayState, prefix, altAcs, domain string, spIndex, hubBirkIndex uint8, idPList []string) (err error) {
	// why not use orig request?
	virtualIDPID := virtualIDPMd.Query1(nil, "./@entityID") // wayf might return domain or hash ...
	wantRequesterID := realIDPMd.QueryXMLBool(nil, xprefix+`wantRequesterID`) || gosaml.DebugSetting(r, "wantRequesterID") != ""
	newrequest, sRequest, err := gosaml.NewAuthnRequest(request, hubKribSPMd, realIDPMd, virtualIDPID, idPList, altAcs, wantRequesterID, spIndex, hubBirkIndex)
	if err != nil {
		return
	}

	if request != nil && request.QueryXMLBool(nil, `//*[@Name="nemlogin"]/saml:AttributeValue`) {
		providerName := getFirstByAttribute(spMd, "md:SPSSODescriptor//mdui:DisplayName[@xml:lang=$]", getAcceptHeaderItems(r, "Accept-Language", []string{"en", "da"}))
		newrequest.QueryDashP(nil, "./@ProviderName", base64.StdEncoding.EncodeToString([]byte(providerName)), nil)

		if tmp := hubKribSPMd.Query1(nil, `//wayf:map2IdP`); tmp != "" { // let the SP choose which SSOIndex to use
			dest := realIDPMd.Query1(nil, `./md:IDPSSODescriptor/md:SingleSignOnService[`+tmp+`][@Binding="`+gosaml.REDIRECT+`"]/@Location`)
			newrequest.QueryDashP(nil, "./@Destination", dest, nil)
		}
		// Nemlog-in SPs announce their ability to do SLO by providing SingleLogoutService(s)
		if spMd.QueryNumber(nil, "count(./md:SPSSODescriptor/md:SingleLogoutService)") == 0 {
			newrequest.QueryDashP(nil, "./@ForceAuthn", "true", nil)
			// before, _ := newrequest.Query(nil, "./samlp:NameIDPolicy")[0].NextSibling() // NameIDPolicy always there, NextSibling returns nil of none, and then Conditions after NameIDIPolicy anyway
			// newrequest.QueryDashP(nil, "saml:Conditions/saml:OneTimeUse", "", before)
		}
	}

	if virtualIDPMd.QueryXMLBool(nil, xprefix+`forceAuthn`) && spMd.QueryXMLBool(nil, xprefix+`forceAuthn`) {
		newrequest.QueryDashP(nil, "./@ForceAuthn", "true", nil)
	}

	var privatekey crypto.PrivateKey
	if realIDPMd.QueryXMLBool(nil, `./md:IDPSSODescriptor/@WantAuthnRequestsSigned`) || hubKribSPMd.QueryXMLBool(nil, `./md:SPSSODescriptor/@AuthnRequestsSigned`) || gosaml.DebugSetting(r, "idpSigAlg") != "" {
		privatekey, _, err = gosaml.GetPrivateKey(hubKribSPMd, "md:SPSSODescriptor"+gosaml.SigningCertQuery)
		if err != nil {
			return
		}
	}

	legacyLog("", "SAML2.0 - IDP.SSOService: Incomming Authentication request:", request.Query1(nil, "./saml:Issuer"), virtualIDPID, "")
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

	gosaml.DumpFileIfTracing(r, newrequest)
	gosaml.NemLog.Log(newrequest, realIDPMd, request.Query1(nil, "@ID"))

	flow := realIDPMd.Query1(nil, xprefix+`response_type`)
	if f := gosaml.DebugSetting(r, "oidcflow"); f != "" {
		flow = f
	}
	var u *url.URL
	if flow != "" {
		u, err = gosaml.SAMLRequest2OIDCRequest(newrequest, relayState, flow, realIDPMd)
	} else {
		u, err = gosaml.SAMLRequest2URL(newrequest, relayState, privatekey, gosaml.DebugSettingWithDefault(r, "idpSigAlg", config.DefaultCryptoMethod))
	}
	if err != nil {
		return
	}
	sRequest.IDPProtocol = flow
	buf := sRequest.Marshal()
	session.Set(w, r, prefix+gosaml.IDHash(newrequest.Query1(nil, "./@ID")), domain, buf, authnRequestCookie, authnRequestTTL)
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func getOriginalRequest(w http.ResponseWriter, r *http.Request, response *goxml.Xp, issuerMdSets, destinationMdSets gosaml.MdSets, prefix string) (spMd, hubBirkIDPMd, virtualIDPMd, request *goxml.Xp, sRequest gosaml.SamlRequest, err error) {
	gosaml.DumpFileIfTracing(r, response)
	inResponseTo := response.Query1(nil, "./@InResponseTo")
	tmpID, err := session.GetDel(w, r, prefix+gosaml.IDHash(inResponseTo), config.Domain, authnRequestCookie)
	//tmpID, err := authnRequestCookie.SpcDecode("id", inResponseTo[1:], gosaml.SRequestPrefixLength) // skip _
	if err != nil {
		return
	}
	sRequest.Unmarshal(tmpID)

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

	if virtualIDPMd, err = md.ExternalIDP.MDQ(sRequest.VirtualIDP); err != nil {
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

	acs := spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@index=`+strconv.Quote(sRequest.AssertionConsumerIndex)+`]/@Location`)
	binding := spMd.Query1(nil, `./md:SPSSODescriptor/md:AssertionConsumerService[@index=`+strconv.Quote(sRequest.AssertionConsumerIndex)+`]/@Binding`)
	request.QueryDashP(nil, "./@AssertionConsumerServiceURL", acs, nil)
	request.QueryDashP(nil, "./@ProtocolBinding", binding, nil)
	request.QueryDashP(nil, "./saml:Issuer", sRequest.SP, nil)
	request.QueryDashP(nil, "./samlp:NameIDPolicy/@Format", gosaml.NameIDList[sRequest.NameIDFormat], nil)
	return
}

// ACSService handles all the stuff related to receiving response and attribute handling
func ACSService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	hubMd, _ := md.Hub.MDQ(config.HubEntityID)
	hubIdpCerts := hubMd.QueryMulti(nil, "md:IDPSSODescriptor"+gosaml.SigningCertQuery)
	response, idpMd, hubKribSpMd, relayState, _, hubKribSpIndex, err := gosaml.ReceiveSAMLResponse(r, intExtIDP, hubExtSP, "https://"+r.Host+r.URL.Path, hubIdpCerts)
	if err != nil {
		return
	}

	spMd, hubBirkIDPMd, virtualIDPMd, request, sRequest, err := getOriginalRequest(w, r, response, intExtSP, hubExtIDP, ssoCookieName)
	if err != nil {
		return
	}

	// check for protocol / flow
	if sRequest.IDPProtocol != response.Query1(nil, "@Flow") {
		return fmt.Errorf("protocol mismatch")
	}

	// check for ID Spoofing attempt - HackmanIT report 2023
	if gosaml.IDHash(idpMd.Query1(nil, "@entityID")) != sRequest.IDP {
		return fmt.Errorf("IdP mismatch")
	}

	origRequestID := request.Query1(nil, "@ID")
	gosaml.NemLog.Log(response, idpMd, origRequestID)

	if err = gosaml.CheckDigestAndSignatureAlgorithms(response); err != nil {
		return
	}

	signingMethod := config.DefaultCryptoMethod
	signingMethods := spMd.QueryMulti(nil, "./md:SPSSODescriptor/md:Extensions/alg:SigningMethod/@Algorithm")
	signingMethods = append(signingMethods, spMd.QueryMulti(nil, "./md:Extensions/alg:SigningMethod/@Algorithm")...)
found:
	for _, preferredMethod := range signingMethods {
		for signingMethod, _ = range config.CryptoMethods {
			if preferredMethod == config.CryptoMethods[signingMethod].SigningMethod {
				break found
			}
		}
	}

	signingMethod = gosaml.DebugSettingWithDefault(r, "spSigAlg", signingMethod)

	var newresponse *goxml.Xp
	var ard AttributeReleaseData
	doEncrypt := false
	var id_token map[string]interface{}
	elementToSign := config.ElementToSign
	signingType := gosaml.SAMLSign

	if response.Query1(nil, `samlp:Status/samlp:StatusCode/@Value`) == "urn:oasis:names:tc:SAML:2.0:status:Success" {
		audience := response.Query1(nil, "./saml:Assertion/saml:Conditions/saml:AudienceRestriction/saml:Audience")
		expectedAudience := sRequest.WAYFSP
		if gosaml.IDHash(audience) != expectedAudience {
			spMd, _, err = gosaml.FindInMetadataSets(hubExtSP, expectedAudience)
			if err != nil {
				return
			}
			return fmt.Errorf(`Audience mismatch "%s" != "%s"`, audience, spMd.Query1(nil, "@entityID"))
		}

		if err = Attributesc14n(request, response, virtualIDPMd, spMd); err != nil {
			return
		}

		shibscope := idpMd.Query1(nil, "/md:EntityDescriptor/md:IDPSSODescriptor/md:Extensions/shibmd:Scope")
		attributeStatement := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement[1]`)[0] // Attributes14n would have failed if it was empty ...
		for _, attribute := range config.AttributeLogList {
			values := response.QueryMulti(attributeStatement, "saml:Attribute[@Name='"+attribute+"']/saml:AttributeValue")
			sort.Strings(values)
			log.Println("attrlog:", shibscope, attribute, strings.Join(values, ","))
		}

		if hubKribSpIndex == 0 { // to the hub itself
			ard, err = wayfACSServiceHandler(idpMd, virtualIDPMd, hubMd, spMd, request, response, sRequest.HubBirkIndex == 1, r)
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

		ard.Values, ard.Hash, err = CopyAttributes(r, response, newresponse, virtualIDPMd, spMd)
		if err != nil {
			return
		}

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

		// Fix up timings if the SP has asked for it
		ad, err := time.ParseDuration(spMd.Query1(nil, xprefix+"assertionDuration"))
		if err == nil {
			issueInstant, _ := time.Parse(gosaml.XsDateTime, newresponse.Query1(nil, "./saml:Assertion/@IssueInstant"))
			newresponse.QueryDashP(nil, "./saml:Assertion/saml:Conditions/@NotOnOrAfter", issueInstant.Add(ad).Format(gosaml.XsDateTime), nil)
		}

		// record SLO info before converting SAML2 response to other formats
		SLOInfoHandler(w, r, response, idpMd, hubKribSpMd, newresponse, spMd, gosaml.SPRole, sRequest.Protocol)

		if spMd.QueryXMLBool(nil, xprefix+"saml20.sign.response") {
			elementToSign = "/samlp:Response"
		}

		// Replace hub issuer if sp wants special hub issuer value and response is sent by the hub (i.e. non-birk):

		if sRequest.HubBirkIndex == 0 {
			if setHubIdPIssuerTo := spMd.Query1(nil, xprefix+"setHubIdPIssuerTo"); setHubIdPIssuerTo != "" {
				newresponse.QueryDashP(nil, "./saml:Issuer", setHubIdPIssuerTo, nil)
				newresponse.QueryDashP(nil, "/saml:Assertion/saml:Issuer", setHubIdPIssuerTo, nil)
			}
		}

		id_token = gosaml.Saml2map(newresponse) // last chance to use a non-encrypted and non-saml1 newresponse

		// We don't mark ws-fed RPs in md - let the request decide - use the same attributenameformat for all attributes
		if sRequest.Protocol == "wsfed" {
			newresponse = gosaml.NewWsFedResponse(hubBirkIDPMd, spMd, newresponse)
			signingType = gosaml.WSFedSign
			elementToSign = "./t:RequestedSecurityToken/saml1:Assertion"
		}

		if gosaml.DebugSetting(r, "timingError") == "1" {
			fakeTime := time.Now().UTC().Add(-time.Hour).Format(gosaml.XsDateTime)
			newresponse.QueryDashP(nil, "./saml:Assertion/saml:Conditions/@NotOnOrAfter", fakeTime, nil)
		}

		if elementToSign != "/samlp:Response" {
			err = gosaml.SignResponse(newresponse, elementToSign, hubBirkIDPMd, signingMethod, signingType)
			if err != nil {
				return err
			}
		}

		if gosaml.DebugSetting(r, "signingError") == "1" {
			newresponse.QueryDashP(nil, `./saml:Assertion/@ID`, newresponse.Query1(nil, `./saml:Assertion/@ID`)+"1", nil)
		}

		doEncrypt = spMd.QueryXMLBool(nil, xprefix+"assertion.encryption") ||
			hubKribSpMd.QueryXMLBool(nil, xprefix+"assertion.encryption") ||
			gosaml.DebugSetting(r, "encryptAssertion") == "1"
		// spMd.Query1(nil, "./md:SPSSODescriptor/md:KeyDescriptor/md:EncryptionMethod/@Algorithm") != ""
	} else {
		newresponse = gosaml.NewErrorResponse(hubBirkIDPMd, spMd, request, response)

		err = gosaml.SignResponse(newresponse, "/samlp:Response", hubBirkIDPMd, signingMethod, gosaml.SAMLSign)
		if err != nil {
			return
		}
		ard = AttributeReleaseData{BypassConfirmation: true}
	}
	gosaml.NemLog.Log(newresponse, idpMd, origRequestID)

	// when consent as a service is ready - we will post to that
	// acs := newresponse.Query1(nil, "@Destination")

	ardjson, err := json.Marshal(ard)
	if err != nil {
		return goxml.Wrap(err)
	}

	gosaml.DumpFileIfTracing(r, newresponse)

	data := gosaml.Formdata{
		Protocol:   sRequest.Protocol,
		Acs:        request.Query1(nil, "./@AssertionConsumerServiceURL"),
		SigAlg:     config.CryptoMethods[signingMethod].SigningMethod,
		RelayState: relayState,
		Ard:        template.JS(ardjson),
		Method:     "post",
	}

	var signature []byte

	gosaml.DumpFileIfTracing(r, newresponse)
	multi := spMd.QueryMultiMulti(nil, "./md:SPSSODescriptor"+gosaml.EncryptionCertQuery, []string{".", "../../../md:EncryptionMethod/@Algorithm"})
	_, _, pubs, _ := gosaml.PublicKeyInfoByMethod(goxml.Flatten(multi[0]), x509.RSA)

	if doEncrypt {
		assertion := newresponse.Query(nil, "saml:Assertion[1]")[0]
		newresponse.Encrypt(assertion, "saml:EncryptedAssertion", pubs[0].(*rsa.PublicKey), multi[1][0]) // multi[1] is a list of list of Algos for each key
	}

	if elementToSign == "/samlp:Response" {
		err = gosaml.SignResponse(newresponse, elementToSign, hubBirkIDPMd, signingMethod, signingType)
		if err != nil {
			return err
		}
	}

	responseXML := newresponse.Dump()

	switch sRequest.Protocol {
	default:
		data.Samlresponse = base64.StdEncoding.EncodeToString(responseXML)
	case "wsfed":
		data.Samlresponse = string(responseXML)
	case "code":
		if sRequest.Nonce != "" {
			id_token["nonce"] = sRequest.Nonce
		}
		id_token["@codeChallenge"] = sRequest.CodeChallenge
		debug := ""
		if cookie, err := r.Cookie("debug"); err == nil {
			debug = cookie.Value
		}
		data.Code = hostName + rand.Text()
		fmt.Println("code:", spMd.Query1(nil, "@entityID"), data.Code)
		claimsMap.Store(data.Code, claimsInfo{claims: id_token, debug: debug, eol: time.Now().Add(codeTTL * time.Second)})
		// data.Code, err = encrypt(id_token, "")
		// if err != nil {
		//     return
		// }
		if sRequest.OIDCBinding == gosaml.OIDCQuery {
			data.Method = "get"
		}
	case "id_token":
		if sRequest.Nonce != "" {
			id_token["nonce"] = sRequest.Nonce
		}
		json, err := json.Marshal(&id_token)
		if err != nil {
			return err
		}

		privatekey, _, kid, err := gosaml.GetPrivateKeyByMethod(hubBirkIDPMd, "md:IDPSSODescriptor"+gosaml.SigningCertQuery, x509.RSA)
		if err != nil {
			return err
		}
		signed_id_token, _, err := gosaml.JwtSign(json, privatekey, "RS256", kid)
		if err != nil {
			return err
		}
		data.Id_token = signed_id_token

		if doEncrypt {
			jwe, _ := goxml.Jwe([]byte(signed_id_token), pubs[0].(*rsa.PublicKey), multi[1][0])
			data.Id_token = jwe
		}

		data.Acs = newresponse.Query1(nil, "@Destination")
	}

	data.Signature = base64.RawURLEncoding.EncodeToString(signature)
	return tmpl.ExecuteTemplate(w, "attributeReleaseForm", data)
}

func encrypt(plain map[string]any, label string) (res string, err error) {
	plainJSON, err := json.Marshal(&plain)
	if err != nil {
		return
	}
	compressedJSON := gosaml.Deflate([]byte(plainJSON))
	_, ciphertext, iv, at, err := goxml.EncryptAESGCM([]byte(compressedJSON), config.AuthzCodeEncKey, []byte(label), 0)
	res = base64.RawURLEncoding.EncodeToString(append(append(iv, ciphertext...), at...))
	return
}

func decrypt(ciphertext string, label string) (claims map[string]any, err error) {
	cipherslice, err := base64.RawURLEncoding.DecodeString(ciphertext)
	if err != nil {
		return
	}
	compressedJSON, err := goxml.DecryptAESGCM(config.AuthzCodeEncKey, cipherslice, []byte(label))
	if err != nil {
		return
	}
	plainJSON := gosaml.Inflate(compressedJSON)
	claims = map[string]any{}
	err = json.Unmarshal([]byte(plainJSON), &claims)
	return
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
	hubMd, _ := md.Hub.MDQ(config.HubEntityID)
	return gosaml.Jwt2saml(w, r, md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP, RequestHandler, hubMd)
}

func saml2jwt(w http.ResponseWriter, r *http.Request) (err error) {
	return gosaml.Saml2jwt(w, r, md.Hub, md.Internal, md.ExternalIDP, md.ExternalSP, RequestHandler, config.HubEntityID)
}

// SLOService refers to single logout service. Takes request and issuer and destination metadata sets, role refers to if it as IDP or SP.
func SLOService(w http.ResponseWriter, r *http.Request, issuerMdSet, destinationMdSet gosaml.Md, finalIssuerMdSets, finalDestinationMdSets []gosaml.Md, role int, tag string) (err error) {
	defer r.Body.Close()
	r.ParseForm()
	request, issuerMd, destination, relayState, _, _, err := gosaml.ReceiveLogoutMessage(r, gosaml.MdSets{issuerMdSet}, gosaml.MdSets{destinationMdSet}, role)
	if err != nil {
		return err
	}
	gosaml.NemLog.Log(request, issuerMd, "")

	var issMD, destMD, msg *goxml.Xp
	var binding string
	_, sloinfo, ok, sendResponse := SLOInfoHandler(w, r, request, nil, destination, request, nil, role, request.Query1(nil, "./samlp:Extensions/wayf:protocol"))
	if sloinfo == nil {
		return fmt.Errorf("No SLO info found")
	}

	if sendResponse && !ok {
		return fmt.Errorf("SLO failed")
	} else if sendResponse && sloinfo.Async {
		return fmt.Errorf("SLO completed")
	}
	iss, dest := sloinfo.IDP, sloinfo.SP
	if sloinfo.HubRole == gosaml.SPRole {
		dest, iss = iss, dest
	}
	issMD, _, err = gosaml.FindInMetadataSets(finalIssuerMdSets, iss)
	if err != nil {
		return err
	}
	destMD, _, err = gosaml.FindInMetadataSets(finalDestinationMdSets, dest)
	if err != nil {
		return err
	}

	if sendResponse {
		msg, binding, err = gosaml.NewLogoutResponse(issMD.Query1(nil, `./@entityID`), destMD, sloinfo.ID, uint8((sloinfo.HubRole+1)%2))
	} else {
		msg, binding, err = gosaml.NewLogoutRequest(destMD, sloinfo, issMD.Query1(nil, "@entityID"), false)
	}
	if err != nil {
		return err
	}

	if sloinfo.Protocol == "wsfed" {
		wa := "wsignout1.0"
		if sendResponse {
			wa = "wsignoutcleanup1.0"
		}
		q := url.Values{
			"wtrealm": {issMD.Query1(nil, `./@entityID`)},
			"wa":      {wa},
		}
		http.Redirect(w, r, msg.Query1(nil, "@Destination")+"?"+q.Encode(), http.StatusFound)
		return
	}

	//legacyStatLog("saml20-idp-SLO "+req[role], issuer.Query1(nil, "@entityID"), destination.Query1(nil, "@entityID"), sloinfo.NameID+fmt.Sprintf(" async:%t", async))

	privatekey, _, err := gosaml.GetPrivateKey(issMD, gosaml.Roles[sloinfo.HubRole]+gosaml.SigningCertQuery)
	if err != nil {
		return err
	}

	algo := config.DefaultCryptoMethod
	algo = gosaml.DebugSettingWithDefault(r, "idpSigAlg", algo)

	gosaml.NemLog.Log(msg, destMD, "")

	switch binding {
	case gosaml.REDIRECT:
		u, err := gosaml.SAMLRequest2URL(msg, relayState, privatekey, algo)
		if err != nil {
			return err
		}
		http.Redirect(w, r, u.String(), http.StatusFound)
	case gosaml.POST:
		err = gosaml.SignResponse(msg, "/*[1]", issMD, algo, gosaml.SAMLSign)
		if err != nil {
			return err
		}
		data := gosaml.Formdata{Acs: msg.Query1(nil, "./@Destination"), Samlresponse: base64.StdEncoding.EncodeToString(msg.Dump()), RelayState: relayState}
		return tmpl.ExecuteTemplate(w, "postForm", data)
	}
	return
}

// SLOInfoHandler Saves or retrieves the SLO info relevant to the contents of the samlMessage
// For now uses cookies to keep the SLOInfo
func SLOInfoHandler(w http.ResponseWriter, r *http.Request, samlIn, idpMd, inMd, samlOut, outMd *goxml.Xp, role int, protocol string) (sil *gosaml.SLOInfoList, sloinfo *gosaml.SLOInfo, ok, sendResponse bool) {
	sil = &gosaml.SLOInfoList{}
	data, _ := session.Get(w, r, sloCookieName, sloInfoCookie)
	sil.Unmarshal(data)

	switch samlIn.QueryString(nil, "local-name(/*)") {
	case "LogoutRequest":
		sloinfo = sil.LogoutRequest(samlIn, inMd.Query1(nil, "@entityID"), uint8(role), protocol)
		sendResponse = sloinfo.NameID == ""
	case "LogoutResponse":
		sloinfo, ok = sil.LogoutResponse(samlIn)
		sendResponse = sloinfo.NameID == ""
	case "Response":
		sil.Response(samlIn, inMd.Query1(nil, "@entityID"), idpMd.Query1(nil, "./md:IDPSSODescriptor/md:SingleLogoutService/@Location") != "", gosaml.SPRole, "") // newer non-saml coming in from our IDPS
		sil.Response(samlOut, outMd.Query1(nil, "@entityID"), outMd.Query1(nil, "./md:SPSSODescriptor/md:SingleLogoutService/@Location") != "", gosaml.IDPRole, protocol)
	}
	if sendResponse { // ready to send response - clear cookie
		session.Del(w, r, sloCookieName, config.Domain, sloInfoCookie)
	} else {
		bytes := sil.Marshal()
		session.Set(w, r, sloCookieName, config.Domain, bytes, sloInfoCookie, sloInfoTTL)
	}
	return
}

// MDQWeb - thin MDQ web layer on top of lmdq
func MDQWeb(w http.ResponseWriter, r *http.Request) (err error) {
	if origin, ok := r.Header["Origin"]; ok {
		w.Header().Add("Access-Control-Allow-Origin", origin[0])
		w.Header().Add("Access-Control-Allow-Credentials", "true")
	}

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

// rendezvous

func cleanUp(sm *sync.Map) {
	ticker := time.NewTicker(codeTTL * time.Second)
	go func() {
		for {
			<-ticker.C
			sm.Range(func(k, v any) bool {
				if v.(claimsInfo).eol.Before(time.Now()) {
					sm.Delete(k)
				}
				return true
			})
		}
	}()
}
