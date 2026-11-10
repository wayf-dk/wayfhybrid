package config

//go:generate go run env/env.go

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/nacl/secretbox"
)

type (
	MdDb struct {
		Dsn, Table, TableRev, Short, Rev, Mdq string
	}

	MdFeed struct {
		Path, URL          string
		InsecureSkipVerify bool
	}

	GoElevenSlot struct {
		Keypath, Site string
		Sessions      uint
	}

	GoElevenConfig struct {
		Intf, AllowedIP, HsmLib, SlotPassword, Testkey string
		Keys                                           []string
		Slots                                          map[string]GoElevenSlot
	}

	CryptoMethod struct {
		DigestMethod, SigningMethod string
		Hash                        crypto.Hash
		Type                        x509.PublicKeyAlgorithm
		DerPrefix                   string
	}
)

const (
	OidcConfigurationService  = "wayf.wayf.dk/oidc/config/{homeorg}/"
	OidcConfigurationService2 = "/.well-known/openid-configuration"
	OidcJwkService            = "wayf.wayf.dk/oidc/wayf.jwk"
	SsoService                = "wayf.wayf.dk/saml2/idp/SSOService2.php"
	SsoService2               = "wayf.wayf.dk/saml2/sso"
	SsoService3               = "wayf.wayf.dk/saml2/sso3"
	Acs                       = "wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"
	Acs2                      = "wayf.wayf.dk/saml2/acs"
	NemloginAcs               = "nemlogin.wayf.dk/module.php/saml/sp/saml2-acs.php/nemlogin.wayf.dk"
	NemloginAcs3              = "nemlogin.wayf.dk/acs"
	Spslo                     = "wayf.wayf.dk/module.php/saml/sp/saml2-logout.php/wayf.wayf.dk"
	Spslo2                    = "wayf.wayf.dk/saml2/spslo"
	Spslo3                    = "wayf.wayf.dk/saml2/spslo3"
	Vvpmss                    = "wayf.wayf.dk/vvpmss"
	Saml2jwt                  = "wayf.wayf.dk/saml2jwt"
	Saml3jwt                  = "wayf.wayf.dk/saml3jwt"
	Jwt2saml                  = "wayf.wayf.dk/jwt2saml"
	MDQ                       = "wayf.wayf.dk/MDQ/"
	Nemloginslo               = "nemlogin.wayf.dk/module.php/saml/sp/saml2-logout.php/nemlogin.wayf.dk"
	Idpslo                    = "wayf.wayf.dk/saml2/idp/SingleLogoutService.php"
	Idpslo2                   = "wayf.wayf.dk/saml2/idpslo"
	Idpslo3                   = "wayf.wayf.dk/saml2/idpslo3"
	Birkslo                   = "birk.wayf.dk/SLO/"
	Kribslo                   = "krib.wayf.dk/SLO/"
	Birk                      = "birk.wayf.dk/"
	Krib                      = "krib.wayf.dk/"
	OIDCAuth                  = "wayf.wayf.dk/oidc/auth"
	OIDCToken                 = "wayf.wayf.dk/oidc/token"
	OIDCUserinfo              = "wayf.wayf.dk/oidc/userinfo"
	Dsbackend                 = "wayf.wayf.dk/dsbackend"
	Dstiming                  = "wayf.wayf.dk/dstiming"
	Public                    = "/"

	TestSP2    = "wayfsp2.wayf.dk"
	TestSP2Acs = "wayfsp2.wayf.dk/ACS"
	TestSP2Slo = "wayfsp2.wayf.dk/SLO"
	TestSP     = "wayfsp.wayf.dk"
	TestSPAcs  = "wayfsp.wayf.dk/ACS"
	TestSPSlo  = "wayfsp.wayf.dk/SLO"

	DiscoveryService  = "https://wayf.wayf.dk/ds/?"
	Domain            = "wayf.dk"
	HubEntityID       = "https://wayf.wayf.dk"
	ConsentAsAService = ""
	HsmLib            = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
	//  HsmLib                = "/usr/safenet/lunaclient/libs/64/libCryptoki2.so" // arm64 minimal client
	EnableSimpleSign      = false
	DefaultCryptoMethod   = "rsa256"
	NemlogPublic          = "Acp31ZHEjvIGAEGMvEh1rYbotSKh6lTqiRVYY2MqB0c="
	NemLogMaxSize         = 1 << (26) // 64MB
	NemLogSlotGranularity = 14400     // 4 hours
	NemLogDirectory       = "nemlog"
	NemLogNameFormat      = NemLogDirectory + "/nemlog-%s-%s"
	NemLoginSP            = "b4f133c080"                     // hex(sha1("https://saml.nemlog-in3.wayf.dk"))[:10]
	EWCredential          = "wayf.wayf.dk/wallet/wallet-issuer/credential-offer" // edu wallet credential
	EWOffer               = "wayf.wayf.dk/wallet/wallet-issuer/offers/{offerId}" // edu wallet fetch credentia
	EWCredentialIssuerMetaData = "wayf.wayf.dk/.well-known/openid-credential_issuer"
	EWOAuthAuthorizationServer = "wayf.wayf.dk/.well-known/oauth-authorization-server"
	WalletIssuerEntityID = "https://wayf.wayf.dk/wallet/wallet-issuer"
)

var (
	//go:embed templates/hybrid.tmpl
	HybridTmpl string

	//go:embed templates/env.json
	envJson []byte

	//go:embed public/*
	publicFiles embed.FS

	//go:embed certs/*
	privateKeys embed.FS

	//go:embed certs/2d179672c02a4787bac23df0a0e9e6148214f49a.crt
	MetadataCert string

	//go:embed certs/9d92d3d6c860cb3ecdfddfe18a3552d7e9fc884d.crt
	TestCert3K string

	//go:embed certs/testcert.crt
	TestCert string

	//go:embed certs/ed25519.crt
	Ed25519Cert string

	//go:embed gitCommit
	GitCommit string

	PublicFiles fs.FS
	PrivateKeys fs.FS

	MdqIntf  = "127.0.0.1:9999"
	MdDbPath = "/opt/wayf/hybrid-metadata.mddb"
	MdDbDsn  = MdDbPath + "?mode=ro"

	MetadataKey = `2d179672c02a4787bac23df0a0e9e6148214f49a`

	DiscoMetadata   = MdDbDsn
	DiscoSPMetadata = MdDbDsn
	NotFoundRoutes  = []string{} // "/favicon.ico"}
	envMap          map[string]string

	Hub         = MdDb{Dsn: MdDbDsn, Table: "HYBRID_HUB", TableRev: "HYBRID_HUB", Short: "hub", Rev: "hub"}
	Internal    = MdDb{Dsn: MdDbDsn, Table: "HYBRID_INTERNAL", TableRev: "HYBRID_INTERNAL", Short: "int", Rev: "int"}
	ExternalIDP = MdDb{Dsn: MdDbDsn, Table: "HYBRID_EXTERNAL_IDP", TableRev: "HYBRID_EXTERNAL_SP", Short: "idp", Rev: "sp"}
	ExternalSP  = MdDb{Dsn: MdDbDsn, Table: "HYBRID_EXTERNAL_SP", TableRev: "HYBRID_EXTERNAL_IDP", Short: "sp", Rev: "idp"}

	CryptoMethods = map[string]CryptoMethod{
		"obsolete-sha1": {"http://www.w3.org/2000/09/xmldsig#sha1", "", crypto.SHA1, x509.UnknownPublicKeyAlgorithm, ""},
		"rsa256":        {"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", crypto.SHA256, x509.RSA, "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"},
		"rsa384":        {"http://www.w3.org/2001/04/xmldsig-more#sha384", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", crypto.SHA384, x509.RSA, "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"},
		"rsa512":        {"http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", crypto.SHA512, x509.RSA, "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"},
		//"ecdsa256": {"http://www.w3.org/2001/04/xmlenc#sha256", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", crypto.SHA256, x509.ECDSA, ""},
		"ed25519": {"http://www.w3.org/2001/04/xmlenc#sha512", "http://www.w3.org/2001/04/xmldsig-more#ed25519ph", crypto.SHA512, x509.Ed25519, ""},
	}

	EncryptionAlgorithmsDefaults = []string{"http://www.w3.org/2009/xmlenc11#aes256-gcm", "http://www.w3.org/2009/xmlenc11#rsa-oaep"}
	//EncryptionAlgorithmsDefaults = []string{"http://www.w3.org/2001/04/xmlenc#aes256-cbc", "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"}

	MetadataFeeds []MdFeed
	ElementToSign = "/samlp:Response/saml:Assertion"

	BypassMdUpdate    = flag.Bool("nomd", false, "bypass MD update at start")
	Dev               = flag.Bool("dev", false, "run in dev - mode i.e. with testcerts")
	DevMd             = flag.Bool("devmd", false, "Use development metadata")
	Test              = flag.Bool("tst", false, "run wayffunctionaltests")
	Hybrid            = flag.String("hybrid", "", "which backend to test directly")
	HybridBackend     = flag.String("hybridbackend", "", "which backend to test by setting frontend cookie")
	Env               = flag.String("env", "prod", "environment")
	Trace             = flag.Bool("trace", false, "trace the request/response flow")
	Logxml            = flag.Bool("logxml", false, "dump requests/responses in xml")
	Verbose           = flag.Bool("v", false, "show stdout from hybrid when testing")
	ShowStdout        = flag.Bool("vv", false, "show stdout from tests")
	forceMetadataMods = flag.Bool("metadatamods", false, "use metadata with test certs")
	MetadataMods      bool
	Prod              bool

	GoElevenHybrid = GoElevenConfig{
		HsmLib: HsmLib,
		Slots: map[string]GoElevenSlot{
			"wayfha":        {"/wayf/", "ha", 64},
			"1476113407734": {"", "ore", 1},
			"1455489273185": {"", "uni", 1},
			// 			"1797042450157": {"", "riso", 1},
		},
		Testkey: "wayf.2016.key",
	}

	GoElevenPHPH = GoElevenConfig{
		Intf:      "localhost:8082",
		AllowedIP: "127.0.0.1",
		HsmLib:    HsmLib,
		Slots: map[string]GoElevenSlot{
			"wayfha":        {"/wayf/", "ha", 64},
			"1476113407734": {"", "ore", 1},
			"1455489273185": {"", "uni", 1}},
		Testkey: "wayf.3K.2025.metadata.pri",
	}

	pw, Intf, EptidSalt, SaltForHashedEppn, ThisIsNotAValidIdpKey, SecureCookieHashKey string
	TESTSSHCAKey                                                                       string
	ServerCrt, ServerKey                                                               []byte
	RemoteTest                                                                         bool
	AuthzCodeEncKey                                                                    []byte

	NemLoginRelated = map[string]bool{"https://saml.nemlog-in.dk": true}

	IdP2SPMappping = map[string]string{
		"http://sts.ait.dtu.dk/adfs/services/trust": "https://share.dtu.dk",
		"https://kemibrug.dk":                       "https://share.dtu.dk",
	}

	AttributeLogList = []string{"eduPersonAffiliation", "eduPersonEntitlement", "eduPersonPrimaryAffiliation", "eduPersonScopedAffiliation", "eduPersonAssurance"}

	StrictScopedAttributes = []string{
		"eduPersonPrincipalName", "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
		"eduPersonPrincipalNamePrior", "urn:oid:1.3.6.1.4.1.5923.1.1.1.12",
		"eduPersonUniqueId", "urn:oid:1.3.6.1.4.1.5923.1.1.1.13",
		"pairwise-id", "urn:oasis:names:tc:SAML:attribute:pairwise-id",
		"subject-id", "urn:oasis:names:tc:SAML:attribute:subject-id",
	}

	LaxScopedAttributes = []string{
		"eduPersonScopedAffiliation", "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
	}

	Logger = log.New(os.Stderr, "", log.LstdFlags)

	TestCerts = []string{TestCert3K, TestCert, Ed25519Cert} // last becomes first

	KeyNames = []string{
		"2079f35b3b61c9fcf9470bad4ed0ad3ce4dde5bc", // wayf.2016.key
		"e8a1a239e253f4efbcb6616e39bbfbbb23303921", // wayf.3K.2025.signing
	}

	KeySelectionList = []string{
		"https://" + SsoService3,
		"https://" + Birk + "birk3/",
		"https://" + Birk + "SLO/birk3/",
		"https://" + OIDCAuth,
		"https://" + Spslo3,
		"https://" + Idpslo3,
	}

	UseMDkeyMap = map[string]bool{
		NemLoginSP: true,
	}

	BypassMdUpdateList = []string{"qa-03", "xtest-arken"}

	MDQRmCertByName = []string{
		"2079f35b3b61c9fcf9470bad4ed0ad3ce4dde5bc",
	}

	MDQ2KLocations = []string{
		"https://wayf.wayf.dk/saml2/idp/SSOService2.php",
		"https://wayf.wayf.dk/module.php/saml/sp/saml2-logout.php/wayf.wayf.dk",
		"https://wayf.wayf.dk/saml2/idp/SingleLogoutService.php",
		"https://birk.wayf.dk/birk.php/",
		"https://birk.wayf.dk/SLO/birk.php/",
	}
)

func Init() {
	flag.Parse()
	pw, _ = os.LookupEnv("pw")

	err := os.Mkdir(NemLogDirectory, 0750)
	if err != nil && !os.IsExist(err) {
		log.Fatal(err)
	}

	CryptoMethods["sha256"] = CryptoMethods["rsa256"]
	CryptoMethods["sha384"] = CryptoMethods["rsa384"]
	CryptoMethods["sha512"] = CryptoMethods["rsa512"]

	CryptoMethods[CryptoMethods["obsolete-sha1"].DigestMethod] = CryptoMethods["obsolete-sha1"]
	CryptoMethods[CryptoMethods["sha256"].DigestMethod] = CryptoMethods["sha256"]

	PrivateKeys, _ = fs.Sub(privateKeys, "certs")
	PublicFiles, _ = fs.Sub(publicFiles, "public")

	ServerCrt, _ = fs.ReadFile(PrivateKeys, "localhost.crt")
	ServerKey, _ = fs.ReadFile(PrivateKeys, "localhost.key")

	ServerCrt = []byte(env("ServerCrt", string(ServerCrt)))
	ServerKey = []byte(env("ServerKey", string(ServerKey)))

	pemPrefix := []byte("-----")

	if !bytes.HasPrefix(ServerCrt, pemPrefix) {
		ServerCrt, _ = os.ReadFile(string(ServerCrt))
	}
	if !bytes.HasPrefix(ServerKey, pemPrefix) {
		ServerKey, _ = os.ReadFile(string(ServerKey))
	}

	Intf = env("Intf", "127.0.0.1:443")
	EptidSalt = env("EptidSalt", "")
	SaltForHashedEppn = env("SaltForHashedEppn", "")
	ThisIsNotAValidIdpKey = env("ThisIsNotAValidIdpKey", "")
	SecureCookieHashKey = env("SecureCookieHashKey", "")
	TESTSSHCAKey = env("TESTSSHCAKey", "")

	AuthzCodeEncKey, _ = hex.DecodeString(env("AuthzCodeEncKey", "0123456789012345678901234567890101234567890123456789012345678901"))

	RemoteTest = *Hybrid != "" || *HybridBackend != ""
	Prod = !(*Test || RemoteTest)

	MetadataMods = *Test || *Dev || *forceMetadataMods
	if MetadataMods {
		ThisIsNotAValidIdpKey = "" // just so we don't need to change the env vars
		KeyNames = []string{
			"e4bd771e63c84e1b9385eaea9ba7d90f05146c0d", // test cert
			"9d92d3d6c860cb3ecdfddfe18a3552d7e9fc884d", // 3ktest
			"814ebc248e71623a2ee8200e5b22f32f06d9d470", // ed25519
		}
		MetadataCert = TestCert3K
		MetadataKey = `9d92d3d6c860cb3ecdfddfe18a3552d7e9fc884d`
	}

	MetadataFeeds = []MdFeed{{Path: MdDbPath, URL: "https://phph.wayf.dk/md/hybrid-metadata.mddb"}}
	if *DevMd {
		MetadataFeeds = []MdFeed{{Path: MdDbPath, URL: "https://test-arken.test.lan/md/hybrid-metadata.mddb", InsecureSkipVerify: true}}
	}

	if *Test {
		Hub.Mdq = "http://127.0.0.1:9999/MDQ/hub/"
		Internal.Mdq = "http://127.0.0.1:9999/MDQ/int/"
		ExternalIDP.Mdq = "http://127.0.0.1:9999/MDQ/idp/"
		ExternalSP.Mdq = "http://127.0.0.1:9999/MDQ/sp/"
	}

	MdDbPath = env("MdDbPath", MdDbPath)
	MdDbDsn = MdDbPath + "?mode=ro"

	DiscoMetadata = MdDbDsn
	DiscoSPMetadata = MdDbDsn

	Hub.Dsn = MdDbDsn
	Internal.Dsn = MdDbDsn
	ExternalIDP.Dsn = MdDbDsn
	ExternalSP.Dsn = MdDbDsn

	GoElevenHybrid.SlotPassword = env("SlotPassword", "")
	GoElevenHybrid.Keys = strings.Split(env("HybridKeys", ""), ",")
	GoElevenPHPH.SlotPassword = env("PHPHSlotPassword", "")
	GoElevenPHPH.Keys = strings.Split(env("PHPHKeys", ""), ",")
	log.Println("hybrid-config.go", GitCommit)
}

func env(name, defaultvalue string) string {
	if *Test {
		return defaultvalue
	}
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	if envMap == nil && pw != "" {
		var key [32]byte
		keySlice, _ := base64.RawStdEncoding.DecodeString(pw)
		copy(key[:], keySlice[:32])

		var decryptNonce [24]byte
		copy(decryptNonce[:], envJson[:24])
		decrypted, ok := secretbox.Open(nil, envJson[24:], &decryptNonce, &key)
		if !ok {
			panic("decryption error")
		}
		envMap = map[string]string{}
		err := json.Unmarshal(decrypted, &envMap)
		if err != nil {
			log.Panic(err)
		}
	}
	if val, ok := envMap[name]; ok {
		return val
	}
	return defaultvalue
}

// PP - super simple Pretty Print - using JSON
func PP(i ...interface{}) {
	for _, e := range i {
		switch v := e.(type) {
		case []byte:
			fmt.Println(string(v))
		default:
			s, _ := json.MarshalIndent(v, "", "    ")
			fmt.Println(string(s))
		}
	}
	return
}

var fld = regexp.MustCompile(`\b([\w-]+:)`)

func PPx(i ...interface{}) {
	for _, e := range i {
		fmt.Println(fld.ReplaceAllString(fmt.Sprintf("%#v\n", e), "\n\t$1"))
	}
}
