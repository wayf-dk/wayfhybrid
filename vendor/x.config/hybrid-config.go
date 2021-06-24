package config

import (
	"embed"
	"io/fs"
	"log"
	"os"
)

type (
	mddb struct {
		Path, Table string
	}

	mdFeeds []struct {
		Path, URL string
	}

	GoElevenConfig struct {
		Intf, AllowedIP                       string
		HsmLib, Slot, SlotPassword, KeyLabels string
		MaxSessions                           int
	}
)

const (
	SsoService  = "wayf.wayf.dk/saml2/idp/SSOService2.php"
	Acs         = "wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"
	NemloginAcs = "nemlogin.wayf.dk/module.php/saml/sp/saml2-acs.php/nemlogin.wayf.dk"
	Spslo       = "wayf.wayf.dk/module.php/saml/sp/saml2-logout.php/wayf.wayf.dk"
	Vvpmss      = "wayf.wayf.dk/vvpmss"
	Saml2jwt    = "wayf.wayf.dk/saml2jwt"
	Jwt2saml    = "wayf.wayf.dk/jwt2saml"
	MDQ         = "wayf.wayf.dk/MDQ/"
	Nemloginslo = "nemlogin.wayf.dk/module.php/saml/sp/saml2-logout.php/nemlogin.wayf.dk"
	Idpslo      = "wayf.wayf.dk/saml2/idp/SingleLogoutService.php"
	Birkslo     = "birk.wayf.dk/SLO/"
	Kribslo     = "krib.wayf.dk/SLO/"
	Birk        = "birk.wayf.dk/"
	Krib        = "krib.wayf.dk/"
	Dsbackend   = "wayf.wayf.dk/dsbackend"
	Dstiming    = "wayf.wayf.dk/dstiming"
	Public      = "/"

	TestSP2    = "wayfsp2.wayf.dk"
	TestSP2Acs = "wayfsp2.wayf.dk/ACS"
	TestSP2Slo = "wayfsp2.wayf.dk/SLO"
	TestSP     = "wayfsp.wayf.dk"
	TestSPAcs  = "wayfsp.wayf.dk/ACS"
	TestSPSlo  = "wayfsp.wayf.dk/SLO"

	SaltForHashedEppn = "just testing for now"

	DiscoveryService = "https://wayf.wayf.dk/ds/?"
	Domain           = "wayf.dk"
	HubEntityID      = "https://wayf.wayf.dk"
	SecureCookieHashKey = "144dfe890f9b155c06b8d464c38b192b844734c7de8d58b1b7325ab27f09627c"
	ConsentAsAService   = ""
	MdDbPath = "file:/opt/wayf/hybrid-metadata.mddb"
	MdDb = MdDbPath + "?mode=ro"
	HsmLib = "/usr/safenet/lunaclient/lib/libCryptoki2_64.so"
)

var (
	//go:embed templates/hybrid.tmpl
	HybridTmpl string

	//go:embed public/*
	publicFiles embed.FS

	//go:embed certs/*
	privateKeys embed.FS

	PublicFiles fs.FS
	PrivateKeys fs.FS

	Intf            = "0.0.0.0:443"
	HTTPSKey        = "/etc/ssl/wayf/https/wildcard.wayf.dk.key"
	HTTPSCert       = "/etc/ssl/wayf/https/wildcard.wayf.dk.pem"
	DiscoMetadata   = MdDb
	DiscoSPMetadata = MdDb
	NotFoundRoutes  = []string{"favicon.ico"}

	Hub         = mddb{Path: MdDb, Table: "HYBRID_HUB"}
	Internal    = mddb{Path: MdDb, Table: "HYBRID_INTERNAL"}
	ExternalIDP = mddb{Path: MdDb, Table: "HYBRID_EXTERNAL_IDP"}
	ExternalSP  = mddb{Path: MdDb, Table: "HYBRID_EXTERNAL_SP"}

	MetadataFeeds  = mdFeeds{{Path: MdDbPath, URL: "https://phph.wayf.dk/md/hybrid-metadata.mddb"}}
	ElementsToSign = []string{"/samlp:Response/saml:Assertion"}

	EptidSalt string


	GoElevenHybrid = GoElevenConfig{
		HsmLib:       HsmLib,
		Slot:         "wayfha",
		SlotPassword: "",
		KeyLabels:    "wayf.2016.key:zzzzzzzzzzzz",
		MaxSessions:  40,
	}

	GoElevenPHPH = GoElevenConfig{
		Intf:         "localhost:8082",
		AllowedIP:    "127.0.0.1",
		HsmLib:       HsmLib,
		Slot:         "metadata",
		SlotPassword: "",
		KeyLabels:    "metadata.2016.signing.key:9yPMqEUEHJNR4WSiWWnz9Hc6",
		MaxSessions:  64,
	}
)

func init() {
	PrivateKeys, _ = fs.Sub(privateKeys, "certs")
	PublicFiles, _ = fs.Sub(publicFiles, "public")
	HTTPSKey = env("HTTPSKey", HTTPSKey)
	HTTPSCert = env("HTTPSCert", HTTPSCert )
	EptidSalt = env("EptidSalt", "")
	GoElevenHybrid.SlotPassword = env("SlotPassword", "")
	GoElevenPHPH.SlotPassword = env("SlotPassword", "")
	GoElevenPHPH.KeyLabels = env("SlotPassword", GoElevenPHPH.KeyLabels)
}

func env(name, defaultvalue string) string {
	if val, ok := os.LookupEnv(name); ok {
		return val
	}
	if defaultvalue == "" {
        log.Fatalf("no env var for %s", name)
	}
	return defaultvalue
}

