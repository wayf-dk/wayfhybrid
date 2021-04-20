// +build test testmdq

package config

import (
	"log"
)

func init() {
	Intf = "127.0.0.1:443"
	//Intf = "192.168.33.63:443"
	HTTPSKey = "/etc/ssl/wayf/https/wildcard.test.lan.key"
	HTTPSCert = "/etc/ssl/wayf/https/wildcard.test.lan.pem"
	DiscoMetadata = "file:/srv/wayf/phph.wayf.dk/public/md/hybrid-metadata.mddb?mode=ro"
	DiscoSPMetadata = "file:/srv/wayf/phph.wayf.dk/public/md/hybrid-metadata.mddb?mode=ro"
	Hub = mddb{Path: "file:/srv/wayf/phph.wayf.dk/public/md/hybrid-metadata.mddb?mode=ro", Table: "HYBRID_HUB"}
	Internal = mddb{Path: "file:/srv/wayf/phph.wayf.dk/public/md/hybrid-metadata.mddb?mode=ro", Table: "HYBRID_INTERNAL"}
	ExternalIDP = mddb{Path: "file:/srv/wayf/phph.wayf.dk/public/md/hybrid-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_IDP"}
	ExternalSP = mddb{Path: "file:/srv/wayf/phph.wayf.dk/public/md/hybrid-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_SP"}
	MetadataFeeds = mdFeeds{{Path: "/srv/dev/wayf-hybrid-test/hybrid-metadata.mddb", URL: "https://phph.wayf.dk/md/hybrid-metadata.mddb"}}
	log.Println("hybrid-config-test.go")
}
