module github.com/wayf-dk/wayfhybrid

go 1.15

require (
	github.com/mattn/go-sqlite3 v1.14.0 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pelletier/go-toml v1.8.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.6.1 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20190219221342-73e9d89f5add
	github.com/wayf-dk/godiscoveryservice v0.0.0-20200814223804-6155ba4f0849
	github.com/wayf-dk/goeleven v0.0.0-20200814225736-c05bb61e7cb0
	github.com/wayf-dk/gosaml v0.0.0-20200814223902-c82a90a196e3
	github.com/wayf-dk/goxml v0.0.0-20200814223832-adc46d6f7b13
	github.com/wayf-dk/lmdq v0.0.0-20200814231607-c2ca41543d75
	gopkg.in/xmlpath.v1 v1.0.0-20140413065638-a146725ea6e7 // indirect
	launchpad.net/gocheck v0.0.0-20140225173054-000000000087 // indirect
	launchpad.net/xmlpath v0.0.0-20130614043138-000000000004 // indirect
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/godiscoveryservice => ../godiscoveryservice
	github.com/wayf-dk/goeleven => ../goeleven
	github.com/wayf-dk/gosaml => ../gosaml
	github.com/wayf-dk/goxml => ../goxml
	github.com/wayf-dk/lmdq => ../lmdq
)
