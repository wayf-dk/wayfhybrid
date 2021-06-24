module github.com/wayf-dk/wayfhybrid

go 1.16

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.0 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20200913202138-5af62eb8566b
	github.com/wayf-dk/godiscoveryservice v0.0.0-20200814223804-6155ba4f0849
	github.com/wayf-dk/goeleven v0.0.0-20210308204711-8ad7357fdc65
	github.com/wayf-dk/gosaml v0.0.0-20200814223902-c82a90a196e3
	github.com/wayf-dk/goxml v0.0.0-20201218125345-b1a8c71da4f0
	github.com/wayf-dk/lmdq v0.0.0-20200814231607-c2ca41543d75
	x.config v0.0.0-00010101000000-000000000000
)

replace (
	github.com/wayf-dk/go-libxml2 => ../go-libxml2
	github.com/wayf-dk/godiscoveryservice => ../godiscoveryservice
	github.com/wayf-dk/goeleven => ../goeleven
	github.com/wayf-dk/gosaml => ../gosaml
	github.com/wayf-dk/goxml => ../goxml
	github.com/wayf-dk/lmdq => ../lmdq
	x.config => ../hybrid-config
)
