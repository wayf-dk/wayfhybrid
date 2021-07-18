module github.com/wayf-dk/wayfhybrid

go 1.16

require (
	github.com/wayf-dk/go-libxml2 v0.0.0-20210308214358-9c9e7b3a8e9c
	github.com/wayf-dk/godiscoveryservice v0.0.0-20210718204616-d566bc752aa1
	github.com/wayf-dk/goeleven v0.0.0-20210622080738-31052701ada3
	github.com/wayf-dk/gosaml v0.0.0-20210625075105-0384b2997a7c
	github.com/wayf-dk/goxml v0.0.0-20210624110732-3d7665237fff
	github.com/wayf-dk/lmdq v0.0.0-20210625074409-32dad8c2e27a
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
