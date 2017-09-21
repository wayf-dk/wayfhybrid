package wayfhybrid

import (
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"io/ioutil"
	"log"
)

var (
	_ = log.Println
)

func xpFromFile(file string) (res *goxml.Xp) {
	xml, err := ioutil.ReadFile(file)
	if err != nil {
		log.Panic(err)
	}
	res = goxml.NewXp(string(xml))
	return
}

func ExampleCheckCprCentury() {
	testData := [][]int{
		{88, 0},
		{58, 1},
		{03, 2},
		{01, 3},
		{36, 4},
		{37, 4},
		{36, 5},
		{37, 5},
		{36, 6},
		{37, 6},
		{36, 7},
		{37, 7},
		{57, 8},
		{58, 8},
		{36, 9},
		{37, 9},
	}

	//var year, ciffer int = 88, 3
	for i, _ := range testData {
		var res = yearfromyearandcifferseven(testData[i][0], testData[i][1])
		fmt.Println(res)
	}
	// Output:
	// 1988
	// 1958
	// 1903
	// 1901
	// 2036
	// 1937
	// 2036
	// 1937
	// 2036
	// 1937
	// 2036
	// 1937
	// 2057
	// 1858
	// 2036
	// 1937
}

func ExampleWayfAttributeHandler() {
	sourceResponse := xpFromFile("testdata/sourceresponse_dtu.saml")
	idp_md := xpFromFile("testdata/idp_md_dtu.xml")
	hub_md := xpFromFile("testdata/hub_md.xml")
	sp_md := xpFromFile("testdata/sp_md.xml")
	prepareTables(hub_md)

	WayfAttributeHandler(idp_md, hub_md, sp_md, sourceResponse)
	gosaml.AttributeCanonicalDump(sourceResponse)

	// output:
	// cn urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek Petersen
	// displayName urn:oid:2.16.840.1.113730.3.1.241 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek Petersen
	// eduPersonAssurance urn:oid:1.3.6.1.4.1.5923.1.1.1.11 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     2
	// eduPersonEntitlement urn:oid:1.3.6.1.4.1.5923.1.1.1.7 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     urn:mace:terena.org:tcs:escience-user
	// eduPersonPrimaryAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.5 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     staff
	// eduPersonPrincipalName urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     madpe@dtu.dk
	// eduPersonScopedAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.9 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     staff@just.testing.dtu.dk
	// eduPersonTargetedID urn:oid:1.3.6.1.4.1.5923.1.1.1.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     WAYF-DK-9c03f6bdabf9e280d9dfdedb42ebaf161c30ed51
	// gn urn:oid:2.5.4.42 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek
	// mail urn:oid:0.9.2342.19200300.100.1.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     madpe@dtu.dk
	// organizationName urn:oid:2.5.4.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Danmarks Tekniske Universitet
	// preferredLanguage urn:oid:2.16.840.1.113730.3.1.39 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     da-DK
	// schacDateOfBirth urn:oid:1.3.6.1.4.1.25178.1.2.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     18580824
	// schacHomeOrganization urn:oid:1.3.6.1.4.1.25178.1.2.9 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     dtu.dk
	// schacHomeOrganizationType urn:oid:1.3.6.1.4.1.25178.1.2.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     urn:mace:terena.org:schac:homeOrganizationType:eu:higherEducationalInstitution
	// schacPersonalUniqueID urn:oid:1.3.6.1.4.1.25178.1.2.15 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408588834
	// schacYearOfBirth urn:oid:1.3.6.1.4.1.25178.1.0.2.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     1858
	// sn urn:oid:2.5.4.4 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Petersen
}

func ExampleNemLoginAttributeHandler() {
	nemloginResponse := xpFromFile("testdata/nemloginresponse.xml")
	idp_md := xpFromFile("testdata/idp_md_nemlogin.xml")
	hub_md := xpFromFile("testdata/hub_md.xml")
	sp_md := xpFromFile("testdata/sp_md.xml")
	prepareTables(hub_md)

	_, _ = WayfAttributeHandler(idp_md, hub_md, sp_md, nemloginResponse)

	gosaml.AttributeCanonicalDump(nemloginResponse)
	// output:
	// cn urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton Cantonsen
	//     Anton Banton Cantonsen
	// displayName urn:oid:2.16.840.1.113730.3.1.241 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton Cantonsen
	// eduPersonAssurance urn:oid:1.3.6.1.4.1.5923.1.1.1.11 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     3
	// eduPersonPrimaryAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.5 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     member
	// eduPersonPrincipalName urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     PID:5666-1234-2-529868547821@sikker-adgang.dk
	// eduPersonTargetedID urn:oid:1.3.6.1.4.1.5923.1.1.1.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     WAYF-DK-d00398ea98ce6cac598a317dfe8a9e5145b3b5df
	// gn urn:oid:2.5.4.42 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton
	// mail urn:oid:0.9.2342.19200300.100.1.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     someone@example.com
	//     someone@example.com
	// organizationName urn:oid:2.5.4.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Ingen organisatorisk tilknytning
	//     NemLogin
	// schacDateOfBirth urn:oid:1.3.6.1.4.1.25178.1.2.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     18580824
	// schacHomeOrganization urn:oid:1.3.6.1.4.1.25178.1.2.9 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     sikker-adgang.dk
	// schacHomeOrganizationType urn:oid:1.3.6.1.4.1.25178.1.2.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     urn:mace:terena.org:schac:homeOrganizationType:int:other
	// schacPersonalUniqueID urn:oid:1.3.6.1.4.1.25178.1.2.15 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     urn:mace:terena.org:schac:personalUniqueID:dk:CPR:2408588234
	// schacYearOfBirth urn:oid:1.3.6.1.4.1.25178.1.0.2.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     1858
	// sn urn:oid:2.5.4.4 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//
	//     Cantonsen
}
