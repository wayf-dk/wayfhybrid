package wayfhybrid

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/lMDQ"
	"github.com/y0ssar1an/q"
	"log"
	"os"
	"sort"
	"strconv"
	"time"
)

var (
	_ = log.Println
	_ = q.Q
)

func printHashedDom(xp *goxml.Xp) {
	hash := sha1.Sum([]byte(xp.C14n(nil, "")))
	fmt.Println(base64.StdEncoding.EncodeToString(append(hash[:])))
}

func scopeCheckTest(scopes [][]string) {
	for _, scope := range scopes {
		response := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
		scopeList := goxml.NewXpFromFile("testdata/scope.xml")
		ext := scopeList.Query(nil, "//md:EntityDescriptor/md:Extensions")[1]
		for i, j := range scope {
			if i > 0 {
				scopeList.QueryDashP(ext, `/shibmd:Scope[`+strconv.Itoa(i)+`]`, j, nil)
			}
			response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[1]/saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue`, scope[0], nil)
		}
		attrNode := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
		eppn, securitydomain, err := checkScope(response, scopeList, attrNode, "saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
		fmt.Println(eppn, securitydomain, err)
	}
}

func ExampleCheckScope() {
	scopes := [][]string{
		{"mekhan@dtu.dk", "dtu.dk", "sdu.dk", "ku.dk"},
		{"mekhan@student.aau.dk@aau.dk", "dtu.dk", "sdu.dk", "ku.dk", "student.aau.dk@aau.dk"},
		{"mekhan@nu.edu.dk", "aau.dk", "sdu.dk"},
		{"mh@kmduni.dans.kmd.dk", "kmduni.dans.kmd.dk", "sdu.dk"},
		{"mh@kmduni.dans.kmd.dk", "dans.kmd.dk", "sdu.dk"},
		{"mh@nybuni.dans.kmd.dk", "ku.dk", "sdu.dk", "nybuni.dans.kmd.dk"},
		{"mh@dansidp-test2.stads.dk", "dansidp-test2.stads.dk", "sdu.dk", "ruc.dk"},
		{"mh@dansidp-qa3.stads.dk", "ku.dk", "sdu.dk", "dansidp-qa3.stads.dk"},
		{"mh@cphbusiness.dk", "cphbusiness.dk", "dtu.dk", "dansidp-test2.stads.dk"},
		{"mh@cphbusiness.dk", "cph.dk", "dtu.dk", "dansidp-test2.stads.dk"},
		{"mh@handelsskolen.com", "handelsskolen.com", "sdu.dk", "dansidp-test2.stads.dk"},
		{"mh@sikker-adgang.dk", "sikker-adgang.dk", "sdu.dk", "handelsskolen.com"},
		{"mh@sikker-adgang.dk", "sikker.dk", "sdu.dk", "handelsskolen.com"},
		{"mh@handelsskolen.com", "handelsskolen.com", "sdu.dk"},
		{"mh@orphanage.wayf.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk"},
		{"mh@plan.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk"},
		{"mekhan@student.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk"},
		{"mh@hst.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk", "hst.aau.dk@aau.dk"},
		{"mh@hst.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk"},
		{"mh@adm.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "adm.aau.dk@aau.dk", "plan.aau.dk@aau.dk", "hst.aau.dk@aau.dk", "create.aau.dk@aau.dk"},
		{"mh@create.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk", "hst.aau.dk@aau.dk", "create.aau.dk@aau.dk"},
		{"mh@civil.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk", "hst.aau.dk@aau.dk", "civil.aau.dk@aau.dk"},
		{"mh@civil.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk", "hst.aau.dk@aau.dk", "mk.aau.dk@aau.dk"},
		{"mh@aub.aau.dk@aau.dk", "sikker-adgang.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk", "hst.aau.dk@aau.dk", "aub.aau.dk@aau.dk"},
		{" ", "dtu.dk", "sdu.dk", "ku.dk"},
	}
	scopeCheckTest(scopes)
	// Output:
	// mekhan@dtu.dk dtu.dk <nil>
	// mekhan@student.aau.dk@aau.dk student.aau.dk@aau.dk <nil>
	// mekhan@nu.edu.dk nu.edu.dk security domain 'nu.edu.dk' does not match any scopes
	// mh@kmduni.dans.kmd.dk kmduni.dans.kmd.dk <nil>
	// mh@kmduni.dans.kmd.dk kmduni.dans.kmd.dk security domain 'kmduni.dans.kmd.dk' does not match any scopes
	// mh@nybuni.dans.kmd.dk nybuni.dans.kmd.dk <nil>
	// mh@dansidp-test2.stads.dk dansidp-test2.stads.dk <nil>
	// mh@dansidp-qa3.stads.dk dansidp-qa3.stads.dk <nil>
	// mh@cphbusiness.dk cphbusiness.dk <nil>
	// mh@cphbusiness.dk cphbusiness.dk security domain 'cphbusiness.dk' does not match any scopes
	// mh@handelsskolen.com handelsskolen.com <nil>
	// mh@sikker-adgang.dk sikker-adgang.dk <nil>
	// mh@sikker-adgang.dk sikker-adgang.dk security domain 'sikker-adgang.dk' does not match any scopes
	// mh@handelsskolen.com handelsskolen.com <nil>
	// mh@orphanage.wayf.dk orphanage.wayf.dk <nil>
	// mh@plan.aau.dk@aau.dk plan.aau.dk@aau.dk <nil>
	// mekhan@student.aau.dk@aau.dk student.aau.dk@aau.dk security domain 'student.aau.dk@aau.dk' does not match any scopes
	// mh@hst.aau.dk@aau.dk hst.aau.dk@aau.dk <nil>
	// mh@hst.aau.dk@aau.dk hst.aau.dk@aau.dk security domain 'hst.aau.dk@aau.dk' does not match any scopes
	// mh@adm.aau.dk@aau.dk adm.aau.dk@aau.dk <nil>
	// mh@create.aau.dk@aau.dk create.aau.dk@aau.dk <nil>
	// mh@civil.aau.dk@aau.dk civil.aau.dk@aau.dk <nil>
	// mh@civil.aau.dk@aau.dk civil.aau.dk@aau.dk security domain 'civil.aau.dk@aau.dk' does not match any scopes
	// mh@aub.aau.dk@aau.dk aub.aau.dk@aau.dk <nil>
	//   not a scoped value:
}

/**
  ExampleNewMetadata tests that the lock preventing race conditions when
  opening and using a mddb works. In real life we (re-)open a mddb file with the
  same name (but hopefully with updated metadata).
*/
func ExampleNewMetadata() {
	onetwo := map[string]bool{}
	finish := make(chan bool)
	mdset := &lMDQ.MDQ{Path: "file:testdata/one.mddb?mode=ro", Table: "wayf_hub_base"}
	mdset.Open()
	go func() {
		for range [1000]int{} {
			md, _ := mdset.MDQ("https://wayf.wayf.dk")
			onetwo[md.Query1(nil, "//wayf:phphfeed")] = true
		}
		finish <- true
	}()
	time.Sleep(1 * time.Millisecond)
	mdset.Path = "file:testdata/two.mddb?mode=ro"
	mdset.Open()
	<-finish
	keys := make([]string, len(onetwo))

	i := 0
	for k := range onetwo {
		keys[i] = k
		i++
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Println(k, onetwo[k])
	}
	// Output:
	// one true
	// two true
}

func ExampleCheckCprCentury() {
	testData := [][]int{
		{88, 0},
		{58, 1},
		{03, 2},
		{01, 3},
		{36, 4},
		{37, 4},
		{56, 5},
		{58, 5},
		{56, 6},
		{58, 6},
		{56, 7},
		{58, 7},
		{56, 8},
		{58, 8},
		{36, 9},
		{37, 9},
	}

	//var year, ciffer int = 88, 3
	for i := range testData {
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
	// 2056
	// 1858
	// 2056
	// 1858
	// 2056
	// 1858
	// 2056
	// 1858
	// 2036
	// 1937
}

func ExampleWayfAttributeHandler() {
	sourceResponse := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
	idp_md := goxml.NewXpFromFile("testdata/idp_md_dtu.xml")
	hub_md := goxml.NewXpFromFile("testdata/hub_md.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	prepareTables(hub_md)

	WayfACSServiceHandler(idp_md, hub_md, sp_md, nil, sourceResponse)
	gosaml.AttributeCanonicalDump(os.Stdout, sourceResponse)

	// Output:
	// cn urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek Petersen
	// displayName urn:oid:2.16.840.1.113730.3.1.241 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek Petersen
	// eduPersonAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.1 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     member
	//     staff
	// eduPersonAssurance urn:oid:1.3.6.1.4.1.5923.1.1.1.11 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     2
	// eduPersonEntitlement urn:oid:1.3.6.1.4.1.5923.1.1.1.7 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     urn:mace:terena.org:tcs:escience-user
	// eduPersonPrimaryAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.5 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     staff
	// eduPersonPrincipalName urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     madpe@dtu.dk
	// eduPersonScopedAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.9 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     member@dtu.dk
	//     staff@dtu.dk
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
	nemloginResponse := goxml.NewXpFromFile("testdata/nemloginresponse.xml")
	idp_md := goxml.NewXpFromFile("testdata/idp_md_nemlogin.xml")
	hub_md := goxml.NewXpFromFile("testdata/hub_md.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	prepareTables(hub_md)

	WayfACSServiceHandler(idp_md, hub_md, sp_md, nil, nemloginResponse)

	gosaml.AttributeCanonicalDump(os.Stdout, nemloginResponse)
	// Output:
	// cn urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton Cantonsen
	// displayName urn:oid:2.16.840.1.113730.3.1.241 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton Cantonsen
	// eduPersonAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.1 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     member
	// eduPersonAssurance urn:oid:1.3.6.1.4.1.5923.1.1.1.11 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     3
	// eduPersonPrimaryAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.5 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     member
	// eduPersonPrincipalName urn:oid:1.3.6.1.4.1.5923.1.1.1.6 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     PID:5666-1234-2-529868547821@sikker-adgang.dk
	// eduPersonScopedAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.9 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     member@sikker-adgang.dk
	// eduPersonTargetedID urn:oid:1.3.6.1.4.1.5923.1.1.1.10 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     WAYF-DK-d00398ea98ce6cac598a317dfe8a9e5145b3b5df
	// gn urn:oid:2.5.4.42 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton
	// mail urn:oid:0.9.2342.19200300.100.1.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
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

func ExampleSamlError() {
	nemloginResponse := goxml.NewXpFromFile("testdata/samlerror.xml")
	fmt.Println(nemloginResponse.PP())
	// Output:
	// <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
	//                 xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	//                 ID="_27af2a04b11ad6b9b819c6f33e333a536ecffc4163"
	//                 Version="2.0"
	//                 IssueInstant="2017-11-13T13:02:32Z"
	//                 Destination="https://wayf.wayf.dk/module.php/saml/sp/saml2-acs.php/wayf.wayf.dk"
	//                 InResponseTo="_7d8dc3ba9cf00cb09c887d7686cdb33973863fb2b1">
	//     <saml:Issuer>
	//      https://wayf.ait.dtu.dk/saml2/idp/metadata.php
	//     </saml:Issuer>
	//     <samlp:Status>
	//         <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder">
	//             <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:NoPassive"/>
	//         </samlp:StatusCode>
	//         <samlp:StatusMessage>
	//           Passive authentication not supported.
	//         </samlp:StatusMessage>
	//     </samlp:Status>
	// </samlp:Response>
}

func ExampleCheckForCommonFederations() {
	idp_md := goxml.NewXpFromFile("testdata/idp_md_dtu.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	err := checkForCommonFederations(idp_md, sp_md)
	fmt.Println(err)
	// Output:
	// <nil>
}

func ExampleNoCommonFederations() {
	idp_md := goxml.NewXpFromFile("testdata/idp_md_dtu.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	sp_md.QueryDashP(nil, "./md:Extensions/wayf:wayf/wayf:feds", "ExampleFed", nil)
	err := checkForCommonFederations(idp_md, sp_md)
	fmt.Println(err)
	// Output:
	// no common federations
}

func ExampleSetAttribute() {
	response := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
	setAttribute("schacHomeOrganization", "DEIC", response, sourceAttributes)
	setAttribute("organizationName", "WAYF", response, sourceAttributes)
	printHashedDom(response)
	// Output:
	// uOmMloU+SsYGph41T3Fso0lmdCk=
}

func ExampleHandleAttributeNameFormat() {
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	response := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
	requestedAttr := goxml.NewXpFromFile("testdata/requestedattr.xml")
	prepareTables(requestedAttr)
	handleAttributeNameFormat(response, sp_md)
	// Output:
	//
}
