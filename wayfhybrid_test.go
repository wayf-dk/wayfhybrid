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
	"testing"
	"time"
)

var (
	_ = log.Println
	_ = q.Q
)

func TestMain(m *testing.M) {
	Md.Hub = &lMDQ.MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_HUB"}
	Md.Internal = &lMDQ.MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_INTERNAL"}
	Md.ExternalIdP = &lMDQ.MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_IDP"}
	Md.ExternalSP = &lMDQ.MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_SP"}

	for _, md := range []gosaml.Md{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		err := md.(*lMDQ.MDQ).Open()
		if err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func printHashedDom(xp *goxml.Xp) {
	hash := sha1.Sum([]byte(xp.C14n(nil, "")))
	fmt.Println(base64.StdEncoding.EncodeToString(append(hash[:])))
}
/*
func scopeCheckTest(scopes [][]string) {
	for _, scope := range scopes {
		response := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
		scopeList := goxml.NewXpFromFile("testdata/scope.xml")
		ext := scopeList.Query(nil, "//md:EntityDescriptor/md:Extensions")[1]
		for i, j := range scope {
			if i > 0 {
				scopeList.QueryDashP(ext, `/shibmd:Scope[`+strconv.Itoa(i)+`]`, j, nil)
			}
			response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[1]/saml:Attribute[@FriendlyName='eduPersonPrincipalName']/saml:AttributeValue`, scope[0], nil)
			response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[1]/saml:Attribute[@FriendlyName='eduPersonScopedAffiliation']/saml:AttributeValue`, scope[2], nil)
		}
		attrNode := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
		eppn, eppnForEptid, securitydomain, eppsas,err := checkScope(response, scopeList, attrNode, true) // "saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
		fmt.Println(eppn, eppnForEptid, securitydomain, eppsas, err)
	}
}*/

func scopeCheckTest(scopes [][]string, reqEppn bool) {
	for _, scope := range scopes {
		response := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
		scopeList := goxml.NewXpFromFile("testdata/scope.xml")
		ext := scopeList.Query(nil, "//md:EntityDescriptor/md:Extensions")[1]
		exttest := response.Query(nil, "./saml:Assertion/saml:AttributeStatement")[0]
		scopeList.QueryDashP(ext, `/shibmd:Scope`, scope[1], nil)
		if (scope[0] == ""){
		    response.QueryDashP(exttest, `/saml:Attribute[@FriendlyName='eduPersonPrincipalName']`, "\x1b", nil)
		} else {
            response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[1]/saml:Attribute[@FriendlyName='eduPersonPrincipalName']/saml:AttributeValue`, scope[0], nil)
        }
		for i, j := range scope[2:] {
		    response.QueryDashP(exttest, `/saml:Attribute[@FriendlyName='eduPersonScopedAffiliation']/saml:AttributeValue[`+strconv.Itoa(i+1)+`]`, j, nil)
		}

		attrNode := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0]
		eppn, eppnForEptid, securitydomain, eppsas,err := checkScope(response, scopeList, attrNode, reqEppn) // "saml:Attribute[@Name='eduPersonPrincipalName']/saml:AttributeValue")
		fmt.Println(eppn, eppnForEptid, securitydomain, eppsas, err)
	}
}

func ExampleCheckScope() {
    scopesEppn := [][]string{
		{"mekhan@aau.dk", "aau.dk", "staff@aau.dk", "staff@zzz.aau.dk", "staff@xxx.aau.dk"},
		{"mh@sikker-adgang.dk", "sikker-adgang.dk", "staff@adgang.dk"},
		{"", "dtu.dk", "staff@aau.dk"},
	}
    scopeCheckTest(scopesEppn, true)

	scopes := [][]string{
	    {"mekhan@aau.dk", "dtu.dk", "staff@aau.dk", "staff@zzz.aau.dk", "staff@xxx.aau.dk"},
		{"mekhan@aau.dk", "aau.dk", "staff@aau.dk", "staff@zzz.aau.dk", "staff@xxx.aau.dk"},
		{"mh@kmduni.dans.kmd.dk", "kmduni.dans.kmd.dk", "staff@kmduni.dans.kmd.dk"},
		{"mh@sikker-adgang.dk", "sikker-adgang.dk", "sdu.dk", "staff@sikker-adgang.dk"},
		{"mekhan@student.aau.dk@aau.dk", "student.aau.dk@aau.dk", "sdu.dk", "orphanage.wayf.dk", "plan.aau.dk@aau.dk"},
		{"mh@sikker-adgang.dk", "sikker-adgang.dk", "staff@adgang.dk"},
	    {"", "aau.dk", "staff@aau.dk"},
	    {"", "aau.dk", "staff@aau.dk", "member@aau.dk"},
	    {"", "dtu.dk", "staff@aau.dk"},
	}
	scopeCheckTest(scopes, false)
	// Output:
    // mekhan@aau.dk mekhan@aau.dk aau.dk [staff@aau.dk staff@zzz.aau.dk staff@xxx.aau.dk] <nil>
    // mh@sikker-adgang.dk mh@sikker-adgang.dk sikker-adgang.dk [staff@adgang.dk] eduPersonScopedAffiliation: staff@adgang.dk has not 'sikker-adgang.dk' as security sub domain
    //    [staff@aau.dk] Mandatory 'eduPersonPrincipalName' attribute missing
    // mekhan@aau.dk mekhan@aau.dk aau.dk [staff@aau.dk staff@zzz.aau.dk staff@xxx.aau.dk] security domain 'aau.dk' does not match any scopes
    // mekhan@aau.dk mekhan@aau.dk aau.dk [staff@aau.dk staff@zzz.aau.dk staff@xxx.aau.dk] eduPersonScopedAffiliation: staff@zzz.aau.dk has not 'aau.dk' as security domain
    // mh@kmduni.dans.kmd.dk mh@kmduni.dans.kmd.dk kmduni.dans.kmd.dk [staff@kmduni.dans.kmd.dk] <nil>
    // mh@sikker-adgang.dk mh@sikker-adgang.dk sikker-adgang.dk [sdu.dk staff@sikker-adgang.dk] eduPersonScopedAffiliation: sdu.dk does not end with a domain
    // mekhan@student.aau.dk@aau.dk mekhan@student.aau.dk@aau.dk student.aau.dk@aau.dk [sdu.dk orphanage.wayf.dk plan.aau.dk@aau.dk] eduPersonScopedAffiliation: sdu.dk does not end with a domain
    // mh@sikker-adgang.dk mh@sikker-adgang.dk sikker-adgang.dk [staff@adgang.dk] eduPersonScopedAffiliation: staff@adgang.dk has not 'sikker-adgang.dk' as security domain
    //   aau.dk [staff@aau.dk] <nil>
    //   aau.dk [staff@aau.dk member@aau.dk] <nil>
    //   aau.dk [staff@aau.dk] security domain 'aau.dk' does not match any scopes
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

	WayfACSServiceHandler(idp_md, hub_md, sp_md, nil, sourceResponse, false)
	gosaml.AttributeCanonicalDump(os.Stdout, sourceResponse)

	// Output:
	// cn urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek Petersen
	// displayName urn:oid:2.16.840.1.113730.3.1.241 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Mads Freek Petersen
	// eduPersonAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.1 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//
	//     member
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

	WayfACSServiceHandler(idp_md, hub_md, sp_md, nil, nemloginResponse, false)

	gosaml.AttributeCanonicalDump(os.Stdout, nemloginResponse)
	// Output:
	// cn urn:oid:2.5.4.3 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton Cantonsen
	// displayName urn:oid:2.16.840.1.113730.3.1.241 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//     Anton Banton Cantonsen
	// eduPersonAffiliation urn:oid:1.3.6.1.4.1.5923.1.1.1.1 urn:oasis:names:tc:SAML:2.0:attrname-format:uri
	//
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
	// iGxIpD9n687nhQOIovOUBmy1fuM=
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
