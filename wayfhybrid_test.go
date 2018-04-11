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
	fmt.Println(onetwo)
	// Output:
	// map[one:true two:true]
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

func xxExampleMakeSloUrl() {
	response := goxml.NewXpFromFile("testdata/sourceresponse_dtu.saml")
	idp_md := goxml.NewXpFromFile("testdata/idp_md_dtu.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	url := makeSloUrl(response, idp_md, sp_md)
	fmt.Println(url)
	// Output:
	// ?SAMLRequest=fJHNbtQwFIX38xSW95M4jpsfa5IKaVRppIKAFhZsqhv7urWa2CG%2BgfL2aFKQBhbdWP4539E5vofrl2lkP3BJPoaOF5ngDIOJ1ofHjn%2B5v9k3%2FLrfHRJM46xv42Nc6TN%2BXzERe5nGkPT20vF1CTpC8kkHmDBpMvru3ftbLTOh5yVSNHHkF8jbBKSEC%2FkYODsdO%2F5g6gGNU1A1VXvllG2HxklAi6qxDkRlBiMd1o0RnH39W0aey5xSWvEUEkGgjktRNHtR7GV1L1qtCq3qb5wdMZEPQBvF%2Bx1jjG2N9UYv%2FRPRnHSe%2F4RfLgNPmaU1s8%2F5WSNzb%2Bd8QgILBNn8NB%2FyS%2FbC7QNMeDqyu4%2FnzacVRu88Lh3%2Fx35b7DNnN3GZgN7%2Bp%2FONt3u3STUtEJLHQLx%2FULVwJTaDLVUplLwyEtpKloUYFDRWQN3a0hknS%2FwT9zVcv3s9%2Fjfrfvc7AAD%2F%2Fw%3D%3D
}

func ExampleWayfBirkHandler() {
	idp_md := goxml.NewXpFromFile("testdata/idp_md_dtu.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	request, _ := gosaml.NewAuthnRequest(nil, sp_md, idp_md, "")
	_, _, err := WayfBirkHandler(request, sp_md, idp_md)
	fmt.Println(err)
	// Output:
	// Mkhan
}

func ExampleSendRequestToInternalIdP() {
	idp_md := goxml.NewXpFromFile("testdata/idp_md_dtu.xml")
	sp_md := goxml.NewXpFromFile("testdata/sp_md.xml")
	request, _ := gosaml.NewAuthnRequest(nil, sp_md, idp_md, "")
	_, _, err := WayfBirkHandler(request, sp_md, idp_md)
	fmt.Println(err)
	// Output:
	// Mkhan
}
**/
