package wayfhybrid

import (
	"crypto/sha1"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"x.config"
)

type (
	attributeDescription struct {
		c14n       string
		name       string
		nameformat string
		op         string
	}

	attributeKey struct {
		name, nameFormat string
	}

	attributeDescriptionsMap      map[attributeKey]attributeDescription
	attributeDescriptionsListtype map[string][]attributeDescription
)

var (
	internalAttributesBase = []attributeDescription{
		{c14n: "Issuer", op: "xp:msg:./saml:Issuer"},

		// nemlogin computed
		{c14n: "nemlogin", op: "eq:Issuer:https://saml.nemlog-in.dk"},
		{c14n: "nemlogin", op: "eq:Issuer:https://saml.test-nemlog-in.dk/"},
		{c14n: "eduPersonPrimaryAffiliation", name: "eduPersonPrimaryAffiliation", op: "nemlogin:val:member"},
		{c14n: "organizationName", op: "nemlogin:val:NemLog-in"},
		{c14n: "schacPersonalUniqueID", name: "schacPersonalUniqueID", op: "nemlogin:prefix:urn:mace:terena.org:schac:personalUniqueID:dk:CPR:"},
		{c14n: "eduPersonPrincipalName", name: "eduPersonPrincipalName", op: "nemlogin:cp:uid"},
		{c14n: "eduPersonPrincipalName", name: "eduPersonPrincipalName", op: "nemlogin:postfix:@sikker-adgang.dk"},
		{c14n: "ial", name: "loa", op: "nemlogin:loa"},
		{c14n: "aal", name: "loa", op: "nemlogin:loa"},
		{c14n: "loa", name: "loa", op: "nemlogin:loa"},
		{c14n: "eduPersonAssurance", name: "eduPersonAssurance", op: "nemlogin:cp:loa"},

		// computed
		{c14n: "idpPersistentID", op: "xp:idp:@entityID"},
		{c14n: "idpPersistentID", op: "xp:idp://wayf:persistentEntityID"},
		{c14n: "spPersistentID", op: "xp:sp:@entityID"},
		{c14n: "spPersistentID", op: "xp:sp://wayf:persistentEntityID"},
		{c14n: "idpID", op: "xp:idp:@entityID"},
		{c14n: "spID", op: "xp:sp:@entityID"},
		{c14n: "schacHomeOrganization", op: "xp:idp://wayf:wayf_schacHomeOrganization"},
		{c14n: "schacHomeOrganizationType", op: "xp:idp://wayf:wayf_schacHomeOrganizationType"},
		{c14n: "oioCvrNumberIdentifier", op: "xp:idp://wayf:wayf/wayf:oioCvrNumberIdentifier"},
		{c14n: "idpfeds", op: "xp:idp://wayf:wayf/wayf:feds"},
		{c14n: "spfeds", op: "xp:sp://wayf:wayf/wayf:feds"},
		{c14n: "securitydomain", op: "securitydomain:ku.dk"},
		{c14n: "subsecuritydomain", op: "subsecuritydomain:"},
		{c14n: "hub", op: "eq:Issuer:https://wayf.wayf.dk"},
		{c14n: "persistent", op: "persistent:"},
		{c14n: "displayName", op: "displayname:"},
		{c14n: "eduPersonTargetedID", op: "eptid:"},
		{c14n: "gn", op: "gn:"},
		{c14n: "sn", op: "sn:"},
		{c14n: "pairwise-id", name: "pairwise-id", op: "pairwise-id:"},
		{c14n: "schacPersonalUniqueID", op: "cpr:"},
		{c14n: "eduPersonAffiliation", op: "epa:"},
		{c14n: "eduPersonScopedAffiliation", op: "epsa:"},
		{c14n: "AuthnContextClassRef", op: "xpm:msg://saml:AuthnContextClassRef"},
		{c14n: "AuthnContextClassRef", op: "append:authenticationmethod"},
		{c14n: "commonfederations", op: "commonfederations:"},
		{c14n: "nameID", op: "nameid:"},
		{c14n: "modstlogonmethod", op: "val:username-password-protected-transport"},
		{c14n: "norEduPersonNIN", op: "norEduPersonNIN:"},
		{c14n: "europeanStudentIdentifier", op: "europeanStudentIdentifier:"},
		{c14n: "schacPersonalUniqueCode", op: "append:europeanStudentIdentifier"},
	}

	requestAttributesBase = []attributeDescription{
		// from a request
		{c14n: "idpfeds", op: "xp:idp://wayf:wayf/wayf:feds"},
		{c14n: "spfeds", op: "xp:sp://wayf:wayf/wayf:feds"},
		{c14n: "Issuer", op: "xp:msg:./saml:Issuer"},
		{c14n: "hub", op: "eq:Issuer:https://wayf.wayf.dk"},
		{c14n: "AssertionConsumerServiceURL", op: "xp:msg:./@AssertionConsumerServiceURL"},
		{c14n: "IsPassive", op: "xp:msg:./@IsPassive"},
		{c14n: "ForceAuthn", op: "xp:msg:./@ForceAuthn"},
		{c14n: "RequesterID", op: "xp:msg:./samlp:Scoping/samlp:RequesterID"},
		{c14n: "commonfederations", op: "commonfederations:"},
		{c14n: "protocol", op: "xp:msg:local-name()"},
		{c14n: "RequestedAuthnContextClassRef", op: "xp:sp://wayf:RequestedAuthnContext/wayf:AuthnContextClassRef"},
		{c14n: "RequestedAuthnContextComparison", op: "xp:sp://wayf:RequestedAuthnContext/@Comparison"},
		{c14n: "RequestedAuthnContextClassRef", op: "xp:msg:./samlp:RequestedAuthnContext/saml:AuthnContextClassRef"},
		{c14n: "RequestedAuthnContextComparison", op: "xp:msg:./samlp:RequestedAuthnContext/@Comparison"},
		{c14n: "RequestedAuthnContextClassRef", op: "xp:idp://wayf:RequestedAuthnContext/wayf:AuthnContextClassRef"},
		{c14n: "RequestedAuthnContextComparison", op: "xp:idp://wayf:RequestedAuthnContext/@Comparison"},
		{c14n: "idpEntityID", op: "xp:idp:@entityID"},
		{c14n: "nemlogin", op: "eq:idpEntityID:https://nemlogin.wayf.dk"},
	}

	attributesBase = []attributeDescription{
		// nemlogin specials
		{c14n: "schacPersonalUniqueID", name: "dk:gov:saml:attribute:CprNumberIdentifier", nameformat: "basic"},
		//		{c14n: "eduPersonPrincipalName", name: "urn:oid:0.9.2342.19200300.100.1.1", nameformat: "basic"}, // basic ???

		// wayf
		{c14n: "authenticationmethod", name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/authenticationmethod"},
		{c14n: "cn", name: "cn"},
		{c14n: "cn", name: "urn:oid:2.5.4.3"},
		{c14n: "displayName", name: "displayName"},
		{c14n: "displayName", name: "urn:oid:2.16.840.1.113730.3.1.241"},
		{c14n: "eduPersonAffiliation", name: "eduPersonAffiliation"},
		{c14n: "eduPersonAffiliation", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"},
		{c14n: "eduPersonAssurance", name: "dk:gov:saml:attribute:AssuranceLevel"},
		{c14n: "eduPersonAssurance", name: "eduPersonAssurance"},
		{c14n: "eduPersonAssurance", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.11"},
		{c14n: "eduPersonEntitlement", name: "eduPersonEntitlement"},
		{c14n: "eduPersonEntitlement", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"},
		{c14n: "eduPersonPrimaryAffiliation", name: "eduPersonPrimaryAffiliation"},
		{c14n: "eduPersonPrimaryAffiliation", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.5"},
		{c14n: "eduPersonPrincipalName", name: "eduPersonPrincipalName"},
		{c14n: "eduPersonPrincipalName", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6"},
		{c14n: "eduPersonScopedAffiliation", name: "eduPersonScopedAffiliation"},
		{c14n: "eduPersonScopedAffiliation", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.9"},
		{c14n: "eduPersonTargetedID", name: "eduPersonTargetedID"},
		{c14n: "eduPersonTargetedID", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10"},
		{c14n: "entryUUID", name: "entryUUID"},
		{c14n: "gn", name: "givenName"},
		{c14n: "gn", name: "gn"},
		{c14n: "gn", name: "urn:oid:2.5.4.42"},
		{c14n: "isMemberOf", name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"},
		{c14n: "isMemberOf", name: "isMemberOf"},
		{c14n: "isMemberOf", name: "urn:oid:1.3.6.1.4.1.5923.1.5.1.1"},
		{c14n: "mail", name: "emailaddress"},
		{c14n: "mail", name: "mail"},
		{c14n: "mail", name: "urn:oid:0.9.2342.19200300.100.1.3"},
		{c14n: "mobile", name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone"},
		{c14n: "mobile", name: "mobile"},
		{c14n: "mobile", name: "urn:oid:0.9.2342.19200300.100.1.41"},
		{c14n: "norEduPersonLIN", name: "norEduPersonLIN"},
		{c14n: "norEduPersonLIN", name: "urn:oid:1.3.6.1.4.1.2428.90.1.4"},
		{c14n: "organizationName", name: "organizationName"},
		{c14n: "organizationName", name: "urn:oid:2.5.4.10"},
		{c14n: "pairwise-id", name: "urn:oasis:names:tc:SAML:attribute:pairwise-id"},
		{c14n: "preferredLanguage", name: "preferredLanguage"},
		{c14n: "preferredLanguage", name: "urn:oid:2.16.840.1.113730.3.1.39"},
		{c14n: "schacCountryOfCitizenship", name: "schacCountryOfCitizenship"},
		{c14n: "schacCountryOfCitizenship", name: "urn:oid:1.3.6.1.4.1.25178.1.2.5"},
		{c14n: "schacDateOfBirth", name: "schacDateOfBirth"},
		{c14n: "schacDateOfBirth", name: "urn:oid:1.3.6.1.4.1.25178.1.2.3"},
		{c14n: "schacHomeOrganization", name: "schacHomeOrganization"},
		{c14n: "schacHomeOrganization", name: "urn:oid:1.3.6.1.4.1.25178.1.2.9"},
		{c14n: "schacHomeOrganizationType", name: "schacHomeOrganizationType"},
		{c14n: "schacHomeOrganizationType", name: "urn:oid:1.3.6.1.4.1.25178.1.2.10"},
		{c14n: "schacPersonalUniqueCode", name: "schacPersonalUniqueCode"},
		{c14n: "schacPersonalUniqueCode", name: "urn:oid:1.3.6.1.4.1.25178.1.2.14"},
		{c14n: "schacPersonalUniqueID", name: "schacPersonalUniqueID"},
		{c14n: "schacPersonalUniqueID", name: "urn:oid:1.3.6.1.4.1.25178.1.2.15"},
		{c14n: "norEduPersonNIN", name: "norEduPersonNIN"},
		{c14n: "schacYearOfBirth", name: "schacYearOfBirth"},
		{c14n: "schacYearOfBirth", name: "urn:oid:1.3.6.1.4.1.25178.1.0.2.3"},
		{c14n: "sn", name: "sn"},
		{c14n: "sn", name: "surname"},
		{c14n: "sn", name: "urn:oid:2.5.4.4"},
		{c14n: "street", name: "street"},
		{c14n: "street", name: "urn:oid:2.5.4.9"},
		{c14n: "subject-id", name: "subject-id"},
		{c14n: "subject-id", name: "urn:oasis:names:tc:SAML:attribute:subject-id"},
		{c14n: "uid", name: "uid"},
		{c14n: "uid", name: "urn:oid:0.9.2342.19200300.100.1.1"},

		{c14n: "postalAddress", name: "postalAddress"},
		{c14n: "postalAddress", name: "urn:oid:2.5.4.16"},
		{c14n: "postalCode", name: "postalCode"},
		{c14n: "postalCode", name: "urn:oid:2.5.4.17"},
		{c14n: "localityName", name: "localityName"},
		{c14n: "localityName", name: "urn:oid:2.5.4.7"},
		{c14n: "ou", name: "ou"},
		{c14n: "ou", name: "urn:oid:2.5.4.11"},
		{c14n: "schacGender", name: "urn:oid:1.3.6.1.4.1.25178.1.2.2"},

		// Nemlog-in-3
		{c14n: "uid", name: "https://data.gov.dk/model/core/eid/person/pid"},
		{c14n: "loa", name: "https://data.gov.dk/concept/core/nsis/loa"},
		{c14n: "ial", name: "https://data.gov.dk/concept/core/nsis/ial"},
		{c14n: "aal", name: "https://data.gov.dk/concept/core/nsis/aal"},
		{c14n: "cn", name: "https://data.gov.dk/model/core/eid/fullName"},
		{c14n: "gn", name: "https://data.gov.dk/model/core/eid/firstName"},
		{c14n: "sn", name: "https://data.gov.dk/model/core/eid/lastName"},
		{c14n: "mail", name: "https://data.gov.dk/model/core/eid/email"},
		{c14n: "schacPersonalUniqueID", name: "https://data.gov.dk/model/core/eid/cprNumber"},
		{c14n: "cprUuid", name: "https://data.gov.dk/model/core/eid/cprUuid"},
		//{c14n: "schacDateOfBirth", name: "https://data.gov.dk/model/core/eid/dateOfBirth"}, // wrong format

		// Modst specials
		{c14n: "eduPersonPrincipalName", name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"},
		{c14n: "eduPersonPrincipalName", name: "https://modst.dk/sso/claims/userid"},
		//		{c14n: "eduPersonPrincipalName", name: "https://modst.dk/sso/claims/uniqueid"},
		{c14n: "entryUUID", name: "https://modst.dk/sso/claims/uniqueid"},
		{c14n: "oioCvrNumberIdentifier", name: "https://modst.dk/sso/claims/cvr"},
		{c14n: "mail", name: "https://modst.dk/sso/claims/email"},
		{c14n: "mobile", name: "https://modst.dk/sso/claims/mobile"},
		{c14n: "eduPersonAssurance", name: "https://modst.dk/sso/claims/assurancelevel"},
		{c14n: "modstlogonmethod", name: "https://modst.dk/sso/claims/logonmethod"},
		{c14n: "sn", name: "https://modst.dk/sso/claims/surname"},
		{c14n: "gn", name: "https://modst.dk/sso/claims/givenname"},
	}

	attributenameFormats = map[string]string{
		"basic":       "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		"uri":         "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
		"claims2005":  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims",
		"claims2008":  "http://schemas.xmlsoap.org/ws/2008/05/identity/claims",
		"internal":    "internal",
		"unspecified": "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
		"modst":       "https://modst.dk/sso/claims",
	}

	filtered = map[string]bool{
		//	"eduPersonEntitlement": true,
		"isMemberOf": true,
	}

	internalAttributeDescriptions       = attributeDescriptionsMap{}
	requestAttributeDescriptions        = attributeDescriptionsMap{}
	incomingAttributeDescriptions       = attributeDescriptionsMap{}
	outgoingAttributeDescriptions       = attributeDescriptionsMap{}
	outgoingAttributeDescriptionsByC14n = attributeDescriptionsMap{}
)

func init() {
	for _, ad := range attributesBase {
		incomingAttributeDescriptions[attributeKey{ad.name, attributenameFormats[ad.nameformat]}] = ad
		incomingAttributeDescriptions[attributeKey{ad.name, ""}] = ad
		outgoingAttributeDescriptions[attributeKey{ad.name, ""}] = ad
		outgoingAttributeDescriptionsByC14n[attributeKey{ad.c14n, ""}] = ad
	}
}

// Attributesc14n - Convert to - and compute canonical attributes
func Attributesc14n(request, response, idpMd, spMd *goxml.Xp) (err error) {
	base64encoded := idpMd.QueryXMLBool(nil, xprefix+"base64attributes")
	attributeStatementList := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement[1]`)
	if len(attributeStatementList) == 0 {
		return fmt.Errorf("No AttributeStatement")
	}
	values := map[string][]string{}
	attributeStatement2 := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[2]`, "", nil)
	attributeStatement := attributeStatementList[0]
	sourceAttributes := response.Query(attributeStatement, `./saml:Attribute`)

	//response.QueryDashP(attributeStatement, "./saml:Attribute[1]/@Name", "\x1b", nil)
	//response.QueryDashP(attributeStatement, "./saml:Attribute[1]/saml:AttributeValue[1]", "\x1b", nil)
	//fmt.Println(response.PP())
	for _, attribute := range sourceAttributes {
		name := response.Query1(attribute, "@Name")
		nameFormat := response.Query1(attribute, "@NameFormat")
		atd, ok := incomingAttributeDescriptions[attributeKey{name, nameFormat}]
		if !ok {
			atd, ok = incomingAttributeDescriptions[attributeKey{name, ""}]
		}
		if ok {
			values[atd.c14n] = response.QueryMulti(attribute, `saml:AttributeValue`)
			if base64encoded {
				for i, val := range values[atd.c14n] {
					v, _ := base64.StdEncoding.DecodeString(val)
					values[atd.c14n][i] = string(v)
				}
			}
		}
	}

	attributeOpsHandler(values, internalAttributesBase, request, response, idpMd, spMd, attributeStatement2)
	goxml.RmElement(attributeStatement)
	return
}

// RequestHandler - runs attributeOpsHandler for requestAttributesBase and returns the result as values
func RequestHandler(request, idpMd, spMd *goxml.Xp) (values map[string][]string, err error) {
    values = map[string][]string{}
	attributeOpsHandler(values, requestAttributesBase, request, request, idpMd, spMd, request.QueryDashP(nil, `/saml:AttributeStatement`, "", nil))
	return
}

func attributeOpsHandler(values map[string][]string, atds []attributeDescription, request, msg, idpMd, spMd *goxml.Xp, dest types.Node) {
	contextMap := map[string]*goxml.Xp{"idp": idpMd, "sp": spMd, "msg": msg}
	for _, atd := range atds {
		opParam := strings.SplitN(atd.op, ":", 2)
		if len(values[atd.c14n]) == 0 {
			values[atd.c14n] = []string{""}
		}
		v := &values[atd.c14n][0]
	handleop:
		switch op := opParam[0]; op {
		case "eq":
			opParam = strings.SplitN(opParam[1], ":", 2)
			*v = strconv.FormatBool(values[opParam[0]][0] == opParam[1] || *v == "true")
		case "cp":
			values[atd.c14n] = values[opParam[1]]
		case "val":
			*v = opParam[1]
		case "append":
			values[atd.c14n] = append(values[atd.c14n], values[opParam[1]]...)
		case "prefix":
			*v = opParam[1] + *v
		case "postfix":
			*v = *v + opParam[1]
		case "displayname":
			if *v == "" && len(values["cn"]) != 0 {
				*v = values["cn"][0]
			}
		case "sn":
			if *v == "" && len(values["cn"]) > 0 {
				names := strings.Fields(values["cn"][0])
				*v = names[len(names)-1]
			}
		case "gn":
			if *v == "" && len(values["cn"]) > 0 {
				names := strings.Fields(values["cn"][0])
				*v = strings.Join(names[0:len(names)-1], " ")
			}
		case "xidp":
			*v = idpMd.Query1(nil, xprefix+opParam[1])
		case "xp":
			opParam = strings.SplitN(opParam[1], ":", 2)
			tmp := contextMap[opParam[0]].QueryMulti(nil, opParam[1])
			if len(tmp) != 0 {
				values[atd.c14n] = tmp
			}
		case "xpm":
			opParam = strings.SplitN(opParam[1], ":", 2)
			values[atd.c14n] = append(values[atd.c14n], contextMap[opParam[0]].QueryMulti(nil, opParam[1])...)
		case "securitydomain":
			eppns := values["eduPersonPrincipalName"]
			if len(eppns) > 0 {
				matches := scoped.FindStringSubmatch(eppns[0])
				if len(matches) > 1 {
					*v = matches[2]
					subsecuritydomain := *v
					for _, specialdomain := range strings.Split(opParam[1], ":") {
						if strings.HasSuffix(*v, "."+specialdomain) {
							subsecuritydomain = specialdomain
							break
						}
					}
					values["subsecuritydomain"] = []string{subsecuritydomain}
					values["uid"] = []string{matches[1]}
				}
			}
		case "subsecuritydomain":
			if *v == "" {
				epsas := values["eduPersonScopedAffiliation"]
				if len(epsas) > 0 {
					matches := scoped.FindStringSubmatch(epsas[0])
					if len(matches) > 1 {
						*v = matches[2]
					}
				}
			}
		case "eptid":
			*v = eptid(idpMd, spMd, values)
		case "cpr":
			cpr(idpMd, spMd, values)
		case "epa":
			// get rid of the optional default ""
			if values[atd.c14n][0] == "" {
				values[atd.c14n] = values[atd.c14n][1:]
			}
			values[atd.c14n] = append(values[atd.c14n], values["eduPersonPrimaryAffiliation"]...)
			if intersectionNotEmpty(values[atd.c14n], []string{"student", "faculty", "staff", "employee"}) {
				values[atd.c14n] = append(values[atd.c14n], "member")
			}
		case "epsa":
			if values[atd.c14n][0] == "" {
				values[atd.c14n] = values[atd.c14n][1:]
			}
			if values["securitydomain"][0] != "" {
				for _, epa := range values["eduPersonAffiliation"] {
					if epa == "" {
						continue
					}
					values[atd.c14n] = append(values[atd.c14n], epa+"@"+values["securitydomain"][0])
					values[atd.c14n] = unique(values[atd.c14n])
				}
			}
		case "persistent":
			*v = msg.Query1(nil, "./saml:Assertion/saml:Subject/saml:NameID[@Format='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent']")
			if *v == "" {
				*v = msg.Query1(nil, "./saml:Assertion/saml:AttributeStatement/saml:Attribute[@Name='eduPersonTargetedID']/saml:AttributeValue/saml:NameID")
			}
		case "nemlogin":
			if values["nemlogin"][0] == "true" {
				opParam = strings.SplitN(opParam[1], ":", 2)
				goto handleop
			}
		case "commonfederations":
			*v = strconv.FormatBool(intersectionNotEmpty(values["idpfeds"], values["spfeds"]) || values["hub"][0] == "true")
		case "nameid":
			switch request.Query1(nil, "./samlp:NameIDPolicy/@Format") { // always prechecked when receiving
			case gosaml.Persistent:
				*v = values["eduPersonTargetedID"][0]
			case gosaml.Email:
				*v = values["eduPersonPrincipalName"][0]
			default:
				*v = gosaml.ID()
			}
			switch attr := spMd.Query1(nil, xprefix+"nameIDAttribute"); {
			case attr == "":
			default:
				*v = values[attr][0]
			}
		case "norEduPersonNIN":
			if *v == "" {
				spuid := values["schacPersonalUniqueID"][0]
				const prefix = "urn:mace:terena.org:schac:personalUniqueID:dk:CPR:"
				i := strings.LastIndex(spuid, prefix)
				if i == 0 {
					*v = spuid[len(prefix):]
				}
			}
		case "europeanStudentIdentifier":
			if idpMd.QueryXMLBool(nil, xprefix+"addESI") {
				*v = "urn:schac:personalUniqueCode:int:esi:" + values["schacHomeOrganization"][0] + ":" + eptidforaudience(values, "europeanStudentIdentifier")
			}
		default:
			// panic("unknown op: " + op)
		}
	}

	for basic, vals := range values {
		seen := map[string]bool{}
		for _, val := range vals {
			if seen[val] || val == "" {
				continue
			}
			msg.QueryDashP(dest, `saml:Attribute[@Name="`+basic+`"]/saml:AttributeValue[0]`, val, nil)
			seen[val] = true
		}
	}
}

func eptidforaudience(values map[string][]string, audience string) string {
	idpID := values["idpPersistentID"][0]
	idPSpecificSalt := sha512.Sum512([]byte("IdPSpecificSalt" + config.EptidSalt + idpID))
	hash := sha512.Sum512_224([]byte(audience + string(idPSpecificSalt[:]) + values["eduPersonPrincipalName"][0]))
	return hex.EncodeToString(append(hash[:]))
}

func eptid(idpMd, spMd *goxml.Xp, values map[string][]string) string {
	var epid string

	if epid = values["persistent"][0]; epid == "" {
		if len(values["eduPersonPrincipalName"]) == 0 {
			return ""
		}
		epid = values["eduPersonPrincipalName"][0]
	}

	matches := scoped.FindStringSubmatch(epid)
	if len(matches) != 3 {
		return ""
	}

	idp := values["idpPersistentID"][0]
	sp := values["spPersistentID"][0]

	uidhashbase := "uidhashbase" + config.EptidSalt
	uidhashbase += strconv.Itoa(len(idp)) + ":" + idp
	uidhashbase += strconv.Itoa(len(sp)) + ":" + sp
	uidhashbase += strconv.Itoa(len(epid)) + ":" + epid
	uidhashbase += config.EptidSalt

	hash := sha1.Sum([]byte(uidhashbase))
	return "WAYF-DK-" + hex.EncodeToString(append(hash[:]))
}

func cpr(idpMd, spMd *goxml.Xp, values map[string][]string) {
	for _, cpr := range values["schacPersonalUniqueID"] {
		// schacPersonalUniqueID is multi - use the first DK cpr found
		if matches := dkcprpreg.FindStringSubmatch(cpr); len(matches) > 0 {
			cpryear, _ := strconv.Atoi(matches[3])
			c7, _ := strconv.Atoi(matches[4])
			year := strconv.Itoa(yearfromyearandcifferseven(cpryear, c7))
			if len(values["schacDateOfBirth"]) == 0 {
				values["schacDateOfBirth"] = []string{year + matches[2] + matches[1]}
			}
			if len(values["schacYearOfBirth"]) == 0 {
				values["schacYearOfBirth"] = []string{year}
			}
			break
		}
	}
}

/* see http://www.cpr.dk/cpr_artikler/Files/Fil1/4225.pdf or http://da.wikipedia.org/wiki/CPR-nummer for algorithm */
// yearfromyearandcifferseven returns a year for CPR
func yearfromyearandcifferseven(year, c7 int) int {
	cpr2year := [][]int{
		{99, 1900},
		{99, 1900},
		{99, 1900},
		{99, 1900},
		{36, 2000, 1900},
		{57, 2000, 1800},
		{57, 2000, 1800},
		{57, 2000, 1800},
		{57, 2000, 1800},
		{36, 2000, 1900},
	}
	century := cpr2year[c7]
	if year <= century[0] {
		year += century[1]
	} else {
		year += century[2]
	}
	return year
}

// CopyAttributes copies the attributes
func CopyAttributes(r *http.Request, sourceResponse, response, idpMd, spMd *goxml.Xp) (ardValues map[string][]string, ardHash string) {
	ardValues = make(map[string][]string)
	base64encodedOut := spMd.QueryXMLBool(nil, xprefix+"base64attributes")

	requestedAttributes := spMd.Query(nil, `./md:SPSSODescriptor/md:AttributeConsumingService[1]/md:RequestedAttribute`)
	nameName := "Name"
	nameFormatName := "NameFormat"

	saml := "saml"
	assertionList := response.Query(nil, "./saml:Assertion")
	if len(assertionList) == 0 {
		assertionList = response.Query(nil, "./t:RequestedSecurityToken/saml1:Assertion")
		saml = "saml1"
		nameName = "AttributeName"
		nameFormatName = "AttributeNamespace"
	}

	destinationAttributes := response.QueryDashP(assertionList[0], saml+":AttributeStatement", "", nil) // only if there are actually some requested attributes

	if gosaml.DebugSetting(r, "allAttrs") == "1"  || spMd.QueryXMLBool(nil, xprefix+"RequestedAttributesEqualsStar") {
		destinationAttributes.AddPrevSibling(response.CopyNode(sourceResponse.Query(nil, `//saml:AttributeStatement`)[0], 1))
		goxml.RmElement(destinationAttributes)
		return nil, ""
	}

	spID := sourceResponse.Query1(nil, `//saml:AttributeStatement/saml:Attribute[@Name="spID"]/saml:AttributeValue`)
	var spValues, idpValues types.Node
	if nl := spMd.Query(nil, xprefix+`ValueFilter`); len(nl) > 0 {
		spValues = nl[0]
	}
	if nl := idpMd.Query(nil, xprefix+`ValueFilter[@ServiceProvider="`+spID+`"]`); len(nl) > 0 { // sp specific filters for an IdP
		idpValues = nl[0]
	} else if nl := idpMd.Query(nil, xprefix+`ValueFilter[not(@ServiceProvider)]`); len(nl) > 0 { // default filters for an IdP - only if no sp specific filters are present
		idpValues = nl[0]
	}

	h := sha1.New()
	for _, requestedAttribute := range requestedAttributes {
		friendlyName := spMd.Query1(requestedAttribute, "@FriendlyName")
		name := spMd.Query1(requestedAttribute, "@Name")
		nameFormat := spMd.Query1(requestedAttribute, "@NameFormat")

		atd, ok := outgoingAttributeDescriptions[attributeKey{name, ""}]
		if !ok {
			atd, ok = outgoingAttributeDescriptionsByC14n[attributeKey{friendlyName, ""}]
		}
		if !ok {
			continue
		}

		filters := []*regexp.Regexp{}
		filters = append(filters, makeFilters(spMd.Query(requestedAttribute, `saml:AttributeValue`))...)
		filters = append(filters, makeFilters(spMd.Query(spValues, `wayf:Attribute[@CanonicalName="`+atd.c14n+`"]/wayf:Value`))...)
		filters = append(filters, makeFilters(idpMd.Query(idpValues, `wayf:Attribute[@CanonicalName="`+atd.c14n+`"]/wayf:Value`))...)

		// if filter is required, but none is specified
		if filtered[atd.c14n] && len(filters) == 0 {
			continue
		}

		values := sourceResponse.QueryMulti(nil, `//saml:AttributeStatement/saml:Attribute[@Name="`+atd.c14n+`"]/saml:AttributeValue`)

		if len(filters) > 0 {
			filteredValues := []string{}
			for _, value := range values {
				if matchRegexpArray(value, filters) {
					filteredValues = append(filteredValues, value)
				}
			}
			values = filteredValues
		}

		if len(values) == 0 {
			continue
		}

		io.WriteString(h, atd.c14n)

		newAttribute := response.QueryDashP(destinationAttributes, saml+":Attribute[0]/@"+nameName, name, nil)
		if nameFormat != "" {
			response.QueryDashP(newAttribute, "@"+nameFormatName, nameFormat, nil)
		}
		response.QueryDashP(newAttribute, "@FriendlyName", atd.c14n, nil)

		for _, value := range values {
			io.WriteString(h, value)
			ardValues[atd.c14n] = append(ardValues[atd.c14n], value)
			if base64encodedOut {
				v := base64.StdEncoding.EncodeToString([]byte(value))
				value = string(v)
			}
			response.QueryDashP(newAttribute, saml+":AttributeValue[0]", value, nil)
		}
	}

	io.WriteString(h, spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]`))
	io.WriteString(h, spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="da"]`))
	io.WriteString(h, spMd.Query1(nil, `@entityID`))
	io.WriteString(h, response.Query1(nil, `saml:Issuer`))
	ardHash = fmt.Sprintf("%.5x", h.Sum(nil))
	return
}

func makeFilters(allowedValues types.NodeList) (regexps []*regexp.Regexp) {
	regexps = []*regexp.Regexp{}
	for _, attr := range allowedValues {
		reg := "^" + strings.Replace(regexp.QuoteMeta(strings.TrimSpace(attr.NodeValue())), "\\*", ".*", -1) + "$"
		regexps = append(regexps, regexp.MustCompile(reg))
	}
	return
}

func matchRegexpArray(item string, array []*regexp.Regexp) bool {
	for _, i := range array {
		if i.MatchString(item) {
			return true
		}
	}
	return false
}

func unique(slice []string) (list []string) {
	keys := make(map[string]bool)
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return
}
