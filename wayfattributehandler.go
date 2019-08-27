package wayfhybrid

import (
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/gosaml"
	"github.com/y0ssar1an/q"
	"io"
	"regexp"
	"strconv"
	"strings"
)

type (
	attributeDescription struct {
		basic      string
		name       string
		nameformat string
		op        string
	}

	attributeKey struct {
		name, nameFormat string
	}

	attributeDescriptionsMap      map[attributeKey]attributeDescription
	attributeDescriptionsListtype map[string][]attributeDescription
)

var (
	_ = q.Q

	attributeDescriptionBase = []attributeDescription{
		{basic: "Issuer", nameformat: "internal", op: "xp:msg:./saml:Issuer"},

		// nemlogin computed
		{basic: "nemlogin", nameformat: "internal", op: "eq:Issuer:https://saml.nemlog-in.dk"},
		{basic: "eduPersonPrimaryAffiliation", name: "eduPersonPrimaryAffiliation", nameformat: "internal", op: "nemlogin:val:member"},
		{basic: "organizationName", nameformat: "internal", op: "nemlogin:val:NemLog-in"},
		{basic: "schacPersonalUniqueID", name: "schacPersonalUniqueID", nameformat: "internal", op: "nemlogin:prefix:urn:mace:terena.org:schac:personalUniqueID:dk:CPR:"},
		{basic: "eduPersonPrincipalName", name: "eduPersonPrincipalName", nameformat: "internal", op: "nemlogin:postfix:@sikker-adgang.dk"},

		// computed
		{basic: "hub", nameformat: "internal", op: "eq:Issuer:https://wayf.wayf.dk"},
		{basic: "persistent", nameformat: "internal", op: "persistent:"},
		{basic: "displayName", nameformat: "internal", op: "displayname:"},
		{basic: "eduPersonTargetedID", nameformat: "internal", op: "eptid:"},
		{basic: "gn", nameformat: "internal", op: "gn:"},
		{basic: "schacHomeOrganization", nameformat: "internal", op: "xp:idp://wayf:wayf_schacHomeOrganization"},
		{basic: "schacHomeOrganizationType", nameformat: "internal", op: "xp:idp://wayf:wayf_schacHomeOrganizationType"},
		{basic: "sn", nameformat: "internal", op: "sn:"},
		{basic: "pairwise-id", name: "pairwise-id", nameformat: "internal", op: "pairwise-id:"},
		{basic: "schacPersonalUniqueID", nameformat: "internal", op: "cpr:"},
		{basic: "eduPersonAffiliation", nameformat: "internal", op: "epa:"},
		{basic: "securitydomain", nameformat: "internal", op: "securitydomain:ku.dk:aau.dk@aau.dk"},
		{basic: "subsecuritydomain", nameformat: "internal", op: "subsecuritydomain:"},
		{basic: "eduPersonScopedAffiliation", nameformat: "internal", op: "epsa:"},
		{basic: "AuthnContextClassRef", nameformat: "internal", op: "xp:msg://saml:AuthnContextClassRef"},
		{basic: "idpID", nameformat: "internal", op: "xp:idp:@entityID"},
		{basic: "spID", nameformat: "internal", op: "xp:sp:@entityID"},
		{basic: "idpfeds", nameformat: "internal", op: "xp:idp://wayf:wayf/wayf:feds"},
		{basic: "spfeds", nameformat: "internal", op: "xp:sp://wayf:wayf/wayf:feds"},
		{basic: "commonfederations", nameformat: "internal", op: "commonfederations:"},
		{basic: "oioCvrNumberIdentifier", nameformat: "internal", op: "xp:idp://wayf:wayf/wayf:oioCvrNumberIdentifier"},
		{basic: "nameID", nameformat: "internal", op: "nameid:"},

        // from a request
		{basic: "idpfeds", nameformat: "request", op: "xp:idp://wayf:wayf/wayf:feds"},
		{basic: "spfeds", nameformat: "request", op: "xp:sp://wayf:wayf/wayf:feds"},
		{basic: "Issuer", nameformat: "request", op: "xp:msg:./saml:Issuer"},
		{basic: "hub", nameformat: "request", op: "eq:Issuer:https://wayf.wayf.dk"},
		{basic: "AssertionConsumerServiceURL", nameformat: "request", op: "xp:msg:./@AssertionConsumerServiceURL"},
		{basic: "RequesterID", nameformat: "request", op: "xp:msg:./samlp:Scoping/samlp:RequesterID"},
		{basic: "commonfederations", nameformat: "request", op: "commonfederations:"},

		// nemlogin specials
		{basic: "schacPersonalUniqueID", name: "dk:gov:saml:attribute:CprNumberIdentifier", nameformat: "basic"},
		{basic: "eduPersonPrincipalName", name: "urn:oid:0.9.2342.19200300.100.1.1", nameformat: "basic"},

		// wayf
		{basic: "cn", name: "cn", nameformat: "basic"},
		{basic: "cn", name: "cn", nameformat: "claims2005"},
		{basic: "cn", name: "urn:oid:2.5.4.3", nameformat: "uri"},
		{basic: "cn", name: "urn:oid:2.5.4.3", nameformat: "basic"},
		{basic: "displayName", name: "displayName", nameformat: "basic"},
		{basic: "displayName", name: "displayName", nameformat: "claims2005"},
		{basic: "displayName", name: "urn:oid:2.16.840.1.113730.3.1.241", nameformat: "uri"},
		{basic: "eduPersonAffiliation", name: "eduPersonAffiliation", nameformat: "basic"},
		{basic: "eduPersonAffiliation", name: "eduPersonAffiliation", nameformat: "claims2005"},
		{basic: "eduPersonAffiliation", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.1", nameformat: "uri"},
		{basic: "eduPersonAssurance", name: "dk:gov:saml:attribute:AssuranceLevel", nameformat: "basic"},
		{basic: "eduPersonAssurance", name: "eduPersonAssurance", nameformat: "basic"},
		{basic: "eduPersonAssurance", name: "eduPersonAssurance", nameformat: "claims2005"},
		{basic: "eduPersonAssurance", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.11", nameformat: "uri"},
		{basic: "eduPersonEntitlement", name: "eduPersonEntitlement", nameformat: "basic"},
		{basic: "eduPersonEntitlement", name: "eduPersonEntitlement", nameformat: "claims2005"},
		{basic: "eduPersonEntitlement", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.7", nameformat: "uri"},
		{basic: "eduPersonPrimaryAffiliation", name: "eduPersonPrimaryAffiliation", nameformat: "basic"},
		{basic: "eduPersonPrimaryAffiliation", name: "eduPersonPrimaryAffiliation", nameformat: "claims2005"},
		{basic: "eduPersonPrimaryAffiliation", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.5", nameformat: "uri"},
		{basic: "eduPersonPrincipalName", name: "eduPersonPrincipalName", nameformat: "basic"},
		{basic: "eduPersonPrincipalName", name: "eduPersonPrincipalName", nameformat: "claims2005"},
		{basic: "eduPersonPrincipalName", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.6", nameformat: "uri"},
		{basic: "eduPersonScopedAffiliation", name: "eduPersonScopedAffiliation", nameformat: "basic"},
		{basic: "eduPersonScopedAffiliation", name: "eduPersonScopedAffiliation", nameformat: "claims2005"},
		{basic: "eduPersonScopedAffiliation", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.9", nameformat: "uri"},
		{basic: "eduPersonTargetedID", name: "eduPersonTargetedID", nameformat: "basic"},
		{basic: "eduPersonTargetedID", name: "eduPersonTargetedID", nameformat: "claims2005"},
		{basic: "eduPersonTargetedID", name: "urn:oid:1.3.6.1.4.1.5923.1.1.1.10", nameformat: "uri"},
		{basic: "gn", name: "givenname", nameformat: "claims2005"},
		{basic: "gn", name: "gn", nameformat: "basic"},
		{basic: "gn", name: "urn:oid:2.5.4.42", nameformat: "uri"},
		{basic: "isMemberOf", name: "isMemberOf", nameformat: "basic"},
		{basic: "isMemberOf", name: "urn:oid:1.3.6.1.4.1.5923.1.5.1.1", nameformat: "uri"},
		{basic: "isMemberOf", name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", nameformat: "claims2005"},
		{basic: "mail", name: "emailaddress", nameformat: "claims2005"},
		{basic: "mail", name: "mail", nameformat: "basic"},
		{basic: "mail", name: "urn:oid:0.9.2342.19200300.100.1.3", nameformat: "uri"},
		{basic: "mobile", name: "mobile", nameformat: "basic"},
		{basic: "mobile", name: "urn:oid:0.9.2342.19200300.100.1.41", nameformat: "uri"},
		{basic: "mobile", name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/mobilephone", nameformat: "claims2005"},
		{basic: "norEduPersonLIN", name: "norEduPersonLIN", nameformat: "basic"},
		{basic: "norEduPersonLIN", name: "norEduPersonLIN", nameformat: "claims2005"},
		{basic: "norEduPersonLIN", name: "urn:oid:1.3.6.1.4.1.2428.90.1.4", nameformat: "uri"},
		{basic: "organizationName", name: "organizationName", nameformat: "basic"},
		{basic: "organizationName", name: "organizationName", nameformat: "claims2005"},
		{basic: "organizationName", name: "urn:oid:2.5.4.10", nameformat: "uri"},
		{basic: "preferredLanguage", name: "preferredLanguage", nameformat: "basic"},
		{basic: "preferredLanguage", name: "preferredLanguage", nameformat: "claims2005"},
		{basic: "preferredLanguage", name: "urn:oid:2.16.840.1.113730.3.1.39", nameformat: "uri"},
		{basic: "schacCountryOfCitizenship", name: "schacCountryOfCitizenship", nameformat: "basic"},
		{basic: "schacCountryOfCitizenship", name: "schacCountryOfCitizenship", nameformat: "claims2005"},
		{basic: "schacCountryOfCitizenship", name: "urn:oid:1.3.6.1.4.1.25178.1.2.5", nameformat: "uri"},
		{basic: "schacDateOfBirth", name: "schacDateOfBirth", nameformat: "basic"},
		{basic: "schacDateOfBirth", name: "schacDateOfBirth", nameformat: "claims2005"},
		{basic: "schacDateOfBirth", name: "urn:oid:1.3.6.1.4.1.25178.1.2.3", nameformat: "uri"},
		{basic: "schacHomeOrganization", name: "schacHomeOrganization", nameformat: "basic"},
		{basic: "schacHomeOrganization", name: "schacHomeOrganization", nameformat: "claims2005"},
		{basic: "schacHomeOrganization", name: "urn:oid:1.3.6.1.4.1.25178.1.2.9", nameformat: "uri"},
		{basic: "schacHomeOrganizationType", name: "schacHomeOrganizationType", nameformat: "basic"},
		{basic: "schacHomeOrganizationType", name: "schacHomeOrganizationType", nameformat: "claims2005"},
		{basic: "schacHomeOrganizationType", name: "urn:oid:1.3.6.1.4.1.25178.1.2.10", nameformat: "uri"},
		{basic: "schacPersonalUniqueID", name: "schacPersonalUniqueID", nameformat: "basic"},
		{basic: "schacPersonalUniqueID", name: "schacPersonalUniqueID", nameformat: "claims2005"},
		{basic: "schacPersonalUniqueID", name: "urn:oid:1.3.6.1.4.1.25178.1.2.15", nameformat: "uri"},
		{basic: "schacYearOfBirth", name: "schacYearOfBirth", nameformat: "basic"},
		{basic: "schacYearOfBirth", name: "schacYearOfBirth", nameformat: "claims2005"},
		{basic: "schacYearOfBirth", name: "urn:oid:1.3.6.1.4.1.25178.1.0.2.3", nameformat: "uri"},
		{basic: "sn", name: "sn", nameformat: "basic"},
		{basic: "sn", name: "surname", nameformat: "claims2005"},
		{basic: "sn", name: "urn:oid:2.5.4.4", nameformat: "uri"},
		{basic: "subject-id", name: "urn:oasis:names:tc:SAML:attribute:subject-id", nameformat: "uri"},
		{basic: "subject-id", name: "subject-id", nameformat: "basic"},
		{basic: "pairwise-id", name: "urn:oasis:names:tc:SAML:attribute:pairwise-id", nameformat: "uri"},
		{basic: "role", name: "http://schemas.microsoft.com/ws/2008/06/identity/claims/role", nameformat: "claims2008"},
		{basic: "role", name: "role", nameformat: "basic"},
		{basic: "immutableID", name: "immutableID", nameformat: "basic"},

		// Modst specials
		{basic: "eduPersonPrincipalName", name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name", nameformat: "modst"},
		{basic: "oioCvrNumberIdentifier", name: "https://modst.dk/sso/claims/cvr", nameformat: "modst"},
		{basic: "eduPersonPrincipalName", name: "https://modst.dk/sso/claims/userid", nameformat: "modst"},
		{basic: "mail", name: "https://modst.dk/sso/claims/email", nameformat: "modst"},
		{basic: "eduPersonPrincipalName", name: "https://modst.dk/sso/claims/uniqueid", nameformat: "modst"},
		{basic: "mobile", name: "https://modst.dk/sso/claims/mobile", nameformat: "modst"},
		{basic: "eduPersonAssurance", name: "https://modst.dk/sso/claims/assurancelevel", nameformat: "modst"},
		{basic: "modstlogonmethod", name: "https://modst.dk/sso/claims/logonmethod", nameformat: "modst", op:"eq:username-password-protected-transport"},
		{basic: "sn", name: "https://modst.dk/sso/claims/surname", nameformat: "modst"},
		{basic: "gn", name: "https://modst.dk/sso/claims/givenname", nameformat: "modst"},
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

	AttributeDescriptions     = attributeDescriptionsMap{}
	AttributeDescriptionsList = attributeDescriptionsListtype{}
)

func init() {
	for _, ad := range attributeDescriptionBase {
		AttributeDescriptions[attributeKey{ad.name, attributenameFormats[ad.nameformat]}] = ad
        // we also need it in a name only format for being liberal in what we accept ...
		AttributeDescriptions[attributeKey{ad.name, ""}] = ad
		AttributeDescriptionsList[ad.nameformat] = append(AttributeDescriptionsList[ad.nameformat], ad)
	}
}

func Attributesc14n(request, response, idpMd, spMd *goxml.Xp) {
	base64encoded := idpMd.QueryXMLBool(nil, xprefix+"base64attributes")
	attributeStatement := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement[1]`)[0]
	sourceAttributes := response.Query(attributeStatement, `./saml:Attribute`)
	values := map[string][]string{}
	atds := []attributeDescription{}

	for _, attribute := range sourceAttributes {
		name := response.Query1(attribute, "@Name")
		nameFormat := response.Query1(attribute, "@NameFormat")
		if nameFormat == "" {
			nameFormat = attributenameFormats["basic"]
		}

		atd, ok := AttributeDescriptions[attributeKey{name, nameFormat}]
		if !ok {
    		atd, ok = AttributeDescriptions[attributeKey{name, ""}]
		}
		if ok {
			atds = append(atds, atd)
			values[atd.basic] = response.QueryMulti(attribute, `saml:AttributeValue`)
			if base64encoded {
				for i, val := range values[atd.basic] {
					v, _ := base64.StdEncoding.DecodeString(val)
					values[atd.basic][i] = string(v)
				}
			}
		}
	}

	attributeOpsHandler(values, atds, request, response, idpMd, spMd)
	attributeOpsHandler(values, AttributeDescriptionsList["internal"], request, response, idpMd, spMd)

	c14nAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[2]`, "", nil)

	for basic, vals := range values {
		attr := response.QueryDashP(c14nAttributes, `saml:Attribute[@Name="`+basic+`"]`, "", nil)
		seen := map[string]bool{}
		for _, val := range vals {
			if seen[val] || val == "" {
				continue
			}
			response.QueryDashP(attr, "saml:AttributeValue[0]", val, nil)
			seen[val] = true
		}
	}
	goxml.RmElement(attributeStatement)
}

func RequestHandler(request, idpMd, spMd *goxml.Xp) (values map[string][]string, err error){
	values = map[string][]string{}
	attributeOpsHandler(values, AttributeDescriptionsList["request"], request, request, idpMd, spMd)
	if values["commonfederations"][0] != "true" {
    	err = fmt.Errorf("no common federations")
    }
	return
}

func attributeOpsHandler(values map[string][]string, atds []attributeDescription, request, msg, idpMd, spMd *goxml.Xp) {
	for _, atd := range atds {
			opParam := strings.SplitN(atd.op, ":", 2)
			if len(values[atd.basic]) == 0 {
				values[atd.basic] = []string{""}
			}
			v := &values[atd.basic][0]
		handleop:
			switch opParam[0] {
			case "eq":
			    opParam = strings.SplitN(opParam[1], ":", 2)
				*v = strconv.FormatBool(values[opParam[0]][0] == opParam[1])
			case "val":
				*v = opParam[1]
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
					*v =  names[len(names)-1]
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
				values[atd.basic] = map[string]*goxml.Xp{"idp": idpMd, "sp": spMd, "msg": msg}[opParam[0]].QueryMulti(nil, opParam[1])
			case "securitydomain":
				eppns := values["eduPersonPrincipalName"]
				if len(eppns) > 0 {
					matches := scoped.FindStringSubmatch(eppns[0])
					if len(matches) > 1 {
						*v = matches[1] + matches[2]
						subsecuritydomain := *v
						for _, specialdomain := range strings.Split(opParam[1], ":") {
							if strings.HasSuffix(*v, "."+specialdomain) {
							subsecuritydomain =	specialdomain
								break
							}
						}
						values["subsecuritydomain"] = []string{subsecuritydomain}
					}
				}
			case "subsecuritydomain":
				if *v == "" {
					epsas := values["eduPersonScopedAffiliation"]
					if len(epsas) > 0 {
						matches := scoped.FindStringSubmatch(epsas[0])
						if len(matches) > 1 {
							*v = matches[1] + matches[2]
						}
					}
				}
			case "eptid":
				*v = eptid(idpMd, spMd, values)
			case "cpr":
				cpr(idpMd, spMd, values)
			case "epa":
			    // get rid of the optional default ""
			    if values[atd.basic][0] == "" {
			        values[atd.basic] = values[atd.basic][1:]
			    }
				values[atd.basic] = append(values[atd.basic], values["eduPersonPrimaryAffiliation"]...)
				if intersectionNotEmpty(values[atd.basic], []string{"student", "faculty", "staff", "employee"}) {
					values[atd.basic] = append(values[atd.basic], "member")
				}
			case "epsa":
			    if values[atd.basic][0] == "" {
			        values[atd.basic] = values[atd.basic][1:]
			    }
				for _, epa := range values["eduPersonAffiliation"] {
					if epa == "" {
						continue
					}
					values[atd.basic] = append(values[atd.basic], epa+"@"+values["securitydomain"][0])
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
                        *v = gosaml.Id()
                }
                switch attr := spMd.Query1(nil, xprefix+"nameIDAttribute"); {
                    case attr == "":
                    default:
                        *v = values[attr][0]
                }
            }
	}
}

func eptid(idpMd, spMd *goxml.Xp, values map[string][]string) string {
	var idp, sp, epid string

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

	if matches[2] == "" && aauscope.MatchString(matches[1]) { // legacy support for old @aau.dk scopes for persistent nameid and eptid
		epid += "@aau.dk"
	}

	if idp = idpMd.Query1(nil, xprefix+"persistentEntityID"); idp == "" {
		idp = idpMd.Query1(nil, "@entityID")
	}
	if sp = spMd.Query1(nil, xprefix+"persistentEntityID"); sp == "" {
		sp = spMd.Query1(nil, "@entityID")
	}

	idp = debify.ReplaceAllString(idp, "$1$2")

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


// CopyAttributes copies the attributes
func CopyAttributes(sourceResponse, response, spMd *goxml.Xp) (ardValues map[string][]string, ardHash string) {
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

	h := sha1.New()
	for _, requestedAttribute := range requestedAttributes {
		name := spMd.Query1(requestedAttribute, "@Name")
		nameFormat := spMd.Query1(requestedAttribute, "@NameFormat")

		atd, ok := AttributeDescriptions[attributeKey{name, nameFormat}]

		if !ok {
			continue
		}

		values := sourceResponse.QueryMulti(nil, `//saml:AttributeStatement/saml:Attribute[@Name="`+atd.basic+`"]/saml:AttributeValue`)
		values = filterValues(values, spMd.Query(requestedAttribute, `saml:AttributeValue`))

		if len(values) == 0 {
			continue
		}

		io.WriteString(h, atd.basic)

		newAttribute := response.QueryDashP(destinationAttributes, saml+":Attribute[0]/@"+nameName, atd.name, nil)
		response.QueryDashP(newAttribute, "@"+nameFormatName, attributenameFormats[atd.nameformat], nil)
		response.QueryDashP(newAttribute, "@FriendlyName", atd.basic, nil)

		for _, value := range values {
            io.WriteString(h, value)
            ardValues[atd.basic] = append(ardValues[atd.basic], value)
            if base64encodedOut {
                v := base64.StdEncoding.EncodeToString([]byte(value))
                value = string(v)
            }
            response.QueryDashP(newAttribute, saml+":AttributeValue[0]", value, nil)
		}
	}

	io.WriteString(h, spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]`))
	io.WriteString(h, spMd.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="da"]`))
	ardHash = fmt.Sprintf("%x", h.Sum(nil))
	return
}

func filterValues(values []string, allowedValues types.NodeList) (filteredValues []string) {
    regexps := []*regexp.Regexp{}
    for _, attr := range allowedValues {
        tp := ""
        tpAttribute, _ := attr.(types.Element).GetAttribute("type")
        if tpAttribute != nil {
            tp = tpAttribute.Value()
        }
        val := attr.NodeValue()
        var reg string
        switch tp {
        case "prefix":
            reg = "^" + regexp.QuoteMeta(val)
        case "postfix":
            reg = regexp.QuoteMeta(val) + "$"
        case "wildcard":
            reg = "^" + strings.Replace(regexp.QuoteMeta(val), "\\*", ".*", -1) + "$"
        case "regexp":
            reg = val
        default:
            reg = "^" + regexp.QuoteMeta(val) + "$"
        }
        regexps = append(regexps, regexp.MustCompile(reg))
    }

    for _, value := range values {
        if len(allowedValues) == 0 || matchRegexpArray(value, regexps) {
            filteredValues = append(filteredValues, value)
        }
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
