package wayfhybrid

import (
	"crypto"
	//"database/sql"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	//"github.com/mattn/go-sqlite3"
	toml "github.com/pelletier/go-toml"
	"github.com/wayf-dk/go-libxml2/types"
	"github.com/wayf-dk/godiscoveryservice"
	"github.com/wayf-dk/gohybrid"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type (
	appHandler func(http.ResponseWriter, *http.Request) error

	md struct {
		entities map[string]*goxml.Xp
	}

	mddb struct {
		db, table string
	}

	metadata struct {
		Hub, Internal, External string
	}

	tomlConfig struct {
		Hybrid                                                                                                                                                          gohybrid.Conf
		Metadata                                                                                                                                                        metadata
		Intf, Hubrequestedattributes, Sso_Service, Https_Key, Https_Cert, Acs, Birk, Krib, Dsbackend, Dstiming, Public, Discopublicpath, Discometadata, Discospmetadata string
		Testsp, Testsp_Acs, Nemlogin_Acs, Certpath, SamlSchema                                                                                                          string
	}

	idpsppair struct {
		idp string
		sp  string
	}
)

var (
	config                                                          tomlConfig
	certpath, samlSchema, postformtemplate, hubfrequestedattributes string
	hub, external, internal                                         md // mddb
	idp_md, idp_md_birk, sp_md, sp_md_krib, hub_md                  *goxml.Xp
	stdtiming                                                       = gosaml.IdAndTiming{time.Now(), 4 * time.Minute, 4 * time.Hour, "", ""}
	basic2uri                                                       map[string]string
	remap                                                           = map[string]idpsppair{
		//		"https://nemlogin.wayf.dk": idpsppair{"https://saml.nemlog-in.dk", "https://nemlogin.wayf.dk"},
		"https://nemlogin.wayf.dk": idpsppair{"https://saml.test-nemlog-in.dk/", "https://saml.nemlogin.wayf.dk"},
	}

	bify   = regexp.MustCompile("^(https?://)(.*)$")
	debify = regexp.MustCompile("^(https?://)(?:(?:birk|krib)\\.wayf.dk/(?:birk|krib)\\.php/)(.+)$")
)

func Main() {
	theConfig, err := toml.LoadFile("../hybrid-config/hybrid-config.toml")

	if err != nil { // Handle errors reading the config file
		panic(fmt.Errorf("Fatal error config file: %s \n", err))
	}

	config = tomlConfig{}
	theConfig.Unmarshal(&config)

	//elementsToSign := []string{"/samlp:Response/saml:Assertion"}

	hub = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.Hub, &hub)
	internal = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.Internal, &internal)
	external = md{entities: make(map[string]*goxml.Xp)}
	prepareMetadata(config.Metadata.External, &external)

	/*
		hub = mddb{db: "../hybrid-metadata-test.mddb", table: "WAYF_HUB_PUBLIC"}
		internal = mddb{db: "../hybrid-metadata.mddb", table: "HYBRID_INTERNAL"}
		external = mddb{db: "../hybrid-metadata-test.mddb", table: "HYBRID_EXTERNAL"}
	*/

	attrs := goxml.NewXp(config.Hubrequestedattributes)
	prepareTables(attrs)

	config.Hybrid.HubRequestedAttributes = attrs
	config.Hybrid.Internal = internal
	config.Hybrid.External = external
	config.Hybrid.Hub = hub
	config.Hybrid.Basic2uri = basic2uri
	config.Hybrid.StdTiming = stdtiming
	config.Hybrid.ElementsToSign = []string{"/samlp:Response/saml:Assertion"}
	config.Hybrid.SSOServiceHandler = WayfSSOServiceHandler
	config.Hybrid.BirkHandler = WayfBirkHandler
	config.Hybrid.AttributeHandler = WayfAttributeHandler

	gohybrid.Config(config.Hybrid)

	godiscoveryservice.Config = godiscoveryservice.Conf{
		DiscoMetaData: config.Discometadata,
		SpMetaData:    config.Discospmetadata,
	}

	gosaml.Config = gosaml.Conf{
		SamlSchema: config.SamlSchema,
	}

	//http.HandleFunc("/status", statushandler)
	//http.Handle(config["hybrid_public_prefix"], http.FileServer(http.Dir(config["hybrid_public"])))
	http.Handle(config.Sso_Service, appHandler(gohybrid.SsoService))
	http.Handle(config.Acs, appHandler(gohybrid.AcsService))
	http.Handle(config.Nemlogin_Acs, appHandler(gohybrid.AcsService))
	http.Handle(config.Birk, appHandler(gohybrid.BirkService))
	http.Handle(config.Krib, appHandler(gohybrid.KribService))
	http.Handle(config.Dsbackend, appHandler(godiscoveryservice.DSBackend))
	http.Handle(config.Dstiming, appHandler(godiscoveryservice.DSTiming))
	http.Handle(config.Public, http.FileServer(http.Dir(config.Discopublicpath)))

	http.Handle(config.Testsp_Acs, appHandler(testSPACService))
	http.Handle(config.Testsp+"/", appHandler(testSPService)) // need a root "/" for routing
	http.Handle(config.Testsp+"/favicon.ico", http.NotFoundHandler())

	log.Println("listening on ", config.Intf)
	err = http.ListenAndServeTLS(config.Intf, config.Https_Cert, config.Https_Key, nil)
	if err != nil {
		log.Printf("main(): %s\n", err)
	}
}

func prepareTables(attrs *goxml.Xp) {
	basic2uri = make(map[string]string)
	for _, attr := range attrs.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute") {
		friendlyName, _ := attr.(types.Element).GetAttribute("FriendlyName")
		name, _ := attr.(types.Element).GetAttribute("Name")
		basic2uri[friendlyName.NodeValue()] = name.NodeValue()
	}
}

func prepareMetadata(metadata string, index *md) {
	indextargets := []string{
		"./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location",
		"./md:SPSSODescriptor/md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
	}

	x := goxml.NewXp(metadata)
	entities := x.Query(nil, "md:EntityDescriptor")

	for _, entity := range entities {
		newentity := goxml.NewXpFromNode(entity)
		entityID, _ := entity.(types.Element).GetAttribute("entityID")
		index.entities[entityID.Value()] = newentity
		for _, target := range indextargets {
			locations := newentity.Query(nil, target)
			for _, location := range locations {
				index.entities[location.NodeValue()] = newentity
			}
		}
	}
}

func (m md) MDQ(key string) (xp *goxml.Xp, err error) {
	xp = m.entities[key]
	if xp == nil {
		log.Panicf("Not found: " + key)
		//err = fmt.Errorf("Not found: " + key)
	}
	return
}

/*
func (m mddb) MDQ(key string) (xp *goxml.Xp, err error) {
	db, err := sql.Open("sqlite3", m.db)
	if err != nil {
		return
	}
	defer db.Close()
	ent := hex.EncodeToString(goxml.Hash(crypto.SHA1, key))
	var md string
	var query = "select e.md md from entity_" + m.table + " e, lookup_" + m.table + " l where l.hash = ? and l.entity_id_fk = e.id"
	err = db.QueryRow(query, ent).Scan(&md)
	if err != nil {
		return
	}
	md = string(gosaml.Inflate([]byte(md)))
	xp = goxml.NewXp(md)
	return
}

func (m mddb) Open(db, table string) (err error) {
	m.db = db
	m.table = table
	return
}
*/

func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	/*	ctx := make(map[string]string)
		contextmutex.Lock()
		context[r] = ctx
		contextmutex.Unlock()
		w.Header().Set("content-Security-Policy", "referrer no-referrer;")
	*/
	starttime := time.Now()
	err := fn(w, r)

	status := 200
	if err != nil {
		status = 500
		http.Error(w, err.Error(), status)
	} else {
		err = fmt.Errorf("OK")
	}

	log.Printf("%s %s %s %+v %1.3f %d %s", r.RemoteAddr, r.Method, r.Host, r.URL, time.Since(starttime).Seconds(), status, err)

	/*	contextmutex.Lock()
		delete(context, r)
		contextmutex.Unlock()
	*/
}

func testSPService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	sp_md, _ := internal.MDQ("https://" + config.Testsp)
	hub_md, _ := hub.MDQ(config.Hybrid.HubEntityID)
	newrequest := gosaml.NewAuthnRequest(stdtiming.Refresh(), sp_md, hub_md)
	u, _ := gosaml.SAMLRequest2Url(newrequest, "anton-banton", "", "", "") // not signed so blank key, pw and algo
	q := u.Query()
	//q.Set("idpentityid", "https://birk.wayf.dk/birk.php/nemlogin.wayf.dk")
	//q.Set("idpentityid", "https://birk.wayf.dk/birk.php/idp.testshib.org/idp/shibboleth")
	//q.Set("idpentityid", "https://birk.wayf.dk/birk.php/wayf.ait.dtu.dk/saml2/idp/metadata.php")
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
	return
}

func testSPACService(w http.ResponseWriter, r *http.Request) (err error) {
	defer r.Body.Close()
	response, _, _, relayState, err := gosaml.ReceiveSAMLResponse(r, hub, internal)
	if err != nil {
		log.Println(err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8") // normal header
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("RelayState: " + relayState + "\n"))
	w.Write([]byte(response.PP()))
	//log.Println(response.Doc.Dump(true))
	return
}

func checkForCommonFederations(idp_md, sp_md *goxml.Xp) (err error) {
	idpFeds := idp_md.QueryMulti(nil, "/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:federation")
	tmp := idpFeds[:0]
	for _, federation := range idpFeds {
		tmp = append(tmp, strings.TrimSpace(federation))
	}
	idpFedsQuery := strings.Join(idpFeds, "\" or .=\"")
	commonFeds := sp_md.QueryMulti(nil, `/md:EntityDescriptor/md:Extensions/wayf:wayf/wayf:federation[.="`+idpFedsQuery+`"]`)
	if len(commonFeds) == 0 {
		err = fmt.Errorf("no common federations")
		return
	}
	return
}

func WayfSSOServiceHandler(request, mdsp, mdhub, mdidp *goxml.Xp) (kribID, acsurl string, err error) {
	entityID := mdsp.Query1(nil, "@entityID")

	kribID = bify.ReplaceAllString(entityID, "${1}krib.wayf.dk/krib.php/$2")
	if kribID == entityID {
		kribID = "urn:oid:1.3.6.1.4.1.39153:42:" + entityID
	}

	acs := request.Query1(nil, "@AssertionConsumerServiceURL")
	acsurl = bify.ReplaceAllString(acs, "${1}krib.wayf.dk/krib.php/$2")

	if err = checkForCommonFederations(mdidp, mdsp); err != nil {
		return
	}
	return
}

func WayfBirkHandler(request, mdsp, mdbirkidp *goxml.Xp) (mdhub, mdidp *goxml.Xp, err error) {
	idp := debify.ReplaceAllString(mdbirkidp.Query1(nil, "@entityID"), "$1$2")

	if rm, ok := remap[idp]; ok {
		mdidp, err = internal.MDQ(rm.idp)
		if err != nil {
			return
		}
		mdhub, err = hub.MDQ(rm.sp)
		if err != nil {
			return
		}
	} else {
		mdidp, err = internal.MDQ(idp)
		if err != nil {
			return
		}
		mdhub, err = hub.MDQ(config.Hybrid.HubEntityID)
		if err != nil {
			return
		}
	}
	if err = checkForCommonFederations(mdidp, mdsp); err != nil {
		return
	}

	return
}

func WayfAttributeHandler(idp_md, hub_md, sp_md, response *goxml.Xp) (ard gohybrid.AttributeReleaseData, err error) {
	ard = gohybrid.AttributeReleaseData{Values: make(map[string][]string), IdPDisplayName: make(map[string]string), SPDisplayName: make(map[string]string), SPDescription: make(map[string]string)}
	idp := response.Query1(nil, "/samlp:Response/saml:Issuer")

	if idp == "https://saml.nemlog-in.dk" || idp == "https://saml.test-nemlog-in.dk/" {
		nemloginAttributeHandler(response)
	}

	if err = checkForCommonFederations(idp_md, sp_md); err != nil {
		return
	}

	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement[1]`)[0]
	destinationAttributes := response.QueryDashP(nil, `/saml:Assertion/saml:AttributeStatement[2]`, "", nil)

	base64encoded := idp_md.Query1(nil, "//wayf:base64attributes") == "1"

	attCS := hub_md.Query(nil, "./md:SPSSODescriptor/md:AttributeConsumingService")[0]

	// First check for required and multiplicity
	requestedAttributes := hub_md.Query(attCS, `md:RequestedAttribute[not(@computed)]`) // [@isRequired='true' or @isRequired='1']`)
	for _, requestedAttribute := range requestedAttributes {
		node, _ := requestedAttribute.(types.Element).GetAttribute("Name")
		name := node.NodeValue()
		node, _ = requestedAttribute.(types.Element).GetAttribute("FriendlyName")
		friendlyName := node.NodeValue()
		//nameFormat := requestedAttribute.GetAttr("NameFormat")
		isRequired := hub_md.QueryBool(requestedAttribute.(types.Element), "@isRequired")
		//must := hub_md.QueryBool(requestedAttribute, "@must")
		singular := hub_md.QueryBool(requestedAttribute.(types.Element), "@singular")

		// accept attributes in both uri and basic format
		attributesValues := response.Query(sourceAttributes, `saml:Attribute[@Name="`+name+`" or @Name="`+friendlyName+`"]/saml:AttributeValue`)
		if len(attributesValues) == 0 && isRequired {
			err = fmt.Errorf("isRequired: %s", friendlyName)
			return
		}
		if len(attributesValues) > 1 && singular {
			err = fmt.Errorf("multiple values for singular attribute: %s", name)
			return
		}
		if len(attributesValues) == 0 {
			continue
		}
		attr := response.QueryDashP(destinationAttributes, `saml:Attribute[@Name="`+name+`"]`, "", nil)
		attr.(types.Element).SetAttribute("FriendlyName", friendlyName)
		attr.(types.Element).SetAttribute("NameFormat", gosaml.Uri)

		index := 1
		for _, node := range attributesValues {
			value := node.NodeValue()
			if base64encoded {
				v, _ := base64.StdEncoding.DecodeString(value)
				value = string(v)
			}
			response.QueryDashP(attr, "saml:AttributeValue["+strconv.Itoa(index)+"]", value, nil)
			index++
		}
	}

	parent, _ := sourceAttributes.ParentNode()
	parent.RemoveChild(sourceAttributes)

	// check that the security domain of eppn is one of the domains in the shib:scope list
	// we just check that everything after the (leftmost|rightmost) @ is in the scope list and save the value for later
	eppn := response.Query1(destinationAttributes, "saml:Attribute[@Name='urn:oid:1.3.6.1.4.1.5923.1.1.1.6']/saml:AttributeValue")
	eppnregexp := regexp.MustCompile(`^[^\@]+\@([a-zA-Z0-9\.-]+)$`)
	matches := eppnregexp.FindStringSubmatch(eppn)
	if len(matches) != 2 {
		err = fmt.Errorf("eppn does not seem to be an eppn: %s", eppn)
		return
	}

	securitydomain := matches[1]

	scope := idp_md.Query(nil, "//shibmd:Scope[.='"+securitydomain+"']")
	if len(scope) == 0 {
		err = fmt.Errorf("security domain '%s' for eppn does not match any scopes", securitydomain)
		return
	}

	val := idp_md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganizationType")
	setAttribute("schacHomeOrganizationType", val, response, destinationAttributes)

	val = idp_md.Query1(nil, "./md:Extensions/wayf:wayf/wayf:wayf_schacHomeOrganization")
	setAttribute("schacHomeOrganization", val, response, destinationAttributes)

	if response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="displayName"]/saml:AttributeValue`) == "" {
		if cn := response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="cn"]/saml:AttributeValue`); cn != "" {
			setAttribute("displayName", cn, response, destinationAttributes)
		}
	}

	// Use kribified?, use birkified?
	sp := sp_md.Query1(nil, "@entityID")

	uidhashbase := "uidhashbase" + config.Hybrid.EptidSalt
	uidhashbase += strconv.Itoa(len(idp)) + ":" + idp
	uidhashbase += strconv.Itoa(len(sp)) + ":" + sp
	uidhashbase += strconv.Itoa(len(eppn)) + ":" + eppn
	uidhashbase += config.Hybrid.EptidSalt
	eptid := "WAYF-DK-" + hex.EncodeToString(goxml.Hash(crypto.SHA1, uidhashbase))

	setAttribute("eduPersonTargetedID", eptid, response, destinationAttributes)

	dkcprpreg := regexp.MustCompile(`^urn:mace:terena.org:schac:personalUniqueID:dk:CPR:(\d\d)(\d\d)(\d\d)(\d)\d\d\d$`)
	for _, cprelement := range response.Query(destinationAttributes, `saml:Attribute[@FriendlyName="schacPersonalUniqueID"]`) {
		// schacPersonalUniqueID is multi - use the first DK cpr found
		cpr := strings.TrimSpace(cprelement.NodeValue())
		if matches := dkcprpreg.FindStringSubmatch(cpr); len(matches) > 0 {
			cpryear, _ := strconv.Atoi(matches[3])
			c7, _ := strconv.Atoi(matches[4])
			year := strconv.Itoa(yearfromyearandcifferseven(cpryear, c7))

			setAttribute("schacDateOfBirth", year+matches[2]+matches[1], response, destinationAttributes)
			setAttribute("schacYearOfBirth", year, response, destinationAttributes)
			break
		}
	}

	subsecuritydomain := "." + securitydomain
	epsas := make(map[string]bool)

	for _, epsa := range response.QueryMulti(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonScopedAffiliation"]/saml:AttributeValue`) {
		epsa = strings.TrimSpace(epsa)
		epsaparts := strings.SplitN(epsa, "@", 2)
		if len(epsaparts) != 2 {
			fmt.Errorf("eduPersonScopedAffiliation: %s does not end with a domain", epsa)
			return
		}
		if !strings.HasSuffix(epsaparts[1], subsecuritydomain) && epsaparts[1] != securitydomain {
			fmt.Printf("eduPersonScopedAffiliation: %s has not '%s' as a domain suffix", epsa, securitydomain)
			return
		}
		epsas[epsa] = true
	}

	// primaryaffiliation => affiliation
	epaAdd := []string{}
	eppa := response.Query1(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonPrimaryAffiliation"]`)
	eppa = strings.TrimSpace(eppa)
	epas := response.QueryMulti(destinationAttributes, `saml:Attribute[@FriendlyName="eduPersonAffiliation"]`)
	epaset := make(map[string]bool)
	for _, epa := range epas {
		epaset[strings.TrimSpace(epa)] = true
	}
	if !epaset[eppa] {
		epaAdd = append(epaAdd, eppa)
		epaset[eppa] = true
	}
	// 'student', 'faculty', 'staff', 'employee' => member
	if epaset["student"] || epaset["faculty"] || epaset["staff"] || epaset["employee"] {
		epaAdd = append(epaAdd, "member")
		epaset["member"] = true
	}
	newattribute, _ := hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonAffiliation"]`)[0].Copy()
	_ = destinationAttributes.AddChild(newattribute)
	for i, epa := range epaAdd {
		response.QueryDashP(newattribute, `saml:AttributeValue[`+strconv.Itoa(i+1)+`]`, epa, nil)
	}
	newattribute, _ = hub_md.Query(attCS, `md:RequestedAttribute[@FriendlyName="eduPersonScopedAffiliation"]`)[0].Copy()
	_ = destinationAttributes.AddChild(newattribute)
	i := 1
	for epa, _ := range epaset {
		if epsas[epa] {
			continue
		}
		response.QueryDashP(newattribute, `saml:AttributeValue[`+strconv.Itoa(i)+`]`, epa+"@"+securitydomain, nil)
		i += 1
	}
	// legal affiliations 'student', 'faculty', 'staff', 'affiliate', 'alum', 'employee', 'library-walk-in', 'member'
	// affiliations => scopedaffiliations

	// Fill out the info needed for AttributeReleaseData
	// to-do add value filtering
	arp := sp_md.QueryMulti(nil, "md:SPSSODescriptor/md:AttributeConsumingService/md:RequestedAttribute/@Name")
	arpmap := make(map[string]bool)
	for _, attrName := range arp {
		arpmap[attrName] = true
	}
	for _, attrNode := range response.Query(destinationAttributes, `saml:Attribute`) {
		friendlyName, _ := attrNode.(types.Element).GetAttribute("FriendlyName")
		name, _ := attrNode.(types.Element).GetAttribute("Name")
		if !arpmap[name.NodeValue()] {
			// the real ARP filtering is done i gosaml
			//attrStmt, _ := attrNode.ParentNode()
			//attrStmt.RemoveChild(attrNode)
			continue
		}
		for _, attrValue := range response.Query(attrNode, "saml:AttributeValue") {
			ard.Values[friendlyName.NodeValue()] = append(ard.Values[friendlyName.NodeValue()], attrValue.NodeValue())
		}
	}

	ard.IdPDisplayName["en"] = idp_md.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.IdPDisplayName["da"] = idp_md.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.IdPLogo = idp_md.Query1(nil, `md:IDPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.SPDisplayName["en"] = sp_md.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="en"]`)
	ard.SPDisplayName["da"] = sp_md.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:DisplayName[@xml:lang="da"]`)
	ard.SPDescription["en"] = sp_md.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="en"]`)
	ard.SPDescription["da"] = sp_md.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Description[@xml:lang="da"]`)
	ard.SPLogo = sp_md.Query1(nil, `md:SPSSODescriptor/md:Extensions/mdui:UIInfo/mdui:Logo`)
	ard.SPEntityID = sp_md.Query1(nil, "@entityID")
	ard.Key = eppn
	ard.Hash = eppn + ard.SPEntityID
	return
}

// 2408586234
func yearfromyearandcifferseven(year, c7 int) int {
	cpr2year := [][]int{
		{99, 1900},
		{99, 1900},
		{99, 1900},
		{99, 1900},
		{36, 2000, 1900},
		{36, 2000, 1900},
		{36, 2000, 1900},
		{36, 2000, 1900},
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

func nemloginAttributeHandler(response *goxml.Xp) {
	sourceAttributes := response.Query(nil, `/samlp:Response/saml:Assertion/saml:AttributeStatement`)[0].(types.Element)
	value := response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:2.5.4.3"]/saml:AttributeValue`)
	names := strings.Split(value, " ")
	l := len(names) - 1
	setAttribute("cn", value, response, sourceAttributes)
	setAttribute("gn", strings.Join(names[0:l], " "), response, sourceAttributes)
	setAttribute("sn", names[l], response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:0.9.2342.19200300.100.1.1"]/saml:AttributeValue`)
	setAttribute("eduPersonPrincipalName", value+"@sikker-adgang.dk", response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="urn:oid:0.9.2342.19200300.100.1.3"]/saml:AttributeValue`)
	setAttribute("mail", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:Attribute:AssuranceLevel"]/saml:AttributeValue`)
	setAttribute("eduPersonAssurance", value, response, sourceAttributes)
	value = response.Query1(sourceAttributes, `./saml:Attribute[@Name="dk:gov:saml:Attribute:CprNumberIdentifier"]/saml:AttributeValue`)
	setAttribute("schacPersonalUniqueID", "urn:mace:terena.org:schac:personalUniqueID:dk:CPR:"+value, response, sourceAttributes)
	setAttribute("eduPersonPrimaryAffiliation", "member", response, sourceAttributes)
	setAttribute("schacHomeOrganization", "http://sikker-adgang.dk", response, sourceAttributes)
	setAttribute("organizationName", "NemLogin", response, sourceAttributes)
}

func setAttribute(name, value string, response *goxml.Xp, element types.Node) {
	attr := response.QueryDashP(element.(types.Element), `/saml:Attribute[@Name="`+basic2uri[name]+`"]`, "", nil)
	response.QueryDashP(attr, `./@NameFormat`, gosaml.Uri, nil)
	response.QueryDashP(attr, `./@FriendlyName`, name, nil)
	values := len(response.Query(attr, `./saml:AttributeValue`)) + 1
	response.QueryDashP(attr, `./saml:AttributeValue[`+strconv.Itoa(values)+`]`, value, nil)
}

func b64ToString(enc string) string {
	dec, _ := base64.StdEncoding.DecodeString(enc)
	return string(dec)
}
