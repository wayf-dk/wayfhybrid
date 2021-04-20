'use strict';

// minified https://github.com/douglascrockford/JSON-js/blob/master/json2.js
// "object"!=typeof JSON&&(JSON={}),function(){"use strict";var rx_one=/^[\],:{}\s]*$/,rx_two=/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g,rx_three=/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,rx_four=/(?:^|:|,)(?:\s*\[)+/g,rx_escapable=/[\\"\u0000-\u001f\u007f-\u009f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,rx_dangerous=/[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,gap,indent,meta,rep;function f(t){return t<10?"0"+t:t}function this_value(){return this.valueOf()}function quote(t){return rx_escapable.lastIndex=0,rx_escapable.test(t)?'"'+t.replace(rx_escapable,function(t){var e=meta[t];return"string"==typeof e?e:"\\u"+("0000"+t.charCodeAt(0).toString(16)).slice(-4)})+'"':'"'+t+'"'}function str(t,e){var r,n,o,u,f,a=gap,i=e[t];switch(i&&"object"==typeof i&&"function"==typeof i.toJSON&&(i=i.toJSON(t)),"function"==typeof rep&&(i=rep.call(e,t,i)),typeof i){case"string":return quote(i);case"number":return isFinite(i)?String(i):"null";case"boolean":case"null":return String(i);case"object":if(!i)return"null";if(gap+=indent,f=[],"[object Array]"===Object.prototype.toString.apply(i)){for(u=i.length,r=0;r<u;r+=1)f[r]=str(r,i)||"null";return o=0===f.length?"[]":gap?"[\n"+gap+f.join(",\n"+gap)+"\n"+a+"]":"["+f.join(",")+"]",gap=a,o}if(rep&&"object"==typeof rep)for(u=rep.length,r=0;r<u;r+=1)"string"==typeof rep[r]&&(o=str(n=rep[r],i))&&f.push(quote(n)+(gap?": ":":")+o);else for(n in i)Object.prototype.hasOwnProperty.call(i,n)&&(o=str(n,i))&&f.push(quote(n)+(gap?": ":":")+o);return o=0===f.length?"{}":gap?"{\n"+gap+f.join(",\n"+gap)+"\n"+a+"}":"{"+f.join(",")+"}",gap=a,o}}"function"!=typeof Date.prototype.toJSON&&(Date.prototype.toJSON=function(){return isFinite(this.valueOf())?this.getUTCFullYear()+"-"+f(this.getUTCMonth()+1)+"-"+f(this.getUTCDate())+"T"+f(this.getUTCHours())+":"+f(this.getUTCMinutes())+":"+f(this.getUTCSeconds())+"Z":null},Boolean.prototype.toJSON=this_value,Number.prototype.toJSON=this_value,String.prototype.toJSON=this_value),"function"!=typeof JSON.stringify&&(meta={"\b":"\\b","\t":"\\t","\n":"\\n","\f":"\\f","\r":"\\r",'"':'\\"',"\\":"\\\\"},JSON.stringify=function(t,e,r){var n;if(gap="",indent="","number"==typeof r)for(n=0;n<r;n+=1)indent+=" ";else"string"==typeof r&&(indent=r);if(rep=e,e&&"function"!=typeof e&&("object"!=typeof e||"number"!=typeof e.length))throw new Error("JSON.stringify");return str("",{"":t})}),"function"!=typeof JSON.parse&&(JSON.parse=function(text,reviver){var j;function walk(t,e){var r,n,o=t[e];if(o&&"object"==typeof o)for(r in o)Object.prototype.hasOwnProperty.call(o,r)&&(void 0!==(n=walk(o,r))?o[r]=n:delete o[r]);return reviver.call(t,e,o)}if(text=String(text),rx_dangerous.lastIndex=0,rx_dangerous.test(text)&&(text=text.replace(rx_dangerous,function(t){return"\\u"+("0000"+t.charCodeAt(0).toString(16)).slice(-4)})),rx_one.test(text.replace(rx_two,"@").replace(rx_three,"]").replace(rx_four,"")))return j=eval("("+text+")"),"function"==typeof reviver?walk({"":j},""):j;throw new SyntaxError("JSON.parse")})}();

if (typeof Object.assign != 'function') {
  Object.assign = function(target, varArgs) { // .length of function is 2
    'use strict';
    if (target == null) { // TypeError if undefined or null
      throw new TypeError('Cannot convert undefined or null to object');
    }

    var to = Object(target);

    for (var index = 1; index < arguments.length; index++) {
      var nextSource = arguments[index];

      if (nextSource != null) { // Skip over if undefined or null
        for (var nextKey in nextSource) {
          // Avoid bugs when hasOwnProperty is shadowed
          if (Object.prototype.hasOwnProperty.call(nextSource, nextKey)) {
            to[nextKey] = nextSource[nextKey];
          }
        }
      }
    }
    return to;
  };
}

var data = {
  questionmarkicon: '<img src="/questionMarkIcon.png">',
  attributes: {
      "edupersonassurance": {
          "da": "Niveau af autentitetssikring",
          "en": "Level of assurance"
      },
      "edupersonassurance_description": {
          "da": "Niveau af autentitetssikring",
          "en": "Level of assurance"
      },
      "organizationname": {
          "da": "Organisationens kaldenavn",
          "en": "The organisation's nickname"
      },
      "cn": {
          "da": "Kaldenavn",
          "en": "Nick name"
      },
      "displayname": {
          "da": "Visningsnavn",
          "en": "Display name"
      },
      "gn": {
          "da": "Fornavn",
          "en": "First name"
      },
      "mail": {
          "da": "Emailadresse",
          "en": "E-mail"
      },
      "preferredlanguage": {
          "da": "Foretrukkent sprog",
          "en": "Preferred language"
      },
      "sn": {
          "da": "Efternavn",
          "en": "Last name"
      },
      "edupersonaffiliation": {
          "da": "Brugerens tilknytning til hjemmeorganisationen",
          "en": "Affiliation"
      },
      "edupersonentitlement": {
          "da": "S\u00e6rlige adgangsrettigheder",
          "en": "Entitlements"
      },
      "edupersonprimaryaffiliation": {
          "da": "Prim\u00e6r tilknytning",
          "en": "Primary affiliation"
      },
      "edupersonprincipalname": {
          "da": "Bruger-ID",
          "en": "User ID"
      },
      "edupersonscopedaffiliation": {
          "da": "Gruppemedlemskab",
          "en": "Group membership"
      },
      "edupersontargetedid": {
          "da": "Dit tjenestespecifikke pseudonym",
          "en": "Your service specific pseudonym"
      },
      "schachomeorganization": {
          "da": "Institutionens dom\u00e6nenavn",
          "en": "Domain name of the institution"
      },
      "schachomeorganizationtype": {
          "da": "Institutionstype",
          "en": "Institution type"
      },
      "organisationname": {
          "da": "Organisationens navn",
          "en": "Organisation name"
      },
      "schacpersonaluniqueid": {
          "da": "Nationalt ID-nummer",
          "en": "National ID number"
      },
      "schacyearofbirth": {
          "da": "F\u00f8dsels\u00e5r",
          "en": "Year of birth"
      },
      "schacdateofbirth": {
          "da": "F\u00f8dselsdato",
          "en": "Date of birth"
      },
      "schaccountryofcitizenship": {
          "da": "Land",
          "en": "Country"
      },
      "sn_description": {
          "da": "Dit efternavn",
          "en": "Your last name, also known as family name"
      },
      "gn_description": {
          "da": "Dit fornavn og eventuelle mellemnavne",
          "en": "Your first name, also known as christian name and any middle names"
      },
      "cn_description": {
          "da": "Navnet du bruger til at omtale dig selv",
          "en": "The name you use"
      },
      "mail_description": {
          "da": "Emailadresse",
          "en": "E-mail"
      },
      "edupersonprimaryaffiliation_description": {
          "da": "Prim\u00e6r tilknytning",
          "en": "Primary affiliation"
      },
      "edupersonprincipalname_description": {
          "da": "Dit unikke bruger-ID hos institutionen \/ organisationen (identitetsudbyderen) hvor du loggede ind [eduPersonPrincipalName]",
          "en": "Your unique user ID at the institution \/ organisation (identify provider) where you logged in"
      },
      "organizationname_description": {
          "da": "Navnet p\u00e5 din institutionen \/ organisationen (identitetsudbyderen)",
          "en": "The name of your institution or organisation (identify provider)"
      },
      "noredupersonnin_description": {
          "da": "Dit CPR-nummer",
          "en": "Your social security number"
      },
      "schacpersonaluniqueid_description": {
          "da": "CPR-nummer, pas-nummer eller lignende",
          "en": "Social security number, passport number or something equivalent"
      },
      "schacyearofbirth_description": {
          "da": "\u00c5r du er f\u00f8dt",
          "en": "Year of birth"
      },
      "schacdateofbirth_description": {
          "da": "F\u00f8dselsdato",
          "en": "The date you have been born"
      },
      "edupersonscopedaffiliation_description": {
          "da": "Grupper som du er medlem af",
          "en": "Groups that you are member of"
      },
      "preferredlanguage_description": {
          "da": "Dit foretrukne sprog",
          "en": "Your preferred language"
      },
      "edupersonentitlement_description": {
          "da": "Oplysninger om s\u00e6rlige adgangrettigheder til tjenester eller klasser af tjenester",
          "en": "Priveleges for certain services or classes of classes of services"
      },
      "noredupersonlin_description": {
          "da": "Brugernummer som alene bruges internt, der hvor du loggede ind",
          "en": "User number which is only used internally, at the institution \/ organisation (identy provider) where you are logged in"
      },
      "schachomeorganization_description": {
          "da": "Entydigt (dom\u00e6ne)navn som kan bruges til at identifikation af institutionen \/ organisationen (identitetsudbyderen) hvor du er logget ind",
          "en": "Unique (domain) name used for identification of the institution \/ organisation (identity provider) where you are logged in"
      },
      "schachomeorganizationtype_description": {
          "da": "Institutions type i bredere kategorier for institutionen \/ organisationen (identitetsudbyderen) hvor du er logget ind",
          "en": "Institution type in broader categories for the institution \/ organisation (identity provider) where you are logged in"
      },
      "edupersontargetedid_description": {
          "da": "Pseudonymet g\u00f8r dig genkendelig for tjenesten, uden at g\u00f8re dig identificerbar som person. Du f\u00e5r forskellige pseudonymer til forskellige tjenester",
          "en": "The pseudonym makes you recognizable to the service, without making you identifiable as a person. You get different pseudonyms for different services"
      },
      "schaccountryofcitizenship_description": {
          "da": "lister de lande hvori brugeren p\u00e5st\u00e5r at have statsborgerskab",
          "en": "specifies the (claimed) countries of citizenship for the subject it is associated with."
      }
  },
  attributeRelease: {
      "questionmarkicon": '/questionMarkIcon.png',
      "yes": {
          "da": "Ja, jeg accepterer",
          "en": "Yes, I accept"
      },
      "no": {
          "da": "Nej, jeg accepterer ikke",
          "en": "No, I do not accept"
      },
      "remember": {
          "da": "OK",
          "en": "OK"
      },
      "remember_description": {
          da: "Dit samtykke vil blive gemt i 30 dage på denne enhed. Hvis du bruger et privat/incognito vindue, vil dit samtykke blive slettet når du lukker vinduet.",
          en: "engligsh remember_description"
      },
      "attributeRelease_notice": {
          "da": "Du er ved at logge ind p\u00e5 tjenesten",
          "en": "You are about to login to the service"
      },
      "attributeRelease_accept_newline": {
          "da": "Du er ved at logge ind på <em>{{SPDisplayName}}</em>.<p>{{SPDescription}}<p><b>Oplysningerne herunder er nødvendige for at tilgå tjenesten.<p>Klik <a href=\"https://www.wayf.dk/da/attributter\" target=_blank>her</a> for en detaljeret beskrivelse af oplysningstyperne.<p>{{{content}}}<\/b>",
          "en": "You are about to log into {{SPDisplayName}}.<p>{{SPDescription}}<p><b>The information below is required for access to the service.<p>Click <a href=\"https://www.wayf.dk/en/node/60\" target=_blank>here</a> for a detailed description of the fields.<p>{{{content}}}<\/b>"
      },
      "attributeRelease_privacypolicy": {
          "da": "Tjenestens politik vedr\u00f8rende personoplysninger",
          "en": "Privacypolicy for the service"
      },
      "login": {
          "da": "login",
          "en": "login"
      },
      "service_providers_for": {
          "da": "Tjenesteudbyder for",
          "en": "Service Providers for"
      },
      "service_provider_header": {
          "da": "Tjenesteudbyder",
          "en": "Service Provider"
      },
      "status_header": {
          "da": "Samtykke status",
          "en": "attributeRelease status"
      },
      "show_hide_attributes": {
          "da": "vis\/skjul attributter",
          "en": "show\/hide attributes"
      },
      "noattributeRelease_title": {
          "da": "Manglende samtykke",
          "en": "No attributeRelease given"
      },
      "noattributeRelease_text": {
          "da": "Du har ikke givet samtykke til overleveringen af oplysninger til tjenesten",
          "en": "You did not give attributeRelease for transfering your attributes to the service provider."
      },
      "noattributeRelease_return": {
          "da": "G\u00e5 tilbage",
          "en": "Return to attributeRelease page"
      },
      "origin_tooltip_text": {
          "da": "V&aelig;rdien: <b>VAL<\/b> stammer fra: <b>ORIGIN<\/b>",
          "en": "The value: <b>VAL<\/b> originates from: <b>ORIGIN<\/b>"
      },
      "attributeReleaseadmin_link": {
          "da": "Administrer samtykker",
          "en": null
      },
      "incorrect_info_link": {
          "da": "Forkerte personoplysninger?",
          "en": "Incorrect personal information?"
      },
      "incorrect_info_text": {
          "da": "Hvis oplysningerne om dig ikke er korrekte, skal du kontakte {{IdPDisplayName}}, hvor de stammer fra.",
          "en": "If your personal information is not correct you must contact the institution ({{IdPDisplayName}}), where they originate."
      },
      "previous_attribute_releases": {
          "da": "Nedenstående tjeneste/institutions-par er registreret i denne browser. Det betyder<ul><li>at du er blevet oplyst om de \
                data der bliver leveret fra institutionen til tjenesten<li>at institutionen måske automatisk \
                bliver valgt når du logger ind fra den tilhørende tjeneste</ul>\
                <p>Hvis du ønsker at benytte en anden institution for en given tjeneste, kan du slette registreringen for et tjeneste/institutions-par ved at klikke på <span class=rm>X</span>",
          "en": "The service / identity provider combinations below are registered in this browser. Thus<ul><li>\
                you have been informed about the data that are passed from the identity provider to the service<li>the identity provider might be selected automatically when you log in from the corresponding service</ul>\
                <p>If you want to be able to use another identity provider with a service you can un-register the service / identity provider combination by clicking on <span class=rm>X</span>"
      },
      "previous_attribute_releases_none": {
          "da": "Ingen",
          "en": "None"
      },
      "myWayf": {
          "da": "Du kan til enhver tid gå til <a href=\"https://wayf.wayf.dk/my/\">my.wayf.dk</a> for at se hvilke par der er registreret i denne browser.",
          "en": "You can always go to <a href=\"https://wayf.wayf.dk/my/\">my.wayf.dk</a> to see the the pairs registered in this browser."
      }
  },

  langs: [ // a bit peculiar for not getting mixed up with the general extracting of language for mustache purposes
      ['da', 'Dansk'],
      ['en', 'English']
  ],

  oid2base: {
    "urn:oid:2.5.4.3": "cn",
    "urn:oid:2.5.4.42": "gn",
    "urn:oid:2.5.4.4": "sn",
    "urn:oid:2.16.840.1.113730.3.1.241": "displayName",
    "urn:oid:0.9.2342.19200300.100.1.3": "mail",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.10": "eduPersonTargetedID",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.6": "eduPersonPrincipalName",
    "urn:oid:1.3.6.1.4.1.25178.1.2.15": "schacPersonalUniqueID",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.5": "eduPersonPrimaryAffiliation",
    "urn:oid:2.5.4.10": "organizationName",
    "urn:oid:1.3.6.1.4.1.25178.1.2.10": "schacHomeOrganizationType",
    "urn:oid:1.3.6.1.4.1.25178.1.2.9": "schacHomeOrganization",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.11": "eduPersonAssurance",
    "urn:oid:1.3.6.1.4.1.25178.1.2.5": "schacCountryOfCitizenship",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.9": "eduPersonScopedAffiliation",
    "urn:oid:2.16.840.1.113730.3.1.39": "preferredLanguage",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.7": "eduPersonEntitlement",
    "urn:oid:1.3.6.1.4.1.2428.90.1.4": "norEduPersonLIN",
    "urn:oid:1.3.6.1.4.1.25178.1.2.3": "schacDateOfBirth",
    "urn:oid:1.3.6.1.4.1.25178.1.0.2.3": "schacYearOfBirth",
    "urn:oid:1.3.6.1.4.1.5923.1.1.1.1": "eduPersonAffiliation"
  }
}

window.ar = (function() {
  var def = '[]'
  var name = 'WAYF'
  var cache = JSON.parse(localStorage[name] || "[]")

  var my = {
      check: function(ard) {
          for (var i = 0; i < cache.length; i++) {
              var ars = cache[i]
              if (ars.Key == ard.Key && ars.Hash == ard.Hash) {
                      return true;
              }
          }
          return false;
      },

      get: function() {
          return cache
/*
          var filtered = []
          cache.forEach(function(v) { if (v.Hash || v.byPassDS) { filtered.push(v); }});
          return filtered
 */
      },

      // Remember this atttribute release
      save: function(data) {
          var found = false
          var i
          for (i = 0; i < cache.length; i++) {
              if (cache[i].Key == data.Key) {
                  found = true
                  break
              }
          }
          if (found) {
              cache[i].Hash = data.Hash
          } else {
              ard = {Key: data.Key, SP: {DisplayNames: data.SPDisplayName, entityID: data.SPEntityID}, IdP: {DisplayNames: data.IdPDisplayName, entityID: data.IdPEntityID}, Hash: data.Hash}
              cache.push(ard)
          }
          localStorage[name] = JSON.stringify(cache);
      },

      unsave: function(key) {
          var newcache = []
          cache.forEach(function(v) { if (key != v.Key) { newcache.push(v); }});
          cache = newcache
          localStorage[name] = JSON.stringify(cache);
      },

      rm: function() {
          localStorage.removeItem(name);
      },

      /** extract one language from obj/array */
      ex: function(lang, obj) {
          if (obj instanceof Array) {
              var res = [];
              for (var i = 0; i < obj.length; i++) {
                  res[i] = my.ex(lang, obj[i])
              }
          } else if (obj instanceof Object) {
              var res = {};
              if (lang in obj) {
                  return my.ex(lang, obj[lang]);
              }

              for (var k in obj) {
                  res[k] = my.ex(lang, obj[k]);
              }
          } else {
              return obj;
          }
          return res;
      },

      // render the form in lang using data for content
      render: function(lang, data, ard) {
          document.querySelector('body').style.display = "block";
          data = my.ex(lang, Object.assign(data, ard))

          // language selectors
          var templatelangs = '<a data-lang="{{lang}}">{{displaylang}}</a> ';
          var langs = '';

          for (var i = 0; i < data.langs.length; i++) {
              if (lang == data.langs[i][0]) {
                  continue;
              }
              langs += Mustache.render(templatelangs, {
                  lang: data.langs[i][0],
                  displaylang: data.langs[i][1]
              });
          }

          document.getElementById("langs").innerHTML = langs;

          // logos
          var templatelogo = '<div class="logos"><img src="{{SPLogo}}" alt="{{SPDisplayName}}-logo"><img src="{{IdPLogo}}" alt="{{IdPDisplayName}}-logo"></div>';
          var content = Mustache.render(templatelogo, data);

          // attribute table
          var template = '<tr><td class="attr" title="{{title}}">{{attr}}</td><td class="val"><ul>{{#val}}<li>{{{.}}}{{/val}}</ul></td></tr>';
          Mustache.parse(template);
          var attrs = "<table id=attributeRelease>"
          for (var k in data.oid2base) {
              var base = data.oid2base[k]
              var vals = data.Values[k] || data.Values[base]
              if (vals === undefined) continue;

              var vals2 = []
              for (var i = 0; i < vals.length; i++) {
                  vals2.push(vals[i].replace(/((\W+)|(\w{30}))/g, '$1<wbr>'))
              }
              // map from oid to base if neccessary
              attrs += Mustache.render(template, {
                  title: data.attributes[base.toLowerCase() + '_description'],
                  attr: data.attributes[base.toLowerCase()],
                  val: vals2,
                  questionmarkicon: data.questionmarkicon
              });
          };
          attrs += "</table>";

          // include in generel text
          var template1 = '<div>{{{attributeRelease_accept_newline}}}</div>';
          var tmpl = Mustache.render(template1, data.attributeRelease);
          content += Mustache.render(tmpl, Object.assign(data, {
              content: attrs
          }));

          // buttons
          //content += Mustache.render('<div><span class=input><input id="no" value="{{no}}" type="submit"></span>&emsp;<span class=input><input id="yes" value="{{yes}}" type="submit"></span>', data.attributeRelease);
          content += Mustache.render('&emsp;<span class=input><input id="remember" value="{{remember}}" title="{{remember_description}}" type="submit"></span>', data.attributeRelease);
          content += '</div>'

          // incorrect attributes text
          tmpl = Mustache.render('<div>{{{incorrect_info_text}}}</div>', data.attributeRelease);
          content += Mustache.render(tmpl, data);

          var prevattrs = my.get()
          content += Mustache.render('{{#val.length}}<hr><div id=prevattrs class="prevattrs"><p>{{{previous_attribute_releases}}}<p><ul class=rm>{{#val}}<li data-key="{{Key}}">{{{SP.DisplayNames}}} / {{{IdP.DisplayNames}}}{{/val}}</ul></div><div>{{{myWayf}}}</div>{{/val.length}}', Object.assign(data.attributeRelease, {val: my.ex(lang, prevattrs)}))

          document.getElementById("content").innerHTML = content;

          //document.getElementById('no').focus()
          //document.getElementById('no').onclick = my.no
          //document.getElementById('yes').onclick = my.yes
          document.getElementById('remember').onclick = my.remember

          var nodes = document.querySelectorAll('#prevattrs li')

          if (nodes) {
              for (var i = 0; i < nodes.length; ++i) {
                nodes[i].onclick = my.unremember;
              }
          }

          nodes = document.getElementById('langs').children
          for (var i = 0; i < nodes.length; ++i) {
            nodes[i].onclick = my.changelang;
          }
      },

      // do not release - just show that we dont
      no: function() { alert('no'); },

      // release but do not remember that we did it
      yes: function() {
//          alert('yes');
          document.getElementById('samlform').submit()
      },

      // release and remember
      remember: function() {
//          alert('remember');
          document.getElementById('samlform').submit()
          my.save(data)
      },

      unremember: function(e) {
        e = e || window.event;
        var target = e.target || e.srcElement
        my.unsave(target.getAttribute("data-key"));
        //my.unsave(target.getAttribute("data-key"));
        my.render(lang, data, ard)
      },

      // delete all previous attributeReleases
      deleteall: function() {
          my.rm()
      },

      // change to another lange and render again
      changelang: function(e) {
          e = e || window.event;
          var target = e.target || e.srcElement
          lang = target.getAttribute("data-lang")
          my.render(lang, data, ard)
      },

      dispatch: function(lang, data, ard) {
          if (ard.ConsentAsAService) {
              document.getElementById('samlform').action = "https://" + ard.ConsentAsAService
          }
          if (ard.ForceConfirmation) {
              my.render(lang, data, ard);
          } else if (ard.BypassConfirmation) {
              document.getElementById('samlform').submit()
          } else if (my.check(ard)) {
              document.getElementById('samlform').submit()
          } else {
              my.render(lang, data, ard);
          }
      }
  };
  return my;
}());


/**
    ds is a javascript object that handles the client side logic of the WAYF discovery service

*/

window.ds = function (wayfhub, brief, show, logtag, prefix) {
    show = show || 100;
    var diskofeed = location.protocol + '//' + location.hostname + prefix + '/dsbackend';
    var starttime = new Date();
    var urlParams = this.urlParams = parseQuery(window.location.search);
    urlParams['returnIDParam'] = urlParams['returnIDParam'] || 'entityID';
    urlParams['return'] = urlParams['return'] || '';
    var dry = Boolean(urlParams['dry']);
    var spEntityID = urlParams.entityID;

    var feds = [];
    var providerIDs = urlParams['idplist'] ? urlParams['idplist'].split(',') : []

    //var feds = ['WAYF'];
    var idplist = [];
    var maxrememberchosen = 10;
    var searchInput = document.getElementById("searchInput");

    var cache = {};
    var cursorKeysUsed = false;
    var touch = "ontouchstart" in document.documentElement;

    document.documentElement.className += touch ? ' touch' : ' no-touch';
    var zzz = JSON.parse(localStorage.WAYF || "[]");

    //searchInput.value = localStorage.query || "";
    //searchInput.selectionStart = searchInput.selectionEnd = searchInput.value.length;

    var stopit = false

    window.addEventListener('mousemove', function onMove(e) {
        stopit = true // e.shiftKey
        window.removeEventListener('mousemove', onMove, false);
    })

    var chosen = []
    var requestcounter = 0;

    // automatically jumps to the bottom of the page for a better mobile experience
    // window.scroll(0, document.body.scrollHeight);

    var delay = function () {
        var timer = 0;
        return function (callback, ms) {
            clearTimeout(timer);
            timer = setTimeout(callback, ms);
        };
    }();

    searchInput.addEventListener("input", function () {
        delay(search, 200);
    }, false);
    document.getElementById("chosenlist").addEventListener("click", choose, false);
    document.getElementById("foundlist").addEventListener("click", choose, false);
    document.getElementsByTagName("body")[0].addEventListener("keydown", enter, false);
    window.addEventListener("beforeunload", windowclose);

    search();

    this.changelang = function () {
        lang = lang == 'da' ? 'en' : 'da';
        search();
        searchInput.focus();
    };

    /**
        choose handles the actual selection of the idp either by a click or by the enter/return key
     */

    function choose(e) {
        var no
        var choseby = 'click';
        searchInput.focus();
        if (typeof e == 'number') {
            no = e
            choseby = 'enter'
        } else {
            no = e.target.attributes.getNamedItem("data-no");
            no = no != null ? parseInt(no.value) : null;
        }
        if (no == null) {
            search();
        } else {
            // return with result
            // we don't want to get the window close event if we leave as a result of the users choise
            window.removeEventListener("beforeunload", windowclose);
            var displayName = idplist[no].DisplayNames[lang] || idplist[no].DisplayNames.en;
            var idp = idplist[no].entityID;

            var query = {
                idp: idp,
                logtag: logtag,
                delta: new Date() - starttime,
                choseby: choseby,
                cursorKeysUsed: cursorKeysUsed,
                touch: touch
            };
            var request = new XMLHttpRequest();
            request.open("GET", location.protocol + '//' + location.hostname + prefix + '/dstiming' + serialize(query), true);
            request.send();
            saveDSPair(idplist[no], cache.sp)
            if (dry) {
                var delim = urlParams['return'].match(/\?/) ? "&" : "?";
                alert('You are being sent to ' + displayName + ' (' + idp + ') ' + delim);
                window.location = window.location;
            } else {
                var delim = urlParams['return'].match(/\?/) ? "&" : "?";
                setTimeout(function() {window.location = urlParams['return'] + delim + urlParams['returnIDParam'] + '=' + encodeURIComponent(idp);}, 10);
            }
        }
    }

    function windowclose(e) {
        //return;
        var query = {
            logtag: logtag,
            delta: new Date() - starttime,
            choseby: 'windowclose',
            touch: touch
        };
        var request = new XMLHttpRequest();
        request.open("GET", location.protocol + '//' + location.hostname + prefix + '/dstiming' + serialize(query), true);
        request.send();
    }

    function saveDSPair(idp, sp) {
        var cache = JSON.parse(localStorage['WAYF'] || "[]")
        var key = sha1.sha1(sp.entityID).substr(0, 10)

        var i
        var found = false
        for (i = 0; i < cache.length; i++) {
            if (cache[i].Key == key) {
                found = true
                break
            }
        }
        var byPassDS = document.querySelector('#byPassDS2c').checked
        if (found) {
            var template =  document.querySelector('#byPassDS').textContent.replace(/IDPNAME/, idp.DisplayNames[lang])
            cache[i].ByPassDS = byPassDS
            cache[i].SP = sp
            cache[i].IdP = idp
        } else {
            cache.push({Key: key, SP: sp, IdP: idp, Hash: "" , ByPassDS: byPassDS})
        }
        localStorage['WAYF'] = JSON.stringify(cache)
    }

    function updateDisplaynamesAndPurge(idps) {
        var byEntityID = {}
        chosen = {}
        for (var i = 0; i < idps.length; i++) {
            chosen[idps[i].entityID] = idps[i]
        }
        var cache = JSON.parse(localStorage['WAYF'] || "[]")
        var newCache = []
        for (i = 0; i < cache.length; i++) { // Update savec display names and delete IdPs that are not active any longer
            if (chosen[cache[i].IdP.entityID]) {
                cache[i].IdP = chosen[cache[i].IdP.entityID]
                newCache.push(cache[i])
            }
        }
        localStorage['WAYF'] = JSON.stringify(newCache)
    }

    /**
        discoverybackend handles the communication with the discovery backend
     */

    function discoverybackend(first, entityID, query, start, end, feds, providerIDs, chosen, callback) {
        var async = Boolean(callback);
        var request = new XMLHttpRequest();
        var urlvalue = {
            entityID: first ? entityID : '',
            query: query,
            start: start,
            end: end,
            lang: lang,
            feds: feds,
            providerids: providerIDs,
            logtag: logtag,
            delta: new Date() - starttime,
            chosen: first ? chosen : ''
        };

        var param = serialize(urlvalue);

        // add entityID + lang for getting the name of the sp in the correct language
        // if no language the maybe don't return icon and name ???
        request.open("GET", diskofeed + param, async);
        request.send();
        if (async) {
            request.onreadystatechange = function () {
                if (request.readyState == XMLHttpRequest.DONE) {
                    if (request.status >= 200 && request.status < 400) {
                        callback(JSON.parse(request.responseText));
                    } else {
                        //callback(JSON.parse(request.responseText));
                    }
                }
            };
        } else {
            var res = JSON.parse(request.responseText);
            return res;
        }
    }

    /**
        renderrows handles the rendering of the previously chosen idps as well as the search result
     */

    function renderrows(dsbe, query) {
        idplist = [];
        var chosenList = [];
        Object.keys(chosen).forEach(function (c) { chosenList.push(chosen[c]) })
        var lists = {
            chosenlist: chosenList,
            foundlist: query || !brief || dsbe.rows == dsbe.found ? dsbe.idps : []
        };
        var no = 0;
        Object.keys(lists).forEach(function (k) {
            var rows = [];
            for (var i = 0; i < lists[k].length; i++) {
                var classs = k == 'chosenlist' ? 'chosen' : 'unchosen';
                var name = lists[k][i].DisplayNames[lang];
                if (!name) name = lists[k][i].DisplayNames.en;
                var entityID = lists[k][i].entityID;
                classs += k == 'chosenlist' && !chosen[entityID].relevant ? ' disabled' : '';
                //var title = JSON.stringify(lists[k][i].Keywords).slice(1, -1);
                idplist[no] = {
                    DisplayNames: lists[k][i].DisplayNames,
                    entityID: entityID,
                    Keywords: lists[k][i].Keywords
                };
                var delement = ""
                var xelement = ""
                if (k == 'chosenlist') {
                    delement = '' //'<div class="delchosen" data-no-x="' + no + '">X</div>'
                    xelement = '' //'&nbsp;<div class="idp forever" data-no="' + no + '">forever</div>'
                }
                rows[i] = '<div class="' + classs + ' metaentry" data-no="' + no + '">'+delement+'<div class="idp" data-no="' + no + '">' + name + '</div>' + xelement + ' </div>';
                no++;
            }
            // fakedivs to make the selected work across the lists
            var fakedivs = k == 'foundlist' ? Array(lists['chosenlist'].length + 1).join('<div></div>') : '';
            document.getElementById(k).innerHTML = fakedivs + rows.join('');
        });
    }

    /**
        search handles the search - is called when the search input field changes
     */

    function search() {
        var query = searchInput.value.trim();
        var idp = {};
        var autochoosenID = "";

        for (var i = 0; i < zzz.length; i++) {
            chosen[zzz[i].IdP.entityID] = zzz[i].IdP // unique'fy
        }

        discoverybackend(!requestcounter, spEntityID, query, 0, show, feds, providerIDs, Object.keys(chosen).join(','), function (dsbe) {
            if (!dsbe.spok) {
                display(dsbe.sp, idp, dsbe.rows, dsbe.found, true);
                return;
            }

            if (!requestcounter) {
                spIcon.src = dsbe.sp.Logo || 'data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=';
                //spIcon.style.display = "block";
                dsbe.sp.Logo = ''
                cache.sp = dsbe.sp;
                updateDisplaynamesAndPurge(dsbe.chosen ? dsbe.chosen : [])
            }
            // chosen = all prev. chosen (incl. byPassDS) that are ok
            // providerIDs - only show subset - also in chosen
            // if chosen[prev] and providerIDs.length > 0 providerIDs[prev] and !stopit -> autochoose

            var key = sha1.sha1(spEntityID).substr(0, 10)
            var byPassDS = ""
            for (var i = 0; i < zzz.length; i++) {
                if (key == zzz[i].Key && zzz[i].ByPassDS) {
                    byPassDS = zzz[i].IdP.entityID
                    break
                }
            }
            stopit = stopit || !byPassDS || !chosen[byPassDS] || !chosen[byPassDS].relevant || (providerIDs.length && providerIDs.indexOf(byPassDS) === -1)

            var delim = urlParams['return'].match(/\?/) ? "&" : "?";
            var loc = urlParams['return'] + delim + urlParams['returnIDParam'] + '=' + encodeURIComponent(byPassDS)
            if (!stopit) { window.location = loc; return }

            document.querySelector('body').style.display = "block"; searchInput.focus();
            renderrows(dsbe, query);
            feds = dsbe.feds; // when we start using ad-hoc feds
            display(cache.sp, idp, dsbe.rows, dsbe.found);
            document.getElementById('found').style.display = idplist.length > Object.keys(chosen).length ? 'block' : 'none';
            //if (dsbe.debug.eop) { document.getElementById('timing').innerHTML = dsbe.debug.eop; }
            document.getElementById('refine').style.display = (query || !brief) && dsbe.rows < dsbe.found ? 'block' : 'none';
            // auto select relevant IdP unless interupted by user action
            requestcounter++;
        });
    }

    /**
        enter handles keypresses
     */

    function enter(e) {
        // eslint-disable-line no-unused-vars
        var keyCodeMappings = {
            13: "enter",
            27: "escape"
        };

        var keyPressed = keyCodeMappings[e.keyCode];
        var top;

        if (e.defaultPrevented) {
            return; // Should do nothing if the key event was already consumed.
        }

        switch (keyPressed) {
            case "escape":
                searchInput.value = "";
                search();
                break;
            case "enter":
                choose(0);
                break;
            default:
                return; // Quit when this doesn't handle the key event.
        }
        e.preventDefault();
    }

    /**
        encode query from object - from http://stackoverflow.com/questions/1714786/querystring-encoding-of-a-javascript-object
     */

    function serialize(obj) {
        return '?' + Object.keys(obj).reduce(function (a, k) {
            a.push(k + '=' + encodeURIComponent(obj[k]));return a;
        }, []).join('&');
    }

    /**
        parseQuery converts the url query params to a map
     */

    function parseQuery(query) {
        var urlParams = {};
        var match;
        var pl = /\+/g; // Regex for replacing addition symbol with a space
        var re = /([^&=]+)=?([^&]*)/g;
        var decode = function decode(s) {
            return decodeURIComponent(s.replace(pl, " "));
        };
        query = query.replace(/^\?/, '');
        while (match = re.exec(query)) {
            // eslint-disable-line no-cond-assign
            urlParams[decode(match[1])] = decode(match[2]);
        }

        return urlParams;
    }
};
