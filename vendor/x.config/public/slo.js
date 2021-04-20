langs: [ // a bit peculiar for not getting mixed up with the general extracting of language for mustache purposes
    ['da', 'Dansk'],
    ['en', 'English']
],

window.slo = (function() {
  var def = '[]'

  var my = {
       // render the form in lang using data for content
      render: function(lang, sil) {
          var template = '<tr><td>{{SLOStatus}}</td><td>{{SLOSupport}}</td><td>{{DisplayName}}</td></tr>';
          Mustache.parse(template);
          var attrs = "<table id=sil>"
          for (const sloinfo of sil) {
            console.log(sloinfo)
              attrs += Mustache.render(template, sloinfo);
          };
          attrs += "</table>";
          document.getElementById("content").innerHTML = attrs;
      },

      // change to another lange and render again
      changelang: function(e) {
          e = e || window.event;
          var target = e.target || e.srcElement
          lang = target.getAttribute("data-lang")
          my.render(lang, data, ard)
      },

      dispatch: function(lang, data, sloinfo) {
          my.render(lang, data, sloinfo);
      }
  };
  return my;
}());

