var eas = {};





/**
 * All logic for the anti-spam module lives in this object.
 *
 * Events triggering this logic will be triggered inline.
 * 
 * @type {Object}
 */
eas.abc = {

  me: false, // Script tag containing init calls
  pr: {
    a: 0,   // Number of times we've waited for jQuery
    b: 10,  // Number of times we should wait for jQuery
  }, // pr

  a: function() {

    console.log('js & timestamp check ');

    var timestamp_el = jQuery(eas.abc.me).closest('form').find('input[name="secret_token"]');
    
    timestamp_el.val( timestamp_el.data('ts') );

  }, // a()

  b: function() {

    console.log('Pure javascript test.');

    var input = document.createElement("input");
    input.setAttribute("type", "hidden");
    input.setAttribute("name", "easjst");
    input.setAttribute("value", "very-js");

    jQuery(eas.abc.me).after(input);

  }, // b()

  z: function(method) {

    if (!eas.abc.me) {

      eas.abc.me = document.currentScript;

    }
 
    if (window.jQuery) {
      method();
    } else {
      
      if (eas.abc.pr.a < eas.abc.pr.b) {

        eas.abc.pr.a++;
        setTimeout(function() { eas.abc.z(method) }, 50);

      }

    }
  } // z()

}; // abc()