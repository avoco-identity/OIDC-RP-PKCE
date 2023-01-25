/**
 * A JavaScript implementation of an OIDC Public Client
 *
 * Copyright (c) AVOCO SECURE LTD. All rights reserved.
 * Licensed under the MIT License, you may not use this file except in compliance with
 * the License.
 * See https://github.com/avoco-identity/OIDC-RP-PKCE for more information
 *
 *
 * THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
 * INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
 * MERCHANTABLITY OR NON-INFRINGEMENT.
 *
 */

/**
 * A function that sets the value of an element with the given id
 * @param {string} elementId - The id of the element
 * @param {any} value - The value to be set
 * @param {string} property - The property of the element to set the value to (defaults to 'value')
 * @returns {boolean} - true if the value was set successfully, false otherwise
 */
function setValue( elementId, value, property ) {
	// Get the element using its id
	var element = document.getElementById( elementId );
	// Check if the element is not null
	if ( element ) {
		// If the property is not provided, default to 'value'
		property = property || 'value';
		// Set the value of the specified property
		element[ property ] = value;
		return true;
	}
	// if the element is null, return false
	return false;
}

function setValueObject( elementId, value, property ) {
	if ( typeof elementId === 'object' ) {
		if ( elementId ) {
			for ( var prop in value ) {
				if ( value.hasOwnProperty( prop ) ) {
					elementId[ prop ] = value[ prop ];
				}
			}
			return true;
		} else {
			return false;
		}
	} else {
		var element = document.getElementById( elementId );
		if ( element ) {
			property = property || 'value';
			element[ property ] = value;
			return true;
		} else {
			return false;
		}
	}
}


var App = {
	gCookieName: 'oidcrpsettings',
	getParams: function ( q ) {
		// "use strict";
		var hashParams = {};
		var e,
			a = /\+/g, // Regex for replacing addition symbol with a space
			r = /([^&;=]+)=?([^&;]*)/g,
			d = function ( s ) {
				return decodeURIComponent( s.replace( a, " " ) );
			};

		while ( e = r.exec( q ) )
			hashParams[ d( e[ 1 ] ) ] = d( e[ 2 ] );

		this.urlParams = hashParams;
	},

	// safe return of param item from App.urlParams
	getParam: function ( name ) {
		if ( !this.urlParams ) {
			return '';
		}
		if ( this.urlParams[ name ] ) {
			return this.urlParams[ name ];
		} else {
			return '';
		}
	},

	displayNotification: function ( title, msg, stat, sticky ) {
		UIkit.notification( '<span class="uk-text-bold">' + title + '</span><br>' + msg, {
			status: stat,
			timeout: sticky === true ? 0 : 6000
		} );
	},

	displayError: function ( error, error_description ) {
		var msg = 'Error: ' + error + '<br>Description: ' + error_description;
		this.displayNotification( 'Information', msg, 'danger' );
	},

	// creates a secure cookie
	setCookie: function ( c_name, c_value, c_exp_days ) {
		var expires = '';
		if ( c_exp_days ) {
			var date = new Date();
			date.setDate( date.getDate() + c_exp_days );
			expires = '; expires=' + date.toGMTString();
		}
		document.cookie = c_name + '=' + c_value + expires + ';secure;SameSite=None;path=' + window.location.pathname;
	},


	getCookie: function ( c_name ) {
		var i, x, y, p, ARRcookies = document.cookie.split( ";" );
		for ( i = 0; i < ARRcookies.length; i++ ) {
			p = ARRcookies[ i ].indexOf( "=" );
			if ( p > -1 ) {
				x = ARRcookies[ i ].substr( 0, p );
				y = ARRcookies[ i ].substr( p + 1 );
				x = x.replace( /^\s+|\s+$/g, "" );
				if ( x === c_name )
					return unescape( y );
			}
		}
		return '';
	},


	getRandomString: function ( length ) {
		var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
		var i, values, result = '';

		values = new Uint32Array( length );
		window.crypto.getRandomValues( values );
		for ( i = 0; i < length; i++ ) {
			result += charset[ values[ i ] % charset.length ];
		}
		return result;

	},

	// url safe base64 encode
	base64URLEncode: function ( data ) {
		return btoa( data )
			.replace( /\+/g, '-' )
			.replace( /\//g, '_' )
			.replace( /=/g, '' );
	},

	// unix time to local
	displayLocalTime: function ( epochTime ) {
		var dt = new Date( epochTime * 1000 );
		return dt.toLocaleString();
	},

	// returns callback URL - current window URL, without query string or hash
	getCallback: function () {

		//default redirect_uri callback
		return window.location.href.split( "?" )[ 0 ].split( "#" )[ 0 ];
	},

	// displays token data
	/*displayTokenData function in ES5 syntax.
	It takes a single parameter tokenData and check if it has an id_token or an access_token.
	It then makes a GET request to the profileurl with the access_token passed in the headers and 
	processes the data received and display it if successful, 
	otherwise it will call the App.displayError function with 
	the error message or error_description that is returned.*/
	displayTokenData: function ( tokenData ) {
		var self = this;
		if ( tokenData.id_token ) {
			// display token content
			var json = self.parseJwt( tokenData.id_token );
			document.getElementById( 'dividtoken' ).innerHTML =
				'<p>ID Token</p>' +
				self.formatJSON( self.syntaxHighlight( JSON.stringify( json, undefined, 2 ) ) );
		} else {
			document.getElementById( 'dividtoken' ).textContent = '';
		}

		if ( tokenData.access_token ) {
			// use token to get claims
			fetch( Settings.options.profileurl, {
					method: 'GET',
					headers: {
						'Authorization': 'Bearer ' + tokenData.access_token
					},
				} )
				.then( function ( response ) {
					return response.json();
				} )
				.then( function ( data ) {
					var checkjwt;
					try {
						checkjwt = App.parseJwt( data );
					} catch ( e ) {
						// not jwt
					}
					if ( checkjwt ) {
						data = checkjwt;
					}

					if ( data.picture ) {
						data.picture = '';
					}
					document.getElementById( 'divattr' ).innerHTML =
						App.formatJSON( App.syntaxHighlight( JSON.stringify( data ) ) );

					if ( data.id ) {
						document.getElementById( 'userid' ).value = data.id;
					}
					if ( data.name ) {
						document.getElementById( 'username' ).value = data.name;
					}
					if ( data.email ) {
						document.getElementById( 'useremail' ).value = data.email;
					}
					if ( data.mobile ) {
						document.getElementById( 'usermobile' ).value = data.mobile;
					}
					if ( data.dateofbirth ) {
						document.getElementById( 'userdob' ).value = data.dateofbirth;
					}
					if ( data.address ) {
						// formatted address has line breaks - replace with space
						if ( data.address.formatted ) {
							var addr = data.address.formatted.replace( /(\n)+/g, ' ' );
							document.getElementById( 'useraddress' ).value = addr;
						}
					}

					// hide / show fields according to settings
					App.showClaimsFields();

					document.getElementById( 'divres' ).style.display = 'block';
				} )
				.catch( function ( error ) {
					if ( error.responseJSON ) {
						App.displayError( error.responseJSON.error, error.responseJSON.error_description );
						console.error( error.responseJSON.error );
					} else {
						App.displayError( error.message );
						console.error( error.message );
					}
				} );

		}
	},


// Function that displays certain fields based on the settings
showClaimsFields: function () {
    // If no fields are set in the settings, return without doing anything
		if ( !Settings.options.fields ) {
			return;
		}

		Object.keys( Settings.options.fields ).forEach( function ( key ) {
			var element = document.getElementById( 'field_' + key );
			if ( !element ) {
				console.error( 'Cannot find element with id field_' + key );
				return;
			}
			element.style.display = Settings.options.fields[ key ] ? "block" : "none";
		} );
	},

// Function that parses a JWT token and returns its payload as a JavaScript object
	parseJwt: function ( token ) {
		var base64Url = token.split( '.' )[ 1 ];
		var base64 = base64Url.replace( '-', '+' ).replace( '_', '/' );
		return JSON.parse( window.atob( base64 ) );
	},
// Function that formats a JSON string by adding line breaks after every comma
	formatJSON: function ( json ) {
		return json.replace( /,/g, ",<br>" );
	},
// Function that adds syntax highlighting to a JSON string
	syntaxHighlight: function ( json ) {
		json = json.replace( /&/g, '&amp;' ).replace( /</g, '&lt;' ).replace( />/g, '&gt;' );
		return json.replace( /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function ( match ) {
			var cls = 'number';
			if ( /^"/.test( match ) ) {
				if ( /:$/.test( match ) ) {
					cls = 'key';
				} else {
					cls = 'string';
				}
			} else if ( /true|false/.test( match ) ) {
				cls = 'boolean';
			} else if ( /null/.test( match ) ) {
				cls = 'null';
			}
			return '<span class="' + cls + '">' + match + '</span>';
		} );
	},

	extractHostname: function ( url, tld ) {
		var hostname;

		// find & remove protocol (http, ftp, etc.) and get hostname
		if ( url.indexOf( '://' ) > -1 ) {
			hostname = url.split( '/' )[ 2 ];
		} else {
			hostname = url.split( '/' )[ 0 ];
		}

		// find & remove port number
		hostname = hostname.split( ':' )[ 0 ];

		// find & remove "?"
		hostname = hostname.split( '?' )[ 0 ];

		if ( tld ) {
			var hostnames = hostname.split( '.' );
			hostname = hostnames[ hostnames.length - 2 ] + '.' + hostnames[ hostnames.length - 1 ];
		}

		return hostname;
	},
	
	clearTokenDisplay: function () {
		document.getElementById( 'dividtoken' ).innerHTML = '';
		document.getElementById( 'divattr' ).innerHTML = '';
	}

};
//End APP


//service provider settings functions
var Settings = {
	options: {},
	//Settings Update function
	update: function () {
		var settings = {};
		// Check if the config form is valid
		if ( document.getElementById( 'form-config' ).checkValidity() ) {
		// Set value of .... in settings object
			setValue( 'authnurl', settings.authnurl );
			setValue( 'tokenurl', settings.tokenurl );
			setValue( 'profileurl', settings.profileurl );
			setValue( 'jwksurl', settings.jwksurl );
			setValue( 'provissuer', settings.provissuer );
			setValue( 'oauth_server', settings.oauth_server );
			setValue( 'ciba_url', settings.ciba_url );
			setValue( 'oauth_clientid', settings.oauth_clientid );
			setValue( 'idp_hint', settings.idp_hint );
			setValue( 'request_mode', settings.request_mode );
			setValue( 'response_mode', settings.response_mode );
			setValue( 'window_type', settings.window_type );
			setValue( 'oauth_scope', settings.oauth_scope );
			setValue( 'useoauth2', settings.oauth, 'checked' );
			setValue( 'acr_values', settings.acr_values );
			settings.fields = {};
			setValue( 'form_name', settings.fields.name, 'checked' );
			setValue( 'form_email', settings.fields.email, 'checked' );
			setValue( 'form_mobile', settings.fields.mobile, 'checked' );
			setValue( 'form_dob', settings.fields.dob, 'checked' );
			setValue( 'form_address', settings.fields.address, 'checked' );
			this.options = settings;
			return true;
		} else {
			var submit = document.createElement( 'input' );
			submit.setAttribute( 'type', 'submit' );
			submit.style.display = 'none';
			document.getElementById( 'form-config' ).appendChild( submit );
			submit.click();
			submit.remove();
			return false;
		}
	},


	update: function () {
		var settings = {};

		function setElementPropertyValue( elementId, target, targetProp ) {
			// Get the element using its id
			var element = document.getElementById( elementId );
			if ( element ) {
				// Check the type of element, input or checkbox
				if ( element.type === 'checkbox' ) {
					target[ targetProp ] = element.checked;
				} else {
					// Assign the value of the element to the provided target
					target[ targetProp ] = element.value;
				}
			}
		}


		if ( document.getElementById( 'form-config' ).checkValidity() ) {
			setElementPropertyValue( 'authnurl', settings, 'authnurl' );
			setElementPropertyValue( 'tokenurl', settings, 'tokenurl' );
			setElementPropertyValue( 'profileurl', settings, 'profileurl' );
			setElementPropertyValue( 'jwksurl', settings, 'jwksurl' );
			setElementPropertyValue( 'provissuer', settings, 'provissuer' );
			setElementPropertyValue( 'oauth_server', settings, 'oauth_server' );
			setElementPropertyValue( 'ciba_url', settings, 'ciba_url' );
			setElementPropertyValue( 'oauth_clientid', settings, 'oauth_clientid' );
			setElementPropertyValue( 'idp_hint', settings, 'idp_hint' );
			setElementPropertyValue( 'request_mode', settings, 'request_mode' );
			setElementPropertyValue( 'response_mode', settings, 'response_mode' );
			setElementPropertyValue( 'window_type', settings, 'window_type' );
			setElementPropertyValue( 'oauth_scope', settings, 'oauth_scope' );
			setElementPropertyValue( 'acr_values', settings, 'acr_values' );
			setElementPropertyValue( 'useoauth2', settings, 'oauth' );
			settings.fields = {};
			setElementPropertyValue( 'form_name', settings.fields, 'name' );
			setElementPropertyValue( 'form_email', settings.fields, 'email' );
			setElementPropertyValue( 'form_mobile', settings.fields, 'mobile' );
			setElementPropertyValue( 'form_dob', settings.fields, 'dob' );
			setElementPropertyValue( 'form_address', settings.fields, 'address' );
			this.options = settings;
			return true;
		} else {
			var submit = document.createElement( "input" );
			submit.type = "submit";
			submit.style.display = "none";
			document.getElementById( 'form-config' ).appendChild( submit );
			submit.click();
			submit.remove();
			return false;
		}
	},


	import: function ( settings ) {
		this.options = settings;

		setValue( 'authnurl', this.options.authnurl );
		setValue( 'tokenurl', this.options.tokenurl );
		setValue( 'profileurl', this.options.profileurl );
		setValue( 'jwksurl', this.options.jwksurl );
		setValue( 'provissuer', this.options.provissuer );
		setValue( 'oauth_server', this.options.oauth_server );
		setValue( 'ciba_url', this.options.ciba_url );
		setValue( 'oauth_clientid', this.options.oauth_clientid );
		setValue( 'useoauth2', this.options.oauth, 'checked' );
		setValue( 'idp_hint', this.options.idp_hint );
		setValue( 'request_mode', this.options.request_mode );
		setValue( 'response_mode', this.options.response_mode );
		setValue( 'window_type', this.options.window_type );
		setValue( 'oauth_scope', this.options.oauth_scope );
		setValue( 'acr_values', this.options.acr_values );
		if ( this.options.fields ) {
			setValue( 'form_name', this.options.fields.name, 'checked' );
			setValue( 'form_email', this.options.fields.email, 'checked' );
			setValue( 'form_mobile', this.options.fields.mobile, 'checked' );
			setValue( 'form_dob', this.options.fields.dob, 'checked' );
			setValue( 'form_address', this.options.fields.address, 'checked' );
		}
	},





	load: function () {
		var cookieData = App.getCookie( App.gCookieName );

		// try settings from cookie first
		if ( cookieData.length > 0 ) {
			try {
				var jsonData = JSON.parse( cookieData );
				this.import( jsonData );
				return;
			} catch ( objError ) {

			}
		} else {
			// try config file
			if ( typeof ( config ) != "undefined" ) {
				this.import( config );
				return;
			}
		}

		this.edit();
	},
	edit: function () {

		// set discovery url
		var discep = document.getElementById( "discep" );
		if ( this.options.provissuer && this.options.provissuer.length > 0 ) {
			if ( discep ) {
				discep.setAttribute( 'href', this.options.provissuer + '/.well-known/openid-configuration' );
				discep.style.display = 'block';
			}
		} else {
			if ( discep ) {
				discep.style.display = 'none';
			}
		}
		if ( App.dlgConfig ) App.dlgConfig.show();
	}




};


/* this function is part of the OAuth object and it is called "exchangeCode". 
It is responsible for exchanging the authorization code for an access token.
creates an XMLHttpRequest, opens a POST request to the tokenurl specified in the settings, sets the request header to "Content-Type: application/json", and sets a timeout.
*/
var OAuth = {
	exchangeCode: function ( code, isWebMessage, nosecret ) {
		// exchange code for token
		var settings = Settings.options;

		var dt = {
			code: code,
			grant_type: 'authorization_code',
			client_id: settings.oauth_clientid,
			redirect_uri: App.getCallback()
		};

		if ( nosecret === undefined || nosecret === null || nosecret === false ) {
			dt.client_secret = settings.oauth_clientsecret;
		}

		// add code verifier if set
		if ( sessionStorage && sessionStorage.codeVerifier && sessionStorage.codeVerifier.length > 0 ) {
			dt.code_verifier = sessionStorage.codeVerifier;
		}

		var xhr = new XMLHttpRequest();
		xhr.open( 'POST', settings.tokenurl, true );
		xhr.setRequestHeader( 'Content-Type', 'application/json' );
		xhr.timeout = 5000;
		xhr.ontimeout = function () {
			App.displayError( 'Timeout Error', 'The request timed out' );
		};
		xhr.onreadystatechange = function () {
			if ( xhr.readyState === 4 ) {
				if ( xhr.status === 200 ) {
					try {
						var data = JSON.parse( xhr.responseText );
						App.displayTokenData( data );
						if ( sessionStorage ) sessionStorage.codeVerifier = '';
					} catch ( e ) {
						App.displayError( 'Error', 'The response is not a valid JSON' );
					}
				} else {
					try {
						var error = JSON.parse( xhr.responseText );
						App.displayError( error.error, error.error_description );
					} catch ( e ) {
						App.displayError( 'Error', xhr.responseText );
					}
				}
			}
		};

		xhr.onerror = function () {
			App.displayError( 'Error', 'A network error occured, please check your connection and try again' );
		}

		xhr.onload = function () {
			if ( xhr.status === 0 ) {
				App.displayError( 'CORS Error', 'The server is not configured to accept cross-origin requests from this origin' );
			}
		}

		xhr.send( JSON.stringify( dt ) );
	},
	startAuth: function ( idpselectbutton ) {
		if ( idpselectbutton === undefined ) {
			idpselectbutton = '';
		}
		// start authorization code flow

		sessionStorage.state = App.getRandomString( 32 ); // verify this matches the value returned in authorization code response
		var settings = Settings.options;


		var qs = 'client_id=' + settings.oauth_clientid;
		var scope = settings.oauth_scope;

		qs += '&state=' + sessionStorage.state;
		if ( settings.response_mode.length > 0 ) {
			qs += '&response_mode=' + settings.response_mode;
		}

		qs += '&redirect_uri=' + encodeURIComponent( App.getCallback() );

		if ( Settings.options.oauth !== true ) {
			// If OIDC generate nonce and add openid to scope
			sessionStorage.nonce = App.getRandomString( 32 );
			qs += '&nonce=' + sessionStorage.nonce;
			if ( scope.indexOf( 'openid' ) === -1 ) {
				scope += ' openid';
			}
		}

		qs += '&scope=' + scope;

		// PKCE stuff
		sessionStorage.codeVerifier = App.base64URLEncode( App.getRandomString( 32 ) );
		var hashObj = new jsSHA( 'SHA-256', 'TEXT', 1 );
		hashObj.update( sessionStorage.codeVerifier );
		var b64_hash = App.base64URLEncode( hashObj.getHash( 'BYTES' ) );

		qs += '&response_type=code';
		qs += '&code_challenge=' + b64_hash + '&code_challenge_method=S256';

		//get idp_hint preferred provider
		if ( idpselectbutton !== '' && idpselectbutton !== undefined ) {
			qs += '&idp_hint=' + idpselectbutton;
		} else if ( settings.idp_hint.length ) {
			qs += '&idp_hint=' + settings.idp_hint;
		}

		var url = settings.authnurl + '?' + qs;

		if ( null != settings.window_type ) {
			// Set default values for window height and width
			var h = 600,
				w = 600;
			var left = ( screen.width / 2 ) - ( w / 2 );
			var top = ( screen.height / 2 ) - ( h / 2 );

			// Use a switch statement to handle different window types
			switch (settings.window_type) {
				case '_default': //browser default
					window.open(url, 'authn');
					break;
				case '_tab': //tab
					window.open(url, 'authn');
					break;
				case '_blank': //nw small
					h = 600;
					w = 600;
					break;
				case '_blank_m': //nw med
					h = 800;
					w = 800;
					break;
				case '_blank_l': //nw large
					h = 1000;
					w = 800;
					break;
				default:
					window.location.href = url;
					break;
			}
			// Open the window with the specified height and width
			window.open(url, 'authn', 'toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);

		} else if ( 'web_message' === settings.response_mode ) {
			// Set default values for window height and width
			var h = 600,
				w = 600;
			var left = ( screen.width / 2 ) - ( w / 2 );
			var top = ( screen.height / 2 ) - ( h / 2 );
			// Open the window with the specified height and width
			window.open(url, 'authn', 'toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);
		} else {
			// If no window type specified, redirect to the URL
			window.location.href = url;
		}

	}
}


// Display Setting page using ES5 JavaScript
document.addEventListener('DOMContentLoaded', function() {
    // Create modal dialog for displaying settings
    App.dlgConfig = new UIkit.modal( '#dlg_config' );

    // Load settings that have been previously saved
    Settings.load();

    // Get any salient data from the URL hash or query string
    if ( window.location.hash ) {
        App.getParams( window.location.hash.substring( 1 ) );
        // Clear the URL hash
        window.location.hash = '';
        history.replaceState( '', document.title, window.location.pathname );
    } else {
        var queryString = window.location.href;
        var pos = queryString.indexOf( '?' ) + 1;
        App.getParams( queryString.substring( pos ) );
    }

    // Clear any previous token data displayed
    App.clearTokenDisplay();

// Check for any error messages in the URL
    var error = App.getParam( 'error' );
    if ( error.length > 0 ) {
        App.displayError( error, App.getParam( 'error_description' ) );
    } else {
        var code = App.getParam( 'code' );
        // Check for a code or token in the URL
        if ( code.length > 20 ) {
            // Handle OAuth code exchange
            OAuth.exchangeCode( code, false, true );
        } else if ( App.getParam( 'access_token' ).length > 0 || App.getParam( 'id_token' ).length > 0 ) {
            var tokenData = {
                access_token: App.getParam( 'access_token' ),
                expires_in: App.getParam( 'expires_in' ),
                id_token: App.getParam( 'id_token' ),
                refresh_token: App.getParam( 'refresh_token' )
            };
            App.displayTokenData( tokenData );
        }
    }

    // Select all input elements with name attribute "new_email" or "new_mobile"
    var inputs = document.querySelectorAll( 'input[name=new_email],input[name=new_mobile]' );

    // Add an event listener for the "input" event on all input elements
    inputs.forEach( function ( input ) {
        input.addEventListener( 'input', function () {
            // Set the required property of the other input to false if this input is not empty
            inputs.forEach( function ( otherInput ) {
                if ( otherInput !== this ) {
                    otherInput.required = !this.value.length;
                }
            } );
        } );
    } );


// Add an event listener for web messages
	window.addEventListener( "message", function ( event ) {

		if ( App.extractHostname( event.origin, false ) !== App.extractHostname( Settings.options.provissuer, false ) ) {
			App.displayError( error, 'Event origin mismatch' );
			return;
		}

		if ( event.data && event.data.response ) {
			var tokenData = event.data.response;

			if ( typeof tokenData.code !== "undefined" && tokenData.code.length > 20 ) {
				OAuth.exchangeCode( tokenData.code, true, true );

			} else if ( ( typeof tokenData.access_token !== "undefined" && tokenData.access_token.length > 0 ) ||
				( typeof tokenData.id_token !== "undefined" && tokenData.length.length > 0 ) ) {
				var tokenData = {};
				tokenData = {
					access_token: typeof tokenData.access_token !== "undefined" ? tokenData.access_token : '',
					expires_in: tokenData.expires_in,
					id_token: typeof tokenData.id_token !== "undefined" ? tokenData.id_token : '',
					refresh_token: typeof tokenData.refresh_token !== "undefined" ? tokenData.refresh_token : ''
				};
				// Display the token data
				App.displayTokenData( tokenData );
			}

		}

	}, false );

	// persist configuration in cookie
	document.getElementById( 'btn_persistcookie' ).addEventListener( 'click', function ( e ) {
		e.preventDefault();
		if ( Settings.update() ) {
			App.setCookie( App.gCookieName, JSON.stringify( Settings.options ), 365 );
			App.displayNotification( 'Result', 'Saved for 1 year', 'success' );
		}
	} );

	document.getElementById( 'btn_persistjson' ).addEventListener( 'click', function ( e ) {
		e.preventDefault();
		if ( Settings.update() ) {
			var filename = 'config.js';
			var $jsonData = 'var config=' + JSON.stringify( Settings.options )
			var URL = window.URL || window.webkitURL;
			var textFileAsBlob = new Blob( [ $jsonData ], {
				type: 'text/plain'
			} );
			var downloadUrl = URL.createObjectURL( textFileAsBlob );

			var a = document.createElement( "a" );
			a.href = downloadUrl;
			a.download = filename;
			document.body.appendChild( a );
			a.click();
			a.remove();
		}
	} );

	// function to Start authentication
	document.getElementById( 'btn_startauth' ).addEventListener( 'click', function ( e ) {
		e.preventDefault();
		document.getElementById( 'divres' ).style.display = 'none';
		document.getElementById( 'formres' ).reset(); // clear form
		OAuth.startAuth();
	} );

	// function to Start authentication class
	var startAuthButtons = document.getElementsByClassName( 'idp-btn-startauth' );
	for ( var i = 0; i < startAuthButtons.length; i++ ) {
		startAuthButtons[ i ].addEventListener( 'click', function ( e ) {
			e.preventDefault();
			document.getElementById( 'divres' ).style.display = 'none';
			document.getElementById( 'formres' ).reset(); // clear form

			var idpname;
			if ( this.className.indexOf( 'idp-name-' ) !== -1 ) {
				var classList = this.className.split( /\s+/ );
				for ( var j = 0; j < classList.length; j++ ) {
					if ( classList[ j ].indexOf( 'idp-name-' ) !== -1 ) {
						idpname = classList[ j ].substring( 9 );
					}
				}
			}
			OAuth.startAuth( idpname );
		} );
	}


	// Edit Settings cfg key
	//this displays the setting page when you press c f g together
	var map = {
		67: false,
		70: false,
		71: false
	}; // cfg
	document.addEventListener( "keydown", function ( e ) {
		if ( e.keyCode in map ) {
			map[ e.keyCode ] = true;
			if ( map[ 67 ] && map[ 70 ] && map[ 71 ] ) {
				Settings.edit();
			}
		}
	} );
	document.addEventListener( "keyup", function ( e ) {
		if ( e.keyCode in map ) {
			map[ e.keyCode ] = false;
		}
	} );



} );