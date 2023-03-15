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
var App = {
    gCookieName: 'oidcrpsettings',
    getParams: function(q) {
        // "use strict";
        var hashParams = {};
        var e,
            a = /\+/g, // Regex for replacing addition symbol with a space
            r = /([^&;=]+)=?([^&;]*)/g,
            d = function(s) {
                return decodeURIComponent(s.replace(a, " "));
            }

        while (e = r.exec(q))
            hashParams[d(e[1])] = d(e[2]);

        this.urlParams = hashParams;
    },

    // safe return of param item from App.urlParams
    getParam: function(name) {
        if (!this.urlParams) {
            return '';
        }
        if (this.urlParams[name]) {
            return this.urlParams[name];
        } else {
            return '';
        }
    },

    displayNotification: function(title, msg, stat, sticky) {
        UIkit.notification('<span class="uk-text-bold">' + title + '</span><br>' + msg, {
            status: stat,
            timeout: sticky === true ? 0 : 6000
        });
    },

    displayError: function(error, error_description) {
        var msg = 'Error: ' + error + '<br>Description: ' + error_description;
        this.displayNotification('Information', msg, 'danger');
    },

    // creates a secure cookie
    setCookie: function(c_name, c_value, c_exp_days) {
        var expires = '';
        if (c_exp_days) {
            var date = new Date();
            date.setDate(date.getDate() + c_exp_days);
            expires = '; expires=' + date.toGMTString();
        }

        document.cookie = `${c_name}=${c_value}${expires};secure;path=${window.location.pathname}`;
    },

    getCookie: function(c_name) {
        var i, x, y, p, ARRcookies = document.cookie.split(";");
        for (i = 0; i < ARRcookies.length; i++) {
            p = ARRcookies[i].indexOf("=");
            if (p > -1) {
                x = ARRcookies[i].substr(0, p);
                y = ARRcookies[i].substr(p + 1);
                x = x.replace(/^\s+|\s+$/g, "");
                if (x === c_name)
                    return unescape(y);
            }
        }
        return '';
    },



    getRandomString: function(length) {
        var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var i, values, result = '';

        values = new Uint32Array(length);
        window.crypto.getRandomValues(values);
        for (i = 0; i < length; i++) {
            result += charset[values[i] % charset.length];
        }
        return result;

    },

    // url safe base64 encode
    base64URLEncode: function(data) {
        return btoa(data)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    },

    // unix time to local
    displayLocalTime: function(epochTime) {
        var dt = new Date(epochTime * 1000);
        return dt.toLocaleString();
    },

    // returns callback URL - current window URL, without query string or hash
    getCallback: function() {

        //default redirect_uri callback
        return window.location.href.split("?")[0].split("#")[0];
    },

    // displays token data
    displayTokenData: function(tokenData) {
        if (tokenData.id_token) {
            // display token content
            var json = this.parseJwt(tokenData.id_token);
            $('#dividtoken').html('<p>ID Token</p>' + this.formatJSON(this.syntaxHighlight(JSON.stringify(json, undefined, 2))));
        } else {
            $('#dividtoken').html('');
        }

        if (tokenData.access_token) {
            // use token to get claims
            $.ajax({
                type: 'GET',
                url: Settings.options.profileurl,
                headers: {
                    'Authorization': 'Bearer ' + tokenData.access_token
                },
                dataType: 'json',
                contentType: 'application/json',
                success: function(data) {

                    var checkjwt;
                    try {
                        checkjwt = App.parseJwt(data);
                    } catch (e) {
                        // not jwt
                    }
                    if (checkjwt) {
                        data = checkjwt;
                    }

                    if (data.picture) {
                        data.picture = '';
                    }
                    $('#divattr').html(App.formatJSON(App.syntaxHighlight(JSON.stringify(data))));

                    if (data.id) {
                        $('#userid').val(data.id);
                    }
                    if (data.name) {
                        $('#username').val(data.name);
                    }
                    if (data.email) {
                        $('#useremail').val(data.email);
                    }
                    if (data.mobile) {
                        $('#usermobile').val(data.mobile);
                    }
                    if (data.dateofbirth) {
                        $('#userdob').val(data.dateofbirth);
                    }
                    if (data.address) {
                        // formatted address has line breaks - replace with space
                        if (data.address.formatted) {
                            var addr = data.address.formatted.replace(/(\n)+/g, ' ');
                            $('#useraddress').val(addr);
                        }
                    }

                    // hide / show fields according to settings
                    App.showClaimsFields();

                    $('#divres').show();
                },
                error: function(jqXHR, textStatus, errorThrown) {
                    App.displayError(jqXHR.responseJSON.error, jqXHR.responseJSON.error_description);
                }
            });

        }
    },

    showClaimsFields: function() {
        if (Settings.options.fields) {
            $.each(Settings.options.fields, function(key, value) {
                if (value === true) {
                    $('#field_' + key).show();
                } else {
                    $('#field_' + key).hide();
                }

            });
        }

    },

    parseJwt: function(token) {
        var base64Url = token.split('.')[1];
        var base64 = base64Url.replace('-', '+').replace('_', '/');
        return JSON.parse(window.atob(base64));
    },

    formatJSON: function(json) {
        return json.replace(/,/g, ",<br>");
    },

    syntaxHighlight: function(json) {
        json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, function(match) {
            var cls = 'number';
            if (/^"/.test(match)) {
                if (/:$/.test(match)) {
                    cls = 'key';
                } else {
                    cls = 'string';
                }
            } else if (/true|false/.test(match)) {
                cls = 'boolean';
            } else if (/null/.test(match)) {
                cls = 'null';
            }
            return '<span class="' + cls + '">' + match + '</span>';
        });
    },

    extractHostname: function(url, tld) {
        let hostname;

        // find & remove protocol (http, ftp, etc.) and get hostname
        if (url.indexOf('://') > -1) {
            hostname = url.split('/')[2];
        } else {
            hostname = url.split('/')[0];
        }

        // find & remove port number
        hostname = hostname.split(':')[0];

        // find & remove "?"
        hostname = hostname.split('?')[0];

        if (tld) {
            let hostnames = hostname.split('.');
            hostname = hostnames[hostnames.length - 2] + '.' + hostnames[hostnames.length - 1];
        }

        return hostname;
    },
    clearTokenDisplay: function() {
        $('#dividtoken').html('');
        $('#divattr').html('');
    }
};
//End APP


var Settings = {
    options: {},
    update: function() {
        var settings = {};

        if ($('#form-config')[0].checkValidity()) {
            settings.authnurl = $('#authnurl').val();
            settings.tokenurl = $('#tokenurl').val();
            settings.profileurl = $('#profileurl').val();
            settings.jwksurl = $('#jwksurl').val();

            settings.provissuer = $('#provissuer').val();
            settings.oauth_server = $('#oauth_server').val();
            settings.ciba_url = $('#ciba_url').val();

            settings.oauth_clientid = $('#oauth_clientid').val();


            settings.idp_hint = $('#idp_hint').val();
            settings.request_mode = $('#request_mode').val();
            settings.response_mode = $('#response_mode').val();
            settings.window_type = $('#window_type').val();


            settings.oauth_scope = $('#oauth_scope').val();

            settings.oauth = $('#useoauth2').is(':checked') ? true : false;

            settings.acr_values = $('#acr_values').val();

            settings.fields = {};
            settings.fields.name = $('#form_name').is(':checked') ? true : false;
            settings.fields.email = $('#form_email').is(':checked') ? true : false;
            settings.fields.mobile = $('#form_mobile').is(':checked') ? true : false;
            settings.fields.dob = $('#form_dob').is(':checked') ? true : false;
            settings.fields.address = $('#form_address').is(':checked') ? true : false;


            this.options = settings;
            return true;
        } else {
            $('<input type="submit">').hide().appendTo($('#form-config')).click().remove();
            return false;
        }
    },

    import: function(settings) {
        this.options = settings;


        $('#authnurl').val(this.options.authnurl);
        $('#tokenurl').val(this.options.tokenurl);
        $('#profileurl').val(this.options.profileurl);
        $('#jwksurl').val(this.options.jwksurl);

        $('#provissuer').val(this.options.provissuer);
        $('#oauth_server').val(this.options.oauth_server);
        $('#ciba_url').val(this.options.ciba_url);

        $('#oauth_clientid').val(this.options.oauth_clientid);


        $('#useoauth2').prop('checked', this.options.oauth);
        $('#idp_hint').val(this.options.idp_hint);
        $('#request_mode').val(this.options.request_mode);
        $('#response_mode').val(this.options.response_mode);
        $('#window_type').val(this.options.window_type);

        $('#oauth_scope').val(this.options.oauth_scope);

        $('#acr_values').val(this.options.acr_values);

        if (this.options.fields) {
            $('#form_name').prop('checked', this.options.fields.name);
            $('#form_email').prop('checked', this.options.fields.email);
            $('#form_mobile').prop('checked', this.options.fields.mobile);
            $('#form_dob').prop('checked', this.options.fields.dob);
            $('#form_address').prop('checked', this.options.fields.address);
        }
    },

    load: function() {
        var cookieData = App.getCookie(App.gCookieName);

        // try settings from cookie first
        if (cookieData.length > 0) {
            try {
                var jsonData = JSON.parse(cookieData);
                this.import(jsonData);
                return;
            } catch (objError) {

            }
        } else {
            // try config file
            if (typeof(config) != "undefined") {
                this.import(config);
                return;
            }
        }

        this.edit();
    },
    edit: function() {

        // set discovery url
        if (this.options.provissuer != undefined && this.options.provissuer.length > 0) {
            $('#discep').attr('href', this.options.provissuer + '/.well-known/openid-configuration');
            $('#discep').show();
        } else {
            $('#discep').hide();
        }


        App.dlgConfig.show();
    }
};

var OAuth = {

    exchangeCode: function(code, isWebMessage, nosecret) {
        // exchange code for token
        var settings = Settings.options;

        var dt = {
            code: code,
            grant_type: 'authorization_code',
            client_id: settings.oauth_clientid,
            redirect_uri: App.getCallback()
        };

        if (nosecret === undefined || nosecret === null || nosecret === false) {
            dt.client_secret = settings.oauth_clientsecret;
        }

        // add code verifier if set
        if (sessionStorage.codeVerifier && sessionStorage.codeVerifier.length > 0) {
            dt.code_verifier = sessionStorage.codeVerifier;
        }

        $.ajax({
            type: 'POST',
            url: settings.tokenurl,
            data: JSON.stringify(dt),
            contentType: 'application/json',
            dataType: 'json',
            success: function(data) {

                App.displayTokenData(data);

                sessionStorage.codeVerifier = '';
            },
            error: function(jqXHR, textStatus, errorThrown) {
                App.displayError(jqXHR.responseJSON.error, jqXHR.responseJSON.error_description);
            }
        });

    },


    startAuth: function(idpselectbutton) {
        if (idpselectbutton === undefined) {
            idpselectbutton = '';
        }
        // start authorization code flow

        sessionStorage.state = App.getRandomString(32); // verify this matches the value returned in authorization code response
        var settings = Settings.options;


        var qs = 'client_id=' + settings.oauth_clientid;
        var scope = settings.oauth_scope;

        qs += '&state=' + sessionStorage.state;
        if (settings.response_mode.length > 0) {
            qs += '&response_mode=' + settings.response_mode;
        }

        qs += '&redirect_uri=' + encodeURIComponent(App.getCallback());

        if (Settings.options.oauth !== true) {
            // If OIDC generate nonce and add openid to scope
            sessionStorage.nonce = App.getRandomString(32);
            qs += '&nonce=' + sessionStorage.nonce;
            if (scope.indexOf('openid') === -1) {
                scope += ' openid';
            }
        }

        qs += '&scope=' + scope;

        // PKCE stuff
        sessionStorage.codeVerifier = App.base64URLEncode(App.getRandomString(32));
        var hashObj = new jsSHA('SHA-256', 'TEXT', 1);
        hashObj.update(sessionStorage.codeVerifier);
        var b64_hash = App.base64URLEncode(hashObj.getHash('BYTES'));

        qs += '&response_type=code';
        qs += '&code_challenge=' + b64_hash + '&code_challenge_method=S256';

        //get idp_hint preferred provider
        if (idpselectbutton !== '' && idpselectbutton !== undefined) {
            qs += '&idp_hint=' + idpselectbutton;
        } else if (settings.idp_hint.length) {
            qs += '&idp_hint=' + settings.idp_hint;
        }

        var url = settings.authnurl + '?' + qs;
        if (null != settings.window_type) {
            var h = 600,
                w = 600;
            var left = (screen.width / 2) - (w / 2);
            var top = (screen.height / 2) - (h / 2);
            windowopenlab: {
                if ('_default' === settings.window_type) { //browser default
                    window.open(url, 'authn');
                    break windowopenlab;
                } else if ('_tab' === settings.window_type) { //tab
                    window.open(url, 'authn');
                    break windowopenlab;
                } else if ('_blank' === settings.window_type) { //nw small
                    var h = 600,
                        w = 600;
                } else if ('_blank_m' === settings.window_type) { //nw med
                    var h = 800,
                        w = 800;
                } else if ('_blank_l' === settings.window_type) { //nw large
                    var h = 1000,
                        w = 800;
                } else {
                    window.location.href = url;
                    break windowopenlab;
                }
                window.open(url, 'authn', 'toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);

            }

        } else if ('web_message' === settings.response_mode) {
            var h = 600,
                w = 600;
            var left = (screen.width / 2) - (w / 2);
            var top = (screen.height / 2) - (h / 2);
            window.open(url, 'authn', 'toolbar=no, location=no, directories=no, status=no, menubar=no, scrollbars=no, resizable=no, copyhistory=no, width=' + w + ', height=' + h + ', top=' + top + ', left=' + left);
        } else {
            window.location.href = url;
        }
    }
}


//Display Setting page
$(function() {
    // create modal
    App.dlgConfig = new UIkit.modal('#dlg_config');

    // load settings
    Settings.load();

    // get any salient data from hash tag or query string
    if (window.location.hash) {
        App.getParams(window.location.hash.substring(1));
        // clear hashtag
        window.location.hash = '';
        history.replaceState('', document.title, window.location.pathname);
    } else {
        var queryString = window.location.href;
        var pos = queryString.indexOf('?') + 1;
        App.getParams(queryString.substring(pos));
    }

    App.clearTokenDisplay();

    var error = App.getParam('error');
    if (error.length > 0) {
        App.displayError(error, App.getParam('error_description'));
    } else {
        var code = App.getParam('code');
        if (code.length > 20) {
            OAuth.exchangeCode(code, false, true);

        } else if (App.getParam('access_token').length > 0 || App.getParam('id_token').length > 0) {
            var tokenData = {
                access_token: App.getParam('access_token'),
                expires_in: App.getParam('expires_in'),
                id_token: App.getParam('id_token'),
                refresh_token: App.getParam('refresh_token')
            };
            App.displayTokenData(tokenData);

        }
    }

    var $inputs = $('input[name=new_email],input[name=new_mobile]');
    $inputs.on('input', function() {
        // Set the required property of the other input to false if this input is not empty.
        $inputs.not(this).prop('required', !$(this).val().length);
    });

    // for web_message
    window.addEventListener("message", function(event) {

        if (App.extractHostname(event.origin, false) !== App.extractHostname(Settings.options.provissuer, false)) {
            App.displayError(error, 'Event origin mismatch');
            return;
        }

        if (event.data && event.data.response) {
            var tokenData = event.data.response;

            if (typeof tokenData.code !== "undefined" && tokenData.code.length > 20) {
                OAuth.exchangeCode(tokenData.code, true, true);

            } else if ((typeof tokenData.access_token !== "undefined" && tokenData.access_token.length > 0) ||
                (typeof tokenData.id_token !== "undefined" && tokenData.length.length > 0)) {
                var tokenData = {};
                tokenData = {
                    access_token: typeof tokenData.access_token !== "undefined" ? tokenData.access_token : '',
                    expires_in: tokenData.expires_in,
                    id_token: typeof tokenData.id_token !== "undefined" ? tokenData.id_token : '',
                    refresh_token: typeof tokenData.refresh_token !== "undefined" ? tokenData.refresh_token : ''
                };
                console.log("here!");
                App.displayTokenData(tokenData);
            }

        }

    }, false);

    // persist configuration in cookie
    $('#btn_persistcookie').click(function(e) {
        e.preventDefault();

        if (Settings.update()) {
            App.setCookie(App.gCookieName, JSON.stringify(Settings.options), 365);
            App.displayNotification('Result', 'Saved for 1 year', 'success');
        }

    });

    $('#btn_persistjson').click(function(e) {
        e.preventDefault();

        if (Settings.update()) {
            var filename = 'config.js';
            var $jsonData = 'var config=' + JSON.stringify(Settings.options)

            var URL = window.URL || window.webkitURL;
            var textFileAsBlob = new Blob([$jsonData], {
                type: 'text/plain'
            });
            var downloadUrl = URL.createObjectURL(textFileAsBlob);

            var a = document.createElement("a");
            a.href = downloadUrl;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            a.remove();
        }
    });

    // function to Start authentication
    $('#btn_startauth').click(function(e) {
        e.preventDefault();

        $('#divres').hide();
        $('#formres')[0].reset(); // clear form

        OAuth.startAuth();

    });
    // function to Start authentication class
    $('.idp-btn-startauth').click(function(e) {
        e.preventDefault();

        $('#divres').hide();
        $('#formres')[0].reset(); // clear form

        // check if idp-name exists add class idp-name-THENAMEOFYOURIDP and idp-btn-startauth
        if ($(this).attr('class').indexOf('idp-name-') !== -1) {

            var idpname = (this.className.match(/(^|\s)(idp\-name\-[^\s]*)/) || [, , ''])[2];
            idpname = idpname.substring(9);
            OAuth.startAuth(idpname);
        } else {
            OAuth.startAuth();
        }


    });

    // Edit Settings cfg key
    var map = {
        67: false,
        70: false,
        71: false
    }; // cfg
    $(document).keydown(function(e) {
        if (e.keyCode in map) {
            map[e.keyCode] = true;
            if (map[67] && map[70] && map[71]) {
                Settings.edit();
            }
        }
    }).keyup(function(e) {
        if (e.keyCode in map) {
            map[e.keyCode] = false;
        }
    });
});