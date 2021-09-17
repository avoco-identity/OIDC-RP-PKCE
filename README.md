# OpenID Connect (OIDC) Relying Party(RP) Library for JavaScript
The Avoco Identity Test OIDC RP Library for JavaScript enables JavaScript (JS) applications to authenticate Users to the Avoco Identity OIDC Trus-t Hub, IdP, or PDS.
It enables your app to get tokens to access the verified user attributes/claims from Trus-t solutions.
To use this library with Trus-t deployment, you will need to have your application registered with the Trust-t service provider.
## Repository

### library
The app/lib folder contains the source code for The JS test Library oidcrpbase.js
The library relies on sha256.js

### configurations
The configurations can be set or altered through the use of a config file or a cookie.
See config.js.dst for basic configurations.
The configurations can be altered at any time, this is not suitable for a production system.
#### cookie configurations
To set the configurations or update the configurations at any time, press the cfg keys together.
The cookie configurations will override the file based configurations.
#### file based configurations
The configurations are stored in a java script file named config.js. See the example config.js.dst
### Warning
The configurations for this relying party can be altered at any time by the user, this Relying party is only suitable for testing.