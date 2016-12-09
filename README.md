Tiny Tiny RSS Contributed files
===============================

This repository contains files which had been removed from trunk for
whatever reason (usually it's because I can't properly test their functionality).


Usage instructions
=================

First of app, make sure you have `php5-ldap` installed.
For Debian users, just do

`sudo apt-get install php5-ldap`


Now, open the `config.php` file in your TT-RSS directory.

First, add the plugin to the list of enabled plugins:

```php
/// append auth_ldap to the list
define('PLUGINS', 'auth_ldap, auth_internal, note');
```

Second, add the following lines to the file and fill in the details of your ldap installation:

```php
// Required parameters:
define('LDAP_AUTH_SERVER_URI', 'ldap://localhost:389/');
define('LDAP_AUTH_USETLS', FALSE); // Enable StartTLS Support for ldap://
define('LDAP_AUTH_ALLOW_UNTRUSTED_CERT', TRUE); // Allows untrusted certificate
define('LDAP_AUTH_BASEDN', 'dc=example,dc=com');
define('LDAP_AUTH_ANONYMOUSBEFOREBIND', FALSE);
// ??? will be replaced with the entered username(escaped) at login
define('LDAP_AUTH_SEARCHFILTER', '(&(objectClass=person)(uid=???))');

// Optional configuration
define('LDAP_AUTH_BINDDN', 'cn=serviceaccount,dc=example,dc=com');
define('LDAP_AUTH_BINDPW', 'ServiceAccountsPassword');
define('LDAP_AUTH_LOGIN_ATTRIB', 'uid');
define('LDAP_AUTH_LOG_ATTEMPTS', FALSE);

// Enable Debug Logging
define('LDAP_AUTH_DEBUG', FALSE);
```
