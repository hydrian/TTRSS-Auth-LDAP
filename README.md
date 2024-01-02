# LDAP authentication for Tiny Tiny RSS

## Installation

1. Follow Tiny Tiny RSS [docker installation guide](https://tt-rss.org/wiki/InstallationNotes) but use some modified image to include `php83-ldap` by creating a simple `Dockerfile` like
    ```Dockerfile
    FROM cthulhoo/ttrss-fpm-pgsql-static:latest

    RUN apk add php83-ldap
    ```
1. Create a bind mount for `<HOST_DIR>` -> `/var/lib/html/tt-rss/plugins.local`
1. Clone the plugin to `<HOST_DIR>/auth_ldap`
1. Enable the plugin by adding `auth_ldap` to `TTRSS_PLUGINS`, e.g.
    ```ini
     TTRSS_PLUGINS=auth_ldap, auth_internal, note, nginx_xaccel
    ```
1. Configure the plugin via its own environment variables:

    ```ini
    # Example for Active Directory without separate bind account
    TTRSS_LDAP_URI=ldap://dc.some.example.com
    TTRSS_LDAP_USE_TLS=true
    TTRSS_LDAP_BASE_DN=CN=Users,DC=some,DC=example,DC=com
    TTRSS_LDAP_BIND_DN=SOME\{login} # {login} gets dynamically replaced
    TTRSS_LDAP_BIND_PW={password} # {password} gets dynamically replaced
    TTRSS_LDAP_SEARCH_FILTER=(&(objectClass=person)(sAMAccountName=???))
    # TTRSS_LDAP_SEARCH_FILTER=(&(objectClass=person)(memberOf=CN=TinyTinyRSS-Users,CN=Users,DC=some,DC=example,DC=com)(sAMAccountName=???))
    TTRSS_LDAP_LOGIN_ATTRIBUTE=sAMAccountName

    # General example using dedicated bind account
    TTRSS_LDAP_URI=ldap://localhost
    TTRSS_LDAP_USE_TLS=false
    TTRSS_LDAP_BASE_DN=DC=example,DC=com
    TTRSS_LDAP_BIND_DN=CN=some-bind-user,DC=example,DC=com
    TTRSS_LDAP_BIND_PW=<SOME_BIND_USER_PASSWORD>
    TTRSS_LDAP_SEARCH_FILTER=(&(objectClass=person)(uid=???))
    TTRSS_LDAP_LOGIN_ATTRIBUTE=uid

    # General example using anonymous bind
    TTRSS_LDAP_URI=ldap://localhost
    TTRSS_LDAP_USE_TLS=false
    TTRSS_LDAP_BASE_DN=DC=example,DC=com
    TTRSS_LDAP_SEARCH_FILTER=(&(objectClass=person)(uid=???))
    TTRSS_LDAP_LOGIN_ATTRIBUTE=uid
    ```