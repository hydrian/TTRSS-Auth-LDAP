<?php

/**
 * Tiny Tiny RSS plugin for LDAP authentication
 * @author tsmgeek (tsmgeek@gmail.com)
 * @author hydrian (ben.tyger@tygerclan.net)
 * @author pasbec (p.b-dev+tt-rss@mailbox.org)
 *  Requires php-ldap 
 * @version 3.0
 */

class Auth_Ldap extends Auth_Base {

    const LDAP_URI = "LDAP_URI";
    const LDAP_USE_TLS = "LDAP_USE_TLS";
    const LDAP_BIND_DN = "LDAP_BIND_DN";
    const LDAP_BIND_PW = "LDAP_BIND_PW";
    const LDAP_BASE_DN = "LDAP_BASE_DN";
    const LDAP_SEARCH_FILTER = "LDAP_SEARCH_FILTER";
    const LDAP_LOGIN_ATTRIBUTE = "LDAP_LOGIN_ATTRIBUTE";

    private function log($msg, $level = E_USER_NOTICE, $file = '', $line = 0, $context = '') {
        Logger::log_error($level, "auth_ldap: " . $msg, $file, $line, $context);
    }

    function about() {
        return array(
            3.0,
            "Authenticates against some LDAP server",
            "pasbec",
            TRUE,
			"https://github.com/pasbec/ttrss-auth-ldap"
        );
    }

    function init($host) {

        Config::add(self::LDAP_URI, "", Config::T_STRING);
        Config::add(self::LDAP_USE_TLS, "true", Config::T_BOOL);
        Config::add(self::LDAP_BIND_DN, "", Config::T_STRING);
        Config::add(self::LDAP_BIND_PW, "", Config::T_STRING);
        Config::add(self::LDAP_BASE_DN, "", Config::T_STRING);
        Config::add(self::LDAP_SEARCH_FILTER, "", Config::T_STRING);
        Config::add(self::LDAP_LOGIN_ATTRIBUTE, "", Config::T_STRING);

        $host->add_hook($host::HOOK_AUTH_USER, $this);
    }

    function authenticate($login, $password, $service = "") {

        if ($login && $password) {

            if (!function_exists('ldap_connect')) {
                trigger_error('auth_ldap requires LDAP support');
                return FALSE;
            }

            // Get configuration settings
            $URI = Config::get(self::LDAP_URI);
            $useTLS = Config::get(self::LDAP_USE_TLS);
            $bindDN = Config::get(self::LDAP_BIND_DN);
            $bindPW = Config::get(self::LDAP_BIND_PW);
            $baseDN = Config::get(self::LDAP_BASE_DN);
            $searchFilter = Config::get(self::LDAP_SEARCH_FILTER);
            $loginAttribute = Config::get(self::LDAP_LOGIN_ATTRIBUTE);

            // Check URI
            $parsedURI = parse_url($URI);
            if ($parsedURI == FALSE) {
                $this->log('Server URI is required and not defined', E_USER_ERROR);
                return FALSE;
            }
            // $scheme = $parsedURI['scheme'];

            // Check base DN
            if (empty($baseDN)) {
                $this->log('Base DN is required and not defined', E_USER_ERROR);
                return FALSE;
            }

            // Create LDAP connection
            $ldap = @ldap_connect($URI);
            if ($ldap == FALSE) {
                $this->log('Could not connect to server URI \'' . $URI . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Set protocol version 
            if (!@ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3)) {
                $this->log('Failed to set LDAP Protocol version (LDAP_OPT_PROTOCOL_VERSION) to 3', E_USER_ERROR);
                return FALSE;
            }

            // Set referrals
            if (!@ldap_set_option($ldap, LDAP_OPT_REFERRALS, FALSE)) {
                $this->log('Failed to set LDAP referrals (LDAP_OPT_REFERRALS) to FALSE', E_USER_ERROR);
                return FALSE;
            }

            // Enable TLS if enabled
            if ($useTLS) {
                if (!@ldap_start_tls($ldap)) {
                    $this->log('Failed to enable TLS for URI \'' . $URI . '\'', E_USER_ERROR);
                    return FALSE;
                }
            }

            // Process bind input
            $myBindDN = NULL;
            $myBindPW = NULL;
            if (!empty($bindDN)) {
                $myBindDN = strtr($bindDN, ['{login}' => $login]);
            }
            if (!empty($bindPW)) {
                $myBindPW = strtr($bindPW, ['{password}' => $password]);
            }

            // Bind 
            $bind = @ldap_bind($ldap, $myBindDN, $myBindPW);
            if ($bind == TRUE) {
                $this->log('Bind successful for \'' . $myBindDN . '\'');
            } else {
                $this->log('Bind failed for \'' . $myBindDN . '\'');
                return FALSE;
            }

            // Create search filter object
            $filter = str_replace('???', ldap_escape($login), $searchFilter);

            // Create search attribute array
            $attributes = array('displayName', 'title', 'sAMAccountName');
            if (!empty($loginAttribute)) {
                array_push($attributes, $loginAttribute);
            }

            // Search
            $searchResults = @ldap_search($ldap, $baseDN, $filter, $attributes, 0, 0, LDAP_DEREF_NEVER);
            if ($searchResults == FALSE) {
                $this->log('Search failed for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Check search result count
            $count = @ldap_count_entries($ldap, $searchResults);
            if ($count > 1) {
                $this->log('Multiple DNs found for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            } elseif ($count == 0) {
                $this->log('Unknown login \'' . $login . '\'');
                return FALSE;
            }

            // Get user entry
            $userEntry = @ldap_first_entry($ldap, $searchResults);
            if ($userEntry == FALSE) {
                $this->log('Unable to get user entry for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Get user attributes
            $userAttributes = @ldap_get_attributes($ldap, $userEntry);
            if ($userEntry == FALSE) {
                $this->log('Unable to get user attributes for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }
            
            // Get user DN
            $userDN = @ldap_get_dn($ldap, $userEntry);
            if ($userDN == FALSE) {
                $this->log('Unable to get user DN for login \'' . $login . '\'', E_USER_ERROR);
                return FALSE;
            }

            // Bind with search DN
            $bind = @ldap_bind($ldap, $userDN, $password);
            @ldap_close($ldap);
            if ($bind == TRUE) {
                $this->log('Authentication successful for login \'' . $userDN . '\'');

                // Get username
                if (strlen($loginAttribute) > 0) {
                    $username = $userAttributes[$loginAttribute][0];
                    if (!is_string($username)) {
                        $this->log('Unable to get login attribute \'' . $loginAttribute . '\' for login \'' . $login . '\'', E_USER_ERROR);
                        return FALSE;
                    }
                } else {
                    $username = $login;
                }

                // Successful login
                return $this->auto_create_user($username);
            } else {
                $this->log('Authentication failed for login \'' . $userDN . '\'', E_USER_ERROR);
                return FALSE;
            }
        }

        return FALSE;
    }

    function api_version() {
        return 2;
    }
}

?>
