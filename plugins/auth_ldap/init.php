<?php
/** 
 * Tiny Tiny RSS plugin for LDAP authentication 
 * @author hydrian (ben.tyger@tygerclan.net)
 * @copyright GPL2
 *  Requires php-ldap and PEAR Net::LDAP2
 * @version 0.05
 */

/**
 *  Configuration
 *  Put the following options in config.php and customize them for your environment
 *
 * 	define('LDAP_AUTH_SERVER_URI', 'ldaps://LDAPServerHostname:port/');
 *	define('LDAP_AUTH_USETLS', FALSE); // Enable TLS Support for ldaps://
 *	define('LDAP_AUTH_ALLOW_UNTRUSTED_CERT', TRUE); // Allows untrusted certificate
 *	define('LDAP_AUTH_BASEDN', 'dc=example,dc=com');
 * 	define('LDAP_AUTH_ANONYMOUSBEFOREBIND', FALSE);
 *	// ??? will be replaced with the entered username(escaped) at login 
 *	define('LDAP_AUTH_SEARCHFILTER', '(&(objectClass=person)(uid=???))');
 *	// Optional configuration
 *      define('LDAP_AUTH_BINDDN', 'cn=serviceaccount,dc=example,dc=com');
 *      define('LDAP_AUTH_BINDPW', 'ServiceAccountsPassword');
 *      define('LDAP_AUTH_LOGIN_ATTRIB', 'uid');
 *	  
 *  define('LDAP_AUTH_SCHEMA_CACHE_ENABLE', TRUE);
 *    Enables Schema Caching (Recommended) 
 *  define('LDAP_AUTH_SCHEMA_CACHE_TIMEOUT', 86400);
 *    Max time a schema cache is kept (seconds) 
 *  define('LDAP_AUTH_LOG_ATTEMPTS', FALSE);
 *    Enable Debug Logging
 *  define('LDAP_AUTH_DEBUG', FALSE);
 *    
 *    
 *    
 */

/**
 *	Notes -
 *	LDAP search does not support follow ldap referals. Referals are disabled to 
 *	allow proper login.  This is particular to Active Directory.  
 * 
 *	Also group membership can be supported if the user object contains the
 *	the group membership via attributes.  The following LDAP servers can 
 *	support this.   
 * 	 * Active Directory
 *   * OpenLDAP support with MemberOf Overlay
 *
 */
class Auth_Ldap extends Plugin implements IAuthModule {

	private $link;
	private $host;
	private $base;
	private $logClass;
	private $ldapObj = NULL;


	function about() {
		return array(0.04,
			"Authenticates against an LDAP server (configured in config.php)",
			"hydrian",
			true);
	}

	function init($host) {
		$this->link = $host->get_link();
		$this->host = $host;
		$this->base = new Auth_Base($this->link);

		$host->add_hook($host::HOOK_AUTH_USER, $this);
	}
	
	private function _log($msg, $level = E_USER_WARNING) {
		$loggerFunction = Logger::get();
		if (is_object($loggerFunction)) {
			$loggerFunction->log_error($level, $msg);
		} else {
			trigger_error($msg, $level);
		}
		
	}
	
	/**
	 * Logs login attempts
	 * @param string $username Given username that attempts to log in to TTRSS
	 * @param string $result "Logging message for type of result. (Success / Fail)"
	 * @return boolean
	 * @deprecated
	 * 
	 * Now that _log support syslog and log levels and graceful fallback user.  
	 */
	private function _logAttempt($username, $result) {
		
		
		return trigger_error('TT-RSS Login Attempt: user '.(string)$username.
			' attempted to login ('.(string)$result.') from '.(string)$ip,
			E_USER_NOTICE
		);	
	}
	
	/**
	 * Finds client's IP address
	 * @return string
	 */
	private function _getClientIP () {
		if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
			//check ip from share internet
		
			$ip=$_SERVER['HTTP_CLIENT_IP'];
		}
		elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
			//to check ip is pass from proxy
			$ip=$_SERVER['HTTP_X_FORWARDED_FOR'];
		}
		else {
			$ip=$_SERVER['REMOTE_ADDR'];
		}
		
		return $ip;
	}

	/**
	 * Main Authentication method
	 * Required for plugin interface 
	 * @param unknown $login  User's username
	 * @param unknown $password User's password
	 * @return boolean
	 */
	function authenticate($login, $password) {
		if ($login && $password) {
			
			if (!function_exists('ldap_connect')) {
				trigger_error('auth_ldap requires PHP\'s PECL LDAP package installed.');
				return FALSE;
			}
			if (!require_once('Net/LDAP2.php')) { 
				trigger_error('auth_ldap requires the PEAR package Net::LDAP2');
				return FALSE;
			}
			
			$debugMode = defined('LDAP_AUTH_DEBUG') ?
				LDAP_AUTH_DEBUG : FALSE;
			
			$anonymousBeforeBind=defined('LDAP_AUTH_ANONYMOUSBEFOREBIND') ?
				LDAP_AUTH_ANONYMOUSBEFOREBIND : FALSE;
			
			$bindDN = defined('LDAP_AUTH_BINDDN') ? LDAP_AUTH_BINDDN : null;
			$bindPW = defined('LDAP_AUTH_BINDPW') ? LDAP_AUTH_BINDPW : null;
			
			$parsedURI=parse_url(LDAP_AUTH_SERVER_URI);
			if ($parsedURI === FALSE) {
				$this->_log('Could not parse LDAP_AUTH_SERVER_URI in config.php');
				return FALSE;
			}
			$ldapConnParams=array(
				'host'=>$parsedURI['scheme'].'://'.$parsedURI['host'],
				'basedn'=>LDAP_AUTH_BASEDN,
				'options' => array('LDAP_OPT_REFERRALS' => 0)
			);

			if (!$anonymousBeforeBind) {
				$ldapConnParams['binddn']= $bindDN;
				$ldapConnParams['bindpw']= $bindPW;
			}
			$ldapConnParams['starttls']= defined('LDAP_AUTH_USETLS') ?
				LDAP_AUTH_USETLS : FALSE;
					
			if (is_int($parsedURI['port'])) {
				$ldapConnParams['port']=$parsedURI['port'];
			}
			
			$ldapSchemaCacheEnable= defined('LDAP_AUTH_SCHEMA_CACHE_ENABLE') ?
				LDAP_AUTH_SCHEMA_CACHE_ENABLE : TRUE;
			
			$ldapSchemaCacheTimeout= defined('LDAP_AUTH_SCHEMA_CACHE_TIMEOUT') ?
				LDAP_AUTH_SCHEMA_CACHE_TIMEOUT : 86400;
			
			$logAttempts= defined('LDAP_AUTH_LOG_ATTEMPTS') ? 
				LDAP_AUTH_LOG_ATTEMPTS : FALSE;
			
			// Making connection to LDAP server
			if (LDAP_AUTH_ALLOW_UNTRUSTED_CERT === TRUE) {
				putenv('LDAPTLS_REQCERT=never');
			}
			$this->ldapObj = new Net_LDAP2;
			$ldapConn=$this->ldapObj->connect($ldapConnParams);
 			if ($this->ldapObj->isError($ldapConn)) {
				$this->_log(
					'Could not connect to LDAP Server: '.$ldapConn->getMessage(), 
					E_USER_ERROR
				);
				return FALSE;
			}
			// Bind with service account if orignal connexion was anonymous
			if ($anonymousBeforeBind) {
				$binding=$this->ldapObj->bind($bindDN, $bindPW);
				if ($this->ldapObj->isError($binding)) {
					$this->_log(
						'Cound not bind service account: '.$binding->getMessage(),
						E_USER_ERROR
					);
					return FALSE;
				}
			} 
			
			//Cache LDAP Schema
			if ($ldapSchemaCacheEnable) {
				if (!sys_get_temp_dir()) {
					$tmpFile=tempnam();
					$tmpDir=dirname($tmpFile);
					unlink($tmpFile);
					unset($tmpFile);
				} else {
					$tmpDir=sys_get_temp_dir();
				}
				if (empty($parsedURI['port'])) {
					$ldapPort= $parsedURI['scheme'] == 'ldaps' ?
						636 : 389;
				} else {
					$ldapPort=$parsedURI['port'];
				}
				$cacheFileLoc=
					$tmpDir.'/ttrss-ldapCache-'.
					$parsedURI['host'].':'.$ldapPort.
					'.cache';
				if ($debugMode) $this->_log('Schema Cache File: '.$cacheFileLoc, E_USER_NOTICE);
				$schemaCacheConf=array(
						'path'=>$cacheFileLoc,
						'max_age'=>$ldapSchemaCacheTimeout
				);
				$schemaCacheObj= new Net_LDAP2_SimpleFileSchemaCache($schemaCacheConf);
				$ldapConn->registerSchemaCache($schemaCacheObj);
				$schemaCacheObj->storeSchema($ldapConn->schema());
			}
			
			//Searching for user
			$completedSearchFilter=str_replace('???',$login,LDAP_AUTH_SEARCHFILTER);
			$filterObj=Net_LDAP2_Filter::parse($completedSearchFilter);
			if (PEAR::isError($filterObj)) {
				$this->_log( 'Could not parse LDAP Search filter', E_USER_ERROR);
				return FALSE;
			}
			$searchResults=$this->ldapObj->search(LDAP_AUTH_BASEDN, $filterObj);
			if ($this->ldapObj->isError($searchResults)) {
				$this->_log('LDAP Search Failed: '.$searchResults->getMessage());
				return FALSE;
			} elseif ($searchResults->count() === 0) {
				$this->_log((string)$login, 'Unknown User',	E_USER_NOTICE);
				return FALSE;
			} elseif ($searchResults->count() > 1 ) {
				$this->_log('Multiple DNs found for username '.$login, E_USER_WARNING);
				return FALSE;
			}
			//Getting user's DN from search
			$userEntry=$searchResults->shiftEntry();
			$userDN=$userEntry->dn();
			//Binding with user's DN. 
			$this->_log('Try binding with user\'s DN: '.$userDN);
			$loginAttempt=$ldapConn->bind($userDN, $password);
			$ldapConn->disconnect();
			if ($loginAttempt === TRUE) {
				$this->_log('User: '.(string)$login.' authentication successful', E_USER_NOTICE);
				return $this->base->auto_create_user($login);
			} elseif ($loginAttempt->getCode() == 49) {
				$this->_log('User: '.(string)$login.' authentication failed', E_USER_NOTICE);
				return FALSE;
			} else {
				$this->_log('Unknown Error: Code: '.$loginAttempt->getCode().
					' Message: '.$loginAttempt->getMessage().' user('.(string)$login.')');
				return FALSE;
			}
		}
		return false;
	}
	
	/**
	 * Returns plugin API version
	 * Required for plugin interface
	 * @return number
	 */
	function api_version() {
		return 2;
	}

}

?>
