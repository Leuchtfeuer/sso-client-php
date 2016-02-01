<?php

// Debug switch
// $debugflag=true;

# --
#
# Signature-Based Single Sign-On Framework
# Direct SSO Client (PHP)
#
# Version            : 0.8.0
# Last update        : 16.09.2015
#
# (c) Bitmotion GmbH, Hannover, Germany
# http://www.single-signon.com
#
# --

#############################################################################
# Copyright (C) 2003-2006 Dietrich Heise - net&works GmbH - <heise@naw.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
#############################################################################

class DirectSSOClient {

	private $configFile;
	private $tokensFile;
	private $logLevel;
	private $confline = '';
	private $user;
	private $appId;
	private $publicSslKey;
	private $externalOpenssl;
	private $tmpSignaturePrefix;
	private $tmpSignatureDir;
	private $cmd;
	private $logFile;
	private $windowsServer;
	private $thisTime;
	private $expires;
	private $sign;
	private $data;
	private $debugflag;
	private $action;
	private $userData;
	private $version;
	private $flags;
	private $logging;
	private $logit;
	private $errorCodes = array(
		0 => "directsso: file access error - directsso config file",    //
		1 => "directsso: Invocation error - missing USER",        //user_missing
		2 => "directsso: Invocation error - missing APP_ID",    //appid_missing
		3 => "directsso: Invocation error - missing ExpirationTime",//expires_missing
		4 => "directsso: Invocation error - missing signature",    //signature_missing
		10 => "directsso: error in configfile - missing public_ssl_key",//sslkey_missingconf
		11 => "directsso: error in configfile - missing tokensfile entry",//usedtokens_missingconf
		12 => "directsso: error in configfile - missing logfile",    //logfile_missingconf
		20 => "directsso: file access error - SSL public key file",    //sslkey_missingfile
		21 => "directsso: file access error - UsedTokens file",    //usedtokens_missingfile
		22 => "directsso: file access error - log file",        //logfile_missingfile
		30 => "directsso: validation error - APP_ID is invalid or not configured",//appid_unknown
		31 => "directsso: validation error - SSO Link has been used before",//usedtokens_allreadyused
		32 => "directsso: validation error - signature invalid",    //signature_invallid
		33 => "directsso: validation error - SSO Link expired (or system clock out of sync?)!", //expires_exeeded
		40 => "directsso: An error in the Third Party Application Adapter occurred. It said: " //app_error
	);
	private $errorText;

	public function __construct($configFile) {
		$this->configFile = $configFile;

		$this->readConfig();
		$this->errorcode();

		$this->logging = touch($this->logFile);
		$this->logging = @fopen($this->logFile, 'a');
		if (!$this->logging) {            // can't open config
			$this->errorpage(22);
		}

		// get variables
		$this->getvars();

		// check for user,app_id and expires
		$this->checkvars();

		// create and check signed string
		if (!$this->version) {
			$this->data = 'user=' . $this->user . '&tpa_id=' . $this->appId . '&expires=' . $this->expires;
		} else {
			if (version_compare("2.1", $this->version, '>=')) {
				$this->data = 'version=' . $this->version . '&user=' . $this->user . '&app_id=' . $this->appId . '&expires=' . $this->expires . '&action=' . $this->action . '&flags=' . $this->flags . '&userdata=' . $this->userData;
			} else {
				$this->data = 'version=' . $this->version . '&user=' . $this->user . '&tpa_id=' . $this->appId . '&expires=' . $this->expires . '&action=' . $this->action . '&flags=' . $this->flags . '&userdata=' . $this->userData;
			}
		}
		if ($this->debugflag) {
			printf('<br>Parameters detected: ' . $this->data);
		}
		if (version_compare("2.0", $this->version, '<=')) {
			// decode $userdata and $flags and evaluate $flags
			$this->userData = base64_decode($this->userData);
			if ($this->debugflag) {
				printf('<br>submitted userdata: ' . $this->userData);
			}

			$tmpflags = explode('|', base64_decode($this->flags));
			unset($this->flags);
			for ($i = 0; $i < count($tmpflags); $i++) {
				$tmpflag = explode('=', $tmpflags[$i]);
				$this->flags["$tmpflag[0]"] = $tmpflag[1];
			}
			if ($this->debugflag) {
				printf('<br>flags: ');
				print_r($this->flags);
			}
		}

		// read config, set $confline und $public_ssl_key
		$this->readconfig();

		// check signature
		$this->checksign();

		// link allready used?

		$this->checkused();

		// run SSO-script and process return values
		$sso_values = array();

		if ($this->cmd == 'cmd') {
			// get protocol version from the adapter

			$getver = explode(' ', $this->confline, 2);
			$getver = $getver[0] . ' --get_version' . PHP_EOL;
			$tempver = '';
			exec($getver, $tempver);
			$tempver = preg_split("/[\s,]+/", $tempver[0]);
			if ($tempver[0] && $tempver[0] != "Error") {
				$adapter_version = $tempver[1];
			} else {
				$adapter_version = "1.0";
			}
			if (version_compare("2.1", $adapter_version, '<=')) {
				$tmpUserData = explode('|', $this->userData);
				unset($this->userData);
				for ($i = 0; $i < count($tmpUserData); $i++) {
					$tmpData = explode('=', $tmpUserData[$i]);
					$this->userData[$tmpData[0]] = $tmpData[1];
				}
			}
			if ($this->debugflag) {
				printf('<br>Adapter protocol version: ' . $adapter_version);
			}

			if ($adapter_version == "1.0") {
				$return = '';
				exec($this->confline, $return);
				if ($this->debugflag) {
					print('<br>Command executed: ' . $this->confline);
					print('<br>Return values: ');
					print_r($return);
				}
			} elseif (preg_match("/^2./", $adapter_version)) {
				switch ($this->action) {
					case 'logon':
						if ($this->flags["create_modify"] == "1") {
							$confline_create_modify = trim($this->confline) . " --version=" . $this->version . " --action=create_modify --userdata=" . "\"" . $this->userData . "\"" . "\n";
							exec($confline_create_modify, $return);
							if ($this->debugflag) {
								print('<br>Command executed: ' . $confline_create_modify);
								print('<br>Return values: ');
								print_r($return);
							}
							if (!$return[0]) {
								$confline_logon = trim($this->confline) . " --version=" . $this->version . " --action=logon --userdata=" . "\"" . $this->userData . "\"" . "\n";
								exec($confline_logon, $return);
								if ($this->debugflag) {
									print('<br>Command executed: ' . $confline_logon);
									print('<br>Return values: ');
									print_r($return);
								}
							}
						} else {
							$confline_logon = trim($this->confline) . " --version=" . $this->version . " --action=logon --userdata=" . "\"" . $this->userData . "\"" . "\n";
							exec($confline_logon, $return);
							if ($this->debugflag) {
								print('<br>Command executed: ' . $confline_logon);
								print('<br>Return values: ');
								print_r($return);
							}
						}
						break;
					case 'logoff':
						// still needs to be done
						break;
					case 'remove':
						// still needs to be done
						break;
				}
			}
			$sso_values = array();
			$j = -1;
			if (!isset($return) || !is_array($return)) {
				$return = array();
			}
			foreach ((array)$return as $i) {
				$pieces = explode(' ', $i, 2);  // split char whitespace

				if ($pieces[0] == "Error") {
					$$this->errorText = $pieces[1];
					$this->errorpage(40);
				}
				if ($pieces[0] != "redirecturl") {
					if ($pieces[0] == "CookieName") {
						$j = $j + 1;
						$sso_values[$j] = array();
					}
					$sso_values[$j] = $sso_values[$j] + array($pieces[0] => trim($pieces[1]));
				} else {
					$sso_values += array($pieces[0] => trim($pieces[1]));      // $pieces[0] == "redirecturl
				}
			}
		} elseif ($this->cmd == 'php') {
			// Include php script
			$confline = trim($this->confline);
			$arr_exec = explode('--url=', $confline);
			$exec = trim($arr_exec[0]);
			$url = trim($arr_exec[1]);
			include_once($exec);
			if ($this->debugflag) {
				print('<br>Included once: ' . $exec);
			}
			// get protocol version from the adapter
			if (function_exists('get_version')) {
				$adapter_version = get_version();
			}
			if (!isset($adapter_version)) {
				$adapter_version = "1.0";
			}
			if (version_compare("2.1", $adapter_version, '<=')) {
				$tmpUserData = explode('|', $this->userData);
				unset($this->userData);
				for ($i = 0; $i < count($tmpUserData); $i++) {
					$tmpData = explode('=', $tmpUserData[$i]);
					$this->userData[$tmpData[0]] = $tmpData[1];
				}
			}
			if ($this->debugflag) {
				printf('<br>Adapter protocol version: ' . $adapter_version);
			}
			if ($adapter_version == '1.0') {
				$sso_values = sso($this->user, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $url);
				if ($this->debugflag) {
					print('<br>Executed function sso with params : ' . $this->user . ' ' . $_SERVER["REMOTE_ADDR"] . ' ' . $_SERVER["HTTP_USER_AGENT"]);
				}
			} elseif (version_compare("2.0", $adapter_version, '<=')) {
				switch ($this->action) {
					case 'logon':
						if ($this->flags["create_modify"] == "1") {
							$sso_values = sso($this->user, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $url, $this->version, "create_modify", $this->userData);
							if ($this->debugflag) {
								print('<br>Executed function sso with params : ' . $this->user . ' ' . $_SERVER["REMOTE_ADDR"] . ' ' . $_SERVER["HTTP_USER_AGENT"] . ' ' . $url . ' ' . $this->version . ' create_modify ' . $this->userData);
							}

							if (!$sso_values) {
								$sso_values = sso($this->user, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $url, $this->version, "logon", $this->userData);
							}
							if ($this->debugflag) {
								print('<br>Executed function sso again with params : ' . $this->user . ' ' . $_SERVER["REMOTE_ADDR"] . ' ' . $_SERVER["HTTP_USER_AGENT"] . ' ' . $url . ' ' . $this->version . ' logon ' . $this->userData);
							}
						} else {
							$sso_values = sso($this->user, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $url, $this->version, "logon", $this->userData);
							if ($this->debugflag) {
								print('<br>Executed function sso with params : ' . $this->user . ' ' . $_SERVER["REMOTE_ADDR"] . ' ' . $_SERVER["HTTP_USER_AGENT"] . ' ' . $url . ' ' . $this->version . ' logon ' . $this->userData);
							}
						}
						break;

					// nothing really happens right now... needs to be finished later
					case 'logoff':
						$sso_values = sso($this->user, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $url, $this->version, "logoff", $this->userData);
						if (!$sso_values) {
							$this->successmessage($this->action);
						}
						break;
					case 'remove':
						$sso_values = sso($this->user, $_SERVER["REMOTE_ADDR"], $_SERVER["HTTP_USER_AGENT"], $url, $this->version, "remove", $this->userData);
						if (!$sso_values) {
							$this->successmessage($this->action);
						}
						break;
				}
			}

			if ($sso_values['Error'] != "") {
				$this->errorText = $sso_values['Error'];
				$this->errorpage(40);
			}
		}

		if ($sso_values['Error'] != "") {
			$this->errorpage($sso_values['Error']);
		}

#print_r("<pre>");
#print_r($sso_values);
#print_r("</pre>");

		if ($this->logLevel > 3) {
			$this->logit = date("D M j G:i:s T Y") . " IP:" . $_SERVER["REMOTE_ADDR"] . " USER:" . $this->user . " APP_ID:" . $this->appId . " TIMESTAMP:" . $this->expires . " SIGNATURE:" . $_GET['signature'] . "\n";
		} elseif ($this->logLevel > 1) {
			$this->logit = date("D M j G:i:s T Y") . " IP:" . $_SERVER["REMOTE_ADDR"] . " USER:" . $this->user . " APP_ID:" . $this->appId . "\n";
		}
		fwrite($this->logging, $this->logit);
		fclose($this->logging);

// begin hoven changes
		$j = (count($sso_values) - 2);
// end hoven changes
		for ($i = 0; $i <= $j; $i++) {
			if ($sso_values[$i]["CookiePath"]) {
				$path = $sso_values[$i]["CookiePath"];
			} else {
				$path = "/";
			}
			setcookie($sso_values[$i]["CookieName"], $sso_values[$i]["CookieValue"], $sso_values[$i]["CookieExpires"], $path, $sso_values[$i]["CookieDomain"], $sso_values[$i]["CookieSecure"]);
		}
		header("Location: " . $sso_values["redirecturl"]);
	}

	private function readConfig() {
		if (!is_readable($this->configFile)) {
			$this->errorpage(0);
		}
		$entries = file_get_contents($this->configFile);
		$lines = explode("\n", $entries);
		$section = '';
		foreach ($lines as $i) {
			if (strtolower(trim($i)) == '[global]') {
				$section = 'global';
			} elseif (strtolower(trim($i)) == '[main]') {
				$section = 'main';
			}

			# begin Hoven changes 13.07.05
			# fix for Windows: limit explode b/c of "C:" etc.

			$tmp = explode(':', $i, 2);

			# end Hoven changes

			if ($section == 'global') {
				if ("public_ssl_key" == strtolower(trim($tmp[0]))) {
					$this->publicSslKey = trim($tmp[1]);
				} elseif ("loglevel" == strtolower(trim($tmp[0]))) {
					$this->logLevel = trim($tmp[1]);
				} elseif ("tokensfile" == strtolower(trim($tmp[0]))) {
					$this->tokensFile = trim($tmp[1]);
				} elseif ("logfile" == strtolower(trim($tmp[0]))) {
					$this->logFile = trim($tmp[1]);
				} elseif ("externalopenssl" == strtolower(trim($tmp[0]))) {
					$this->externalOpenssl = trim($tmp[1]);
				} elseif ("tmp_signature_prefix" == strtolower(trim($tmp[0]))) {
					$this->tmpSignaturePrefix = trim($tmp[1]);
				} elseif ("tmp_signature_dir" == strtolower(trim($tmp[0]))) {
					$this->tmpSignatureDir = trim($tmp[1]);
				} elseif ("windows_server" == strtolower(trim($tmp[0]))) {
					$this->windowsServer = trim($tmp[1]);
				}
			} elseif ($section == 'main') {
				if ($this->appId == trim($tmp[0])) {
					$this->cmd = preg_replace("/\:\/\/.*/", "", trim(str_replace("$tmp[0]:", "", $i)));
					$this->confline = trim(str_replace("$tmp[0]:", "", $i));

					# begin Hoven changes 13.07.05
					# fix for Windows: remove slash at the beginning if on windows

					if ($this->windowsServer == "1") {
						$this->confline = str_replace($this->cmd . "://", "", $this->confline);
					} else {
						$this->confline = str_replace($this->cmd . ":/", "", $this->confline);
					}
					# end Hoven changes

					$this->confline = trim($this->confline);
					$this->confline = str_replace("%remote%", $_SERVER["REMOTE_ADDR"], $this->confline);
					$this->confline = str_replace("%agent%", "\"" . $_SERVER["HTTP_USER_AGENT"] . "\"", $this->confline);
					$this->confline = str_replace("%user%", "\"" . $this->user . "\"", $this->confline);
					$this->confline .= "\n";
				}
			}
		}
		if (!$this->confline) {  // no config entry for app_id
			$this->errorpage(30);
		}
		if (!$this->publicSslKey) {  // no config entry for public_ssl_key
			$this->errorpage(10);
		}
		if (!$this->tokensFile) {  // no tokensfile entry
			$this->errorpage(11);
		}
		if (!$this->logFile) {  // no logfile entry
			$this->errorpage(12);
		}
	}

	private function getvars() {
		$this->appId = isset($_GET['app_id']) ? $_GET['app_id'] : $_GET['tpa_id'];
		$this->thisTime = time();
		$this->user = $_GET['user'];
		$this->expires = $_GET['expires'];
		$this->sign = $this->ssohex2bin($_GET['signature']);
		# N.Hoven 23.6.05
		# added vars for user propagation
		$this->version = $_GET['version'];
		$this->action = $_GET['action'];
		$this->flags = $_GET['flags'];
		$this->userData = $_GET['userdata'];
		#/ N.Hoven

		if ($this->debugflag) {
			print('<br>Signature detected: ' . $this->sign);
			print('<br>Signature ssohex2bin and back: ' . bin2hex($this->sign));
		}
	}

	private function ssohex2bin($data) {
		$len = strlen($data);
		$newdata = '';
		for ($i = 0; $i < $len; $i += 2) {
			$newdata .= pack("C", hexdec(substr($data, $i, 2)));
		}
		return $newdata;
	}

	private function checkvars() {
		if (!$this->user) { // no user?
			$this->errorpage(1);
		}
		if (!$this->appId) { // no app_id?
			$this->errorpage(2);
		}
		if (!$this->expires) { // no expirationtime?
			$this->errorpage(3);
		}
		if ($this->expires < $this->thisTime) {
			$this->errorpage(33);
		}
	}

	private function checksign() {
		$ok = 0;
		if (($this->externalOpenssl == 1) || ($this->externalOpenssl == true)) {
			if ($this->debugflag) {
				printf('<br>Using EXTERNAL openssl');
			}
			$tmp_signature_file = $this->tmpSignatureDir . "/" . uniqid($this->tmpSignaturePrefix);
			$tmp_file = @fopen($tmp_signature_file, "w");
			fwrite($tmp_file, $this->sign);
			fclose($tmp_file);
			if ($this->debugflag) {
				printf('<br>Data to verify: ' . $this->data);
			}

			$verify = shell_exec("echo -n \"" . $this->data . "\"|openssl dgst -sha1 -verify \"" . $this->publicSslKey . "\" -signature \"" . $tmp_signature_file . "\"");
			unlink($tmp_signature_file);

			if ($this->debugflag) {
				printf('<br>Verification result string: ' . $verify);
			}

			if ($verify == "Verified OK\n") {
				$ok = 1;
			} else {
				$this->errorpage(32);
			}
		} else {
			if ($this->debugflag) {
				printf('<br>Using INTERNAL openssl');
			}
			$fp = @fopen($this->publicSslKey, "r");
			if ($fp) {
				$cert = fread($fp, 8192);
				fclose($fp);
				$pubkeyid = openssl_get_publickey($cert);
				if ($this->debugflag) {
					printf('<br>Data to verify: ' . $this->data);
					printf('<br>Key: ' . $cert);
				}
				// compute signature
				$ok = @openssl_verify($this->data, $this->sign, $pubkeyid);
				// remove key from memory
				@openssl_free_key($pubkeyid);
			} else {
				$this->errorpage(20);
			}
		}
		if ($ok != 1) { // error in signature
			$this->errorpage(32);
		}
	}

	private function checkused() {
		if (!touch($this->tokensFile)) { // can't read tokensfile
			$this->errorpage(21);
		}
		$tokensactive = file_get_contents($this->tokensFile);

		$lines = explode("\n", $tokensactive);
		foreach ($lines as $i) {
			$tmp = explode(':', $i);
			if (($tmp[0] == $this->expires) && ($tmp[1] == $this->user) && ($tmp[2] == $this->appId)) {
				$this->errorpage(31);
			}
		}
		$content = '';
		foreach ($lines as $j) {
			$tmp = explode(":", $j);
			if ($tmp[0] > $this->thisTime) {
				$content .= $tmp[0] . ':' . $tmp[1] . ':' . $tmp[2] . "\n";
			}
		}
		$content .= $this->expires . ':' . $this->user . ':' . $this->appId . "\n";
		if (file_put_contents($this->tokensFile, $content) === FALSE) {
			$this->errorpage(21);
		}
	}

	private function errorpage($error) {
		if ($this->logLevel > 2) {
			// Date format: Sat Mar 10 15:16:08 MST 2001
			$this->logit = date("D M j G:i:s T Y") . " IP:" . $_SERVER["REMOTE_ADDR"] . " USER:" . $_GET['user'] . " APP_ID:" . $_GET['tpa_id'] . " TIMESTAMP:" . $_GET['expires'] . " SIGNATURE:" . $_GET['signature'] . " ERROR " . $error . ":" . $this->errorCodes[$error] . "\n";
		} elseif ($this->logLevel > 0) {
			$this->logit = date("D M j G:i:s T Y") . " IP:" . $_SERVER["REMOTE_ADDR"] . " USER:" . $_GET['user'] . " APP_ID:" . $_GET['tpa_id'] . " ERROR " . $error . ":" . $this->errorCodes[$error] . "\n";
		}
		// Write to Logfile
		if ($error != 0) {
			fwrite($this->logging, $this->logit);
			fclose($this->logging);
		}

		if (isset($this->errorCodes[$error + 200])) {
			header("Location: " . $this->errorCodes[$error + 200]);
		} elseif (isset($this->errorCodes[$error + 100])) {
			echo "<html>\n<head>\n<title>" . $this->errorCodes[$error + 100] . "</title>\n</head>\n";
			echo "<body>\n<h1>Server Error</h1>\n<p>" . $this->errorCodes[$error + 100];
			if ($this->errorText) {
				echo "<br />" . $this->errorText;
			}
			echo "</p>\n</body>\n</html>";
		} else {
			echo "<html>\n<head>\n<title>" . $this->errorCodes[$error] . "</title>\n</head>\n";
			echo "<body>\n<h1>Server Error</h1>\n<p>" . $this->errorCodes[$error];
			if ($this->errorText) {
				echo "<br />" . $this->errorText;
			}
			echo "</p>\n</body>\n</html>";
		}
		exit;
	}

	private function errorcode() {
		$entries = file_get_contents($this->configFile);
		$lines = explode("\n", $entries);
		$section = '';
		foreach ($lines as $i) {
			if (strtolower(trim($i)) == '[global]') {
				$section = 'global';
			} elseif (strtolower(trim($i)) == '[main]') {
				$section = 'main';
			} elseif (strtolower(trim($i)) == '[errorcodes]') {
				$section = 'errorcodes';
			}
			$tmp = explode(":", $i, 2);
			$tmp2 = trim($tmp[0]); // conf entry name
			$tmp3 = '';
			if (isset($tmp[1])) {
				$tmp3 = trim($tmp[1]); // conf entry value
			}
			if ($section == 'errorcodes') {
				if ("user_missing" == $tmp2) {
					$this->checkifurl($tmp3, 1);
				} elseif ("appid_missing" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 2);
				} elseif ("expires_missing" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 3);
				} elseif ("signature_missing" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 4);
				} elseif ("sslkey_missingconf" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 10);
				} elseif ("usedtokens_missingconf" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 11);
				} elseif ("logfile_missingconf" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 12);
				} elseif ("sslkey_missingfile" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 20);
				} elseif ("usedtokens_missingfile" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 21);
				} elseif ("logfile_missingfile" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 22);
				} elseif ("appid_unknown" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 30);
				} elseif ("usedtokens_allreadyused" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 31);
				} elseif ("signature_invalid" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 32);
				} elseif ("expires_exeeded" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 33);
				} elseif ("app_error" == strtolower($tmp2)) {
					$this->checkifurl($tmp3, 40);
				}
			}
		}
	}

	private function successmessage($action) {
		if ($this->logLevel > 2) {
			// Date format: Sat Mar 10 15:16:08 MST 2001
			$this->logit = date("D M j G:i:s T Y") . " IP:" . $_SERVER["REMOTE_ADDR"] . " USER:" . $_GET['user'] . " APP_ID:" . $_GET['tpa_id'] . " TIMESTAMP:" . $_GET['expires'] . " SIGNATURE:" . $_GET['signature'] . " SUCCESS: action '" . $action . "' completed successfully\n";
		} elseif ($this->logLevel > 0) {
			$this->logit = date("D M j G:i:s T Y") . " IP:" . $_SERVER["REMOTE_ADDR"] . " USER:" . $_GET['user'] . " APP_ID:" . $_GET['tpa_id'] . " SUCCESS: action '" . $action . "' completed successfully\n";
		}
		// Write to Logfile
		fwrite($this->logging, $this->logit);
		fclose($this->logging);

		echo "<html>\n<head>\n<title>action '" . $action . "' completed successfully</title>\n</head>\n";
		echo "<body onLoad=\"setTimeout('window.close()',5000)\">\n<h1>Server Notice</h1>\n<p>";;
		echo "action '" . $action . "' completed successfully.<p>";
		echo "if this window doesn't close within 5 seconds<BR>please click <a href=\"#\" onclick=\"window.close()\">here</a>";
		echo "</p>\n</body>\n</html>";
		exit;
	}

	private function checkifurl($text, $errorcode) {
		if (preg_match("/^https:\/\//", strtolower(trim($text)))) {
			$num = 200 + $errorcode;
			$this->errorCodes += array($num => $text);
		} elseif (preg_match("/^http:\/\//", strtolower(trim($text)))) {
			$num = 200 + $errorcode;
			$this->errorCodes += array($num => $text);
		} elseif ($text) {
			$num = 100 + $errorcode;
			$this->errorCodes += array($num => $text);
		}
	}
}

$configFile = "/usr/local/directsso/etc/directsso.conf";
$client = new DirectSSOClient($configFile);
