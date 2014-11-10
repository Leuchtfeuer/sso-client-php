<?php

require_once("application/Controller/AuthController.php");

/***
 * Signature-Based Single Sign-On Framework
 * TPA Adapter for
 * bitmotion webapps testclient
 *
 *  Version            : 1.0.0
 *
 *  @copyright (c) bitmotion GmbH, Hannover, Germany
 *  @author Sven Gähle
 *  http://www.single-signon.com
 */

/**
 * Return the protocol version
 *
 * @return  string  Return the protocol version
 *
 */
function get_version(){
  return "2.0";
} 

/**
 *  function which is called after including this file in the SSO-Agent.
 *
 *  @param    string    Username the Session will be created for
 *  @param    string    Remoteaddress of the users system
 *  @param    string    Browser
 *  @param    string    Url where the user will be redirected after establishing a session for him
 *  @param    string    the protocol version of the calling agent
 *  @param    string    the action to perform. Right now this is either 'logon' or 'create_modify'
 *  @param    string    the userdata submitted by the agent
 *
 *  @return   string    return the session data
 *
 *  Leave stubs if you dont need all four params.
 */
function sso($User_Name,$ip,$agent,$sso_url,$sso_version="",$sso_action="",$sso_userdata="") {
  if ($sso_version == "") {return array("Error"=>"sso version out of date"); }
  // get an associative array of the userdata

  $userdata = process_userdata($sso_userdata);
  //INITIALIZE EXTERNAL AUTH
  switch($sso_action) {
    // action: create user / update userdata
  case 'create_modify':
    break;
    // action: create session
  case 'logon':
     $auth = new \Bitmotion\Webapps\Controller\AuthController();
     $auth->setUserData($User_Name,'password');
     $auth->loginAction();

     // create return_val for sso-agent
     $return_val[0] = array();
     $return_val += array('redirecturl'  => $sso_url . validateReturnToUrl($_GET['returnTo']) . "?".session_name()."=".session_id());

    return $return_val;

    break;

  case 'logoff':
    //NOT IMPLEMENTED YET
    break;
  }
}

function validateReturnToUrl($returnToUrl) {
	if (!is_string($returnToUrl)) {
		return '';
	} else if (preg_match('#[[:cntrl:]]#', $returnToUrl)) {
		return '';
	}
		return $returnToUrl;
}

/*
 * process the userdata string and return an associative array
 * @param string $sso_userdata: the data from fe_users (pipe-separated)
 * @return array$data: the userdata
 */
function process_userdata($sso_userdata){
  $sso_userdata = split("\|",$sso_userdata);
  for ($i=0;$i<count($sso_userdata);$i++) {
    $sso_userdata[$i]=split("=",$sso_userdata[$i]);
    $data[$sso_userdata[$i][0]]=$sso_userdata[$i][1];
  }
  unset ($sso_userdata);
  return $data;
}
?>
