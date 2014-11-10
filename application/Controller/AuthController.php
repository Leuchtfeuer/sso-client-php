<?php

namespace Bitmotion\Webapps\Controller;

class AuthController {

    protected $username = NULL;
    protected $password = NULL;

    public function __construct() {
       session_name('webapps_auth_session');
       session_start();
    }

    public function loginAction() {
       //if($this->username =='entwickler' && $this->password == 'password') {
        setcookie('webapps_auth_session',session_id(),time()+60*5,'/');
        setcookie('webapps_auth_user',$this->username,time()+60*5,'/');
        $_SESSION['webapps_auth_session']=true;
        header("Location: " . nl2br($_SERVER["PHP_SELF"]));
        return true;
       //}
       return false;
    }

    public function logoutAction() {
       setcookie('webapps_auth_session',"",0,'/');
       setcookie (session_id(), "", time() - 3600);
       session_destroy();
       session_write_close();
       header("Location: " . nl2br($_SERVER["PHP_SELF"]));
    }

    public function checkLoginAction() {
        if(array_key_exists('webapps_auth_session',$_SESSION)) {
            return true;
        }
        return false;
    }

    public function setUserData($username,$password) {
        $this->username = $username;
        $this->password = $password;
    }

    public function getUsername() {
        return $this->username;
    }
}
