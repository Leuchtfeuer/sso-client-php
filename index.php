<?php

require_once("Autoloader.php");

$urlParts = \Bitmotion\Webapps\Helper\RequestHelper::curPageURL(true);

$auth = new \Bitmotion\Webapps\Controller\AuthController();

//noch auslagern und dispatchen
if(count($urlParts)==4) {
    if(end($urlParts)=='login') {
        if(!array_key_exists('webapps_auth_session',$_SESSION)) {
            $auth->setUserData($_POST['user'],$_POST['password']);
            if($auth->loginAction())
                header("Location: " . nl2br($_SERVER["PHP_SELF"]));
        }
    }
    if(end($urlParts)=='logout') {
        if(array_key_exists('webapps_auth_session',$_SESSION)) {
            $auth->logoutAction();
        }
    }
}

if ($auth->checkLoginAction()) {
    $loginState = "Logged In as ". $_COOKIE['webapps_auth_user'];
    $loginForm = file_get_contents(__DIR__.'/Resources/Private/Partials/logged_in_form.html');
} else {
    $loginState = "Not Logged In";
    $loginForm = file_get_contents(__DIR__.'/Resources/Private/Partials/login_form.html');
}

$content = file_get_contents(__DIR__.'/Resources/Private/Templates/Index/index.html');

$content = preg_replace('/###LOGIN###/',$loginState,$content);

$content = preg_replace('/###LOGINFORM###/',$loginForm,$content);

echo $content;

//print_r($_COOKIE);
//echo "END";

