<?php

namespace Bitmotion\Webapps\Helper;

class RequestHelper {

    /**
     * @param bool $explode
     * @return array|string
     */
    public static function curPageURL($explode=false) {
        $pageURL = 'http';
        if ($_SERVER["HTTPS"] == "on") {$pageURL .= "s";}
        $pageURL .= "://";
        if ($_SERVER["SERVER_PORT"] != "80") {
            $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"].$_SERVER["REQUEST_URI"];
        } else {
            $pageURL .= $_SERVER["SERVER_NAME"].$_SERVER["REQUEST_URI"];
        }
        if($explode) {
            $pageURL = explode('/',$pageURL);
        }
        return $pageURL;
    }

}