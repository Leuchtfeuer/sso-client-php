<?php
class Autoloader {

    protected static $appNamespace = 'Bitmotion\\Webapps';
    protected static $applicationPath = 'application/';
    protected static $resourcesPath = 'Resources/Private/';

    static public function loader($className) {
        $className = str_replace(self::$appNamespace,'',$className);

        if(preg_match('/\Helper/',$className)) {
            $filename = self::$resourcesPath . str_replace('\\', '/', $className) . ".php";
        } else {
            $filename = self::$applicationPath . str_replace('\\', '/', $className) . ".php";
        }
        if (file_exists($filename)) {
            include_once($filename);
            if (class_exists($className)) {
                return TRUE;
            }
        }
        return FALSE;

    }
}
spl_autoload_register('Autoloader::loader');