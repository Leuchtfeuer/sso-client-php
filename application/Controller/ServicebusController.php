<?php

namespace Bitmotion\Webapps\Controller;

class ServicebusController {


    public function __construct()
    {}

    /**
     * Client authentication for Service
     *
     */
    public function authenticate()
    {}

    /**
     * Show currently Registered Services
     *
     * @param bool $state
     */
    public function showRegisteredServices($state=false)
    {}

    /**
     * get Connection Information for given service
     *
     * @param string $serviceName
     * @param string $additionalParams
     */
    public function getServiceInfo($serviceName,$additionalParams)
    {}

    /**
     * Get Status for given Service
     *
     * @param string $serviceName
     */
    public function getServiceStatus($serviceName)
    {
        //@Todo: Verfuegbarkeit, Auslastung, etc. abfragen und zurueckgeben, ggf. auch SB anfragen
    }

    public function registerService()
    {}

    /**
     * Get Service State if this feature is supported by called Service
     * 
     * @param string $serviceName
     */
    public function queryService($serviceName)
    {}
}