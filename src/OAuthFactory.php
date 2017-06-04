<?php
namespace SlimApi\OAuth;

use OAuth\Common\Consumer\Credentials;
use OAuth\Common\Http\Uri\UriFactory;
use OAuth\OAuth2\Service\ServiceInterface;
use OAuth\ServiceFactory;

/**
 * Factory for creating OAuth services
 */
class OAuthFactory
{
    const RETURN_URL_STORAGE_SESSION = 'session';
    const RETURN_URL_STORAGE_COOKIE = 'cookie';
    const DEFAULT_STORAGE = '\OAuth\Common\Storage\Session';

    private $registeredService = false;
    private $serviceFactory;
    private $storage;
    private $oAuthConfig;

    /**
     * Create new OAuthFactory
     *
     * @param mixed $config An array of oauth key/secrets
     */
    public function __construct($oAuthConfig)
    {
        $this->serviceFactory = new ServiceFactory;

        if (!isset($oAuthConfig['storage']) || !class_exists($oAuthConfig['storage'])) {
            $oAuthConfig['storage'] = self::DEFAULT_STORAGE;
        }
        $this->storage = new $oAuthConfig['storage']();

        $this->oAuthConfig = $oAuthConfig;
    }

    /**
     * Create an oauth service based on type
     *
     * @param  string $type the type of oauth services to create
     *
     * @return ServiceInterface
     */
    public function createService($type)
    {
        $typeLower = strtolower($type);

        if (!array_key_exists($typeLower, $this->oAuthConfig)) {
            return false;
        }

        // Create a new instance of the URI class with the current URI, stripping the query string
        $uriFactory = new UriFactory();
        $currentUri = $uriFactory->createFromSuperGlobalArray($_SERVER);
        $currentUri->setQuery('');

        // Setup the credentials for the requests
        $credentials = new Credentials(
            $this->oAuthConfig[$typeLower]['key'],
            $this->oAuthConfig[$typeLower]['secret'],
            $currentUri->getAbsoluteUri() . '/callback'
        );

        $scopes = [];
        if (isset($this->oAuthConfig[$typeLower]['scopes'])) {
            $scopes = $this->oAuthConfig[$typeLower]['scopes'];
        }

        // Instantiate the OAuth service using the credentials, http client and storage mechanism for the token
        $this->registeredService = $this->serviceFactory->createService($type, $credentials, $this->storage, $scopes);
    }

    /**
     * if we don't have a registered service we attempt to make one
     *
     * @param  string $type the oauth provider type
     *
     * @return ServiceInterface       the created service
     */
    public function getOrCreateByType($type)
    {
        if (!$this->registeredService) {
            $this->createService($type);
        }

        return $this->registeredService;
    }

    /**
     * retrieve the registered service
     *
     * @return ServiceInterface the registered oauth service
     */
    public function getService()
    {
        return $this->registeredService;
    }

    /**
     * retrieve the current config
     *
     * @return array
     */
    public function getConfig()
    {
        return $this->oAuthConfig;
    }
}
