<?php
namespace DevSeb\OAuthPhpLib\Server;

use DevSeb\OAuthPhpLib\Client\HttpRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthException;
use DevSeb\OAuthPhpLib\OAuth\OAuthRefreshToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthToken;

/**
 * Class OAuth2ApiServer.
 *
 * 2-legged and 3-legged OAuth 2.0 API server
 * Should be subclassed to implement keys persistence and lookups
 *
 * Mostly based from the documentation:
 * http://oauthbible.com/
 *
 * 2-legged OAuth 2.0 :
 *
 * Consumer                          Server
 *      1. Request access token
 *    |-------------------------------->|
 *      2. Issue an access token
 *    |<--------------------------------|
 *      3. Call protected API
 *    |-------------------------------->|
 *      4. Send response
 *    |<--------------------------------|
 *
 * 3-legged OAuth 2.0 :
 *
 *  Browser                 Consumer                    Server
 *     1. Redirect to auth page
 *  |<--------------------------|
 *                 2. Grant access to customer
 *  |----------------------------------------------------->|
 *                 3. Confirm user authorization
 *  |<-----------------------------------------------------|
 *    4. Redirect to callback
 *  |-------------------------->|
 *                                5. Request access token
 *                              |------------------------->|
 *                                6. Issue an access token
 *                              |<-------------------------|
 *                                7. Call protected API
 *                              |------------------------->|
 *                                8. Send response
 *                              |<-------------------------|
 */
abstract class OAuth2ApiServer extends OAuthApiServer
{
    const GRANT_TYPE_AUTHORIZATION = 'authorization_code';
    const GRANT_TYPE_CREDENTIALS = 'client_credentials';
    const GRANT_TYPE_PASSWORD = 'password';
    const GRANT_TYPE_REFRESH_TOKEN = 'refresh_token';

    const TOKEN_TYPE_BEARER = 'Bearer';
    const TOKEN_TYPE_OAUTH = 'OAuth';
    const TOKEN_TYPE_MAC = 'MAC';

    /**
     * OAuth2ApiServer constructor.
     *
     * @param HttpRequest $Request
     *
     * @throws \Exception
     */
    public function __construct(HttpRequest $Request)
    {
        parent::__construct($Request);
    }

    /**
     * @throws OAuthException
     * @throws \Exception
     */
    protected function init()
    {
        parent::init();
        // Register routes
        $this->setRoutes();
        // Set OAuth version 2.0
        $this->setVersion(self::OAUTH_VERSION_2);
        // Check protected resources access
        if (!strstr($this->Request->getPath(), '/oauth/')) {
            $AccessToken = $this->checkAccessToken();
            if (!$AccessToken) {
                throw new OAuthException(
                    'Access token is not set for this request',
                    self::E_OAUTH_ACCESS_DENIED
                );
            }
        }
    }

    private function setRoutes()
    {
        $this->addRoutes(array(
            new HttpRoute('/oauth/token', 'getAccessToken'),
            new HttpRoute('/oauth/auth', 'authenticate'),
        ));
    }

    //=====================================================================
    // Interface

    /**
     * @throws OAuthException
     * @throws \Exception
     */
    public function getAccessToken()
    {
        $AccessToken = null;
        $this->checkConsumer();
        $grant_type = $this->Request->get('grant_type');
        if (in_array($grant_type, array(
            self::GRANT_TYPE_AUTHORIZATION,
            self::GRANT_TYPE_CREDENTIALS,
            self::GRANT_TYPE_PASSWORD,
            self::GRANT_TYPE_REFRESH_TOKEN,
        ))) {
            $RefreshToken = null;
            $RequestToken = null;
            if ($grant_type == self::GRANT_TYPE_REFRESH_TOKEN) {
                $RefreshToken = $this->checkRefreshToken();
            } else {
                // Get Request Token
                if ($this->Request->containsKey('code')) {
                    $RequestToken = new OAuthRequestToken($this->Request->get('code'));
                }
            }
            // Get a new access token
            $AccessToken = $this->newAccessToken($this->Consumer, $RequestToken, $RefreshToken);
            if (!$AccessToken || !$AccessToken->getKey()) {
                throw new OAuthException(
                    "Can't get a new access token",
                    self::E_OAUTH_SERVER_ERROR
                );
            }
            $this->ResponseNode = new ResponseNode();
            $this->ResponseNode->setNode('access_token', $AccessToken->getKey());
            $this->ResponseNode->setNode('token_type', self::TOKEN_TYPE_BEARER);
            $this->ResponseNode->setNode('expires_in', $AccessToken->getExpiresIn());
        }
        // Add Refresh Token
        if (in_array($grant_type, array(
            self::GRANT_TYPE_AUTHORIZATION,
            self::GRANT_TYPE_REFRESH_TOKEN,
        ))) {
            // Get a new refresh token
            $RefreshToken = $this->newRefreshToken($this->Consumer, $AccessToken);
            if (!$RefreshToken || !$RefreshToken->getKey()) {
                throw new OAuthException(
                    "Can't get refresh token",
                    self::E_OAUTH_SERVER_ERROR
                );
            }
            $this->ResponseNode->setNode('refresh_token', $RefreshToken->getKey());
        }
        $this->showResponse();
    }

    //=====================================================================
    // Private methods

    /**
     * Load current consumer.
     *
     * @throws OAuthException
     */
    protected function checkConsumer()
    {
        $grant_type = $this->Request->get('grant_type');
        if (in_array($grant_type, array(
            self::GRANT_TYPE_AUTHORIZATION,
            self::GRANT_TYPE_CREDENTIALS,
            self::GRANT_TYPE_PASSWORD,
        ))) {
            // First check consumer
            $client_id = $client_secret = '';
            // Header BasicAuth
            if ($this->Request->hasHeader('Authorization')) {
                $credentials = $this->Request->getBasicAuthCredentials();
                $client_id = $credentials['login'];
                $client_secret = $credentials['password'];
            } // GET parameters
            elseif ($this->Request->containsKeys('client_id', 'client_secret')) {
                $client_id = $this->Request->get('client_id');
                $client_secret = $this->Request->get('client_secret');
            }
            // Check credentials
            if ($client_id == '' || $client_secret == '') {
                throw new OAuthException(
                    "Can't get consumer credentials from request",
                    self::E_OAUTH_INVALID_REQUEST
                );
            }
            $this->checkConsumerCredentials($client_id, $client_secret);
            // Other check according to grant type
            if ($grant_type == self::GRANT_TYPE_PASSWORD) {
                $username = $password = '';
                if ($this->Request->containsKeys('username', 'password')) {
                    $username = $this->Request->get('username');
                    $password = $this->Request->get('password');
                }
                if ($username == '' || $password == '') {
                    throw new OAuthException(
                        "Can't get user credentials from request",
                        self::E_OAUTH_INVALID_REQUEST
                    );
                }
                if (!$this->authenticateUser($this->Consumer, $username, $password)) {
                    throw new OAuthException(
                        "Can't authenticate user",
                        self::E_OAUTH_INVALID_CLIENT
                    );
                }
            }
            if ($grant_type == self::GRANT_TYPE_AUTHORIZATION) {
                $this->checkRequestToken();
            }
        }
    }

    /**
     * @param $client_id
     * @param $client_secret
     *
     * @throws OAuthException
     */
    protected function checkConsumerCredentials($client_id, $client_secret)
    {
        // Get consumer from username
        $Consumer = $this->getConsumer($client_id);
        if (!$Consumer || $Consumer->getSecret() == '') {
            throw new OAuthException(
                "Can't authenticate consumer",
                self::E_OAUTH_INVALID_CLIENT
            );
        }
        // Check password
        if ($Consumer->getSecret() != $client_secret) {
            throw new OAuthException(
                "Bad secret for consumer $client_id",
                self::E_OAUTH_INVALID_CLIENT
            );
        }
        $this->Consumer = $Consumer;
    }

    /**
     * Load request token.
     *
     * @return OAuthRequestToken
     *
     * @throws OAuthException
     * @throws \Exception
     */
    protected function checkRequestToken()
    {
        if ($this->Request->containsKey('code')) {
            $Token = $this->getToken(
                $this->Consumer, $this->Request->get('code'), OAuthToken::TYPE_REQUEST
            );
            if ($Token && $Token->getType() == OAuthToken::TYPE_REQUEST) {
                return new OAuthRequestToken($Token->getKey());
            }
        }

        throw new OAuthException(
            "Check request token failed",
            self::E_OAUTH_INVALID_CLIENT
        );
    }

    /**
     * Load access token.
     *
     * @return OAuthAccessToken
     * @throws OAuthException
     * @throws \Exception
     */
    protected function checkAccessToken()
    {
        $access_token = '';
        if ($this->Request->containsKey('access_token')) {
            $access_token = $this->Request->get('access_token');
        } elseif ($this->Request->hasHeader('Authorization')) {
            $authorization = $this->Request->getHeader('Authorization');
            if (preg_match('/' . self::TOKEN_TYPE_BEARER . ' (.*)/', $authorization, $matches)) {
                $access_token = $matches[1];
            }
        }
        if ($access_token) {
            // Load consumer
            $this->Consumer = $this->getConsumerFromToken($access_token);
            if (!$this->Consumer) {
                throw new OAuthException(
                    "Can't get consumer from access token",
                    self::E_OAUTH_INVALID_REQUEST
                );
            }
            // Load Access Token
            $Token = $this->getToken(
                $this->Consumer, $access_token, OAuthToken::TYPE_ACCESS
            );
            if ($Token && $Token->getType() == OAuthToken::TYPE_ACCESS) {
                return new OAuthAccessToken($Token->getKey());
            }
        }

        throw new OAuthException(
            "Check access token failed",
            self::E_OAUTH_INVALID_CLIENT
        );
    }

    /**
     * Load refresh token.
     *
     * @return OAuthRefreshToken
     *
     * @throws OAuthException
     * @throws \Exception
     */
    protected function checkRefreshToken()
    {
        if ($this->Request->containsKey('refresh_token')) {
            $refresh_token = $this->Request->get('refresh_token');
            if ($refresh_token) {
                // Load consumer
                $this->Consumer = $this->getConsumerFromToken($refresh_token);
                if (!$this->Consumer) {
                    throw new OAuthException(
                        "Can't get consumer from refresh token",
                        self::E_OAUTH_INVALID_REQUEST
                    );
                }
                $Token = $this->getToken(
                    $this->Consumer, $refresh_token, OAuthToken::TYPE_REFRESH
                );
                if ($Token && $Token->getType() == OAuthToken::TYPE_REFRESH) {
                    return new OAuthRefreshToken($Token->getKey());
                }
            }
        }

        throw new OAuthException(
            "Check refresh token failed",
            self::E_OAUTH_INVALID_CLIENT
        );
    }

    //=====================================================================
    // OAuth data store interface

    /**
     * Create a new refresh token for this consumer.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthAccessToken|null $RequestToken
     *
     * @return OAuthRefreshToken
     */
    abstract protected function newRefreshToken(OAuthConsumer $Consumer, OAuthAccessToken $RequestToken = null);
}

