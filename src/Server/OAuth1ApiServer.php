<?php
namespace DevSeb\OAuthPhpLib\Server;

use DevSeb\OAuthPhpLib\Client\HttpRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthException;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthSignature;
use DevSeb\OAuthPhpLib\OAuth\OAuthSignatureRsaSha1;
use DevSeb\OAuthPhpLib\OAuth\OAuthToken;

/**
 * Class OAuth1ApiServer.
 *
 * 1-legged, 2-legged and 3-legged OAuth 1.0a API server
 * Should be subclassed to implement keys persistence and lookups
 *
 * Mostly based from the documentation:
 * http://oauthbible.com/
 *
 * 1-legged OAuth 1.0a :
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
 * 2-legged OAuth 1.0a :
 *
 * Consumer                          Server
 *      1. Request a token
 *    |-------------------------------->|
 *      2. Issue a request token
 *    |<--------------------------------|
 *      3. Request access token
 *    |-------------------------------->|
 *      4. Issue an access token
 *    |<--------------------------------|
 *      5. Call protected API
 *    |-------------------------------->|
 *      6. Send response
 *    |<--------------------------------|
 *
 * 3-legged OAuth 1.0a :
 *
 *  Browser                 Consumer                    Server
 *                                1. Request a token
 *                              |------------------------->|
 *                                2. Issue a request token
 *                              |<-------------------------|
 *    3. Redirect to auth page
 *  |<--------------------------|
 *                 4. Grant access to consumer
 *  |----------------------------------------------------->|
 *                 5. Confirm user authorization
 *  |<-----------------------------------------------------|
 *    6. Redirect to callback
 *  |-------------------------->|
 *                                7. Request access token
 *                              |------------------------->|
 *                                8. Issue an access token
 *                              |<-------------------------|
 *                                9. Call protected API
 *                              |------------------------->|
 *                                10. Send response
 *                              |<-------------------------|
 */
abstract class OAuth1ApiServer extends OAuthApiServer
{
    const OAUTH_TIMESTAMP_THRESHOLD = 300000;

    /**
     * OAuth1ApiServer constructor.
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
        // Set OAuth version 1.0a
        $this->setVersion(self::OAUTH_VERSION_1);
        // Check protected ressources access
        if (!strstr($this->Request->getPath(), '/oauth/')) {
            $this->checkConsumer();
            $AccessToken = $this->checkAccessToken();
            if ($AccessToken) {
                // Check request
                $this->checkSignature($AccessToken);
            } else {
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
            new HttpRoute('/oauth/request_token', 'getRequestToken'),
            new HttpRoute('/oauth/access_token', 'getAccessToken'),
            new HttpRoute('/oauth/authenticate', 'authenticate'),
        ));
    }

    //=====================================================================
    // Interface

    /**
     * @throws OAuthException
     */
    public function getRequestToken()
    {
        // Check request
        $this->checkConsumer();
        $this->checkSignature();
        // Get a new request token
        $RequestToken = $this->newRequestToken(
            $this->Consumer, $this->Request->get('oauth_callback')
        );
        if (!$RequestToken || !$RequestToken->getKey() || !$RequestToken->getSecret()) {
            throw new OAuthException(
                "Can't get a new request token",
                self::E_OAUTH_SERVER_ERROR
            );
        }
        $this->ResponseNode = new ResponseNode();
        $this->ResponseNode->setNode('oauth_token', $RequestToken->getKey());
        $this->ResponseNode->setNode('oauth_token_secret', $RequestToken->getSecret());
        // 3-legged OAuth 1.0
        if ($this->Request->containsKey('oauth_callback')) {
            $this->ResponseNode->setNode('oauth_callback_confirmed', true);
        }
        $this->showResponse();
    }

    /**
     * @throws OAuthException
     */
    public function getAccessToken()
    {
        // Check request
        $this->checkConsumer();
        $RequestToken = $this->checkRequestToken();
        $this->checkSignature($RequestToken);
        // Get request token
        if (!$this->Request->containsKey('oauth_token')) {
            throw new OAuthException(
                "oauth_token is not set",
                self::E_OAUTH_INVALID_REQUEST
            );
        }
        // Get a new access token
        $AccessToken = $this->newAccessToken($this->Consumer, $RequestToken);
        if (!$AccessToken || !$AccessToken->getKey() || !$AccessToken->getSecret()) {
            throw new OAuthException(
                "Can't get a new access token",
                self::E_OAUTH_SERVER_ERROR
            );
        }

        $this->ResponseNode->setNode('oauth_token', $AccessToken->getKey());
        $this->ResponseNode->setNode('oauth_token_secret', $AccessToken->getSecret());
        $this->showResponse();
    }

    // TODO: implement Echo and xAuth

    //=====================================================================
    // Private methods

    /**
     * Load current consumer.
     *
     * @throws OAuthException
     */
    protected function checkConsumer()
    {
        // Check params
        $consumerKey = $this->Request->get('oauth_consumer_key');
        if ($consumerKey == '') {
            throw new OAuthException(
                "oauth_consumer_key is not found",
                self::E_OAUTH_INVALID_REQUEST
            );
        }
        // Get Consumer from key
        $this->Consumer = $this->getConsumer($consumerKey);
        if (!$this->Consumer || $this->Consumer->getSecret() == '') {
            throw new OAuthException(
                "Consumer is not set",
                self::E_OAUTH_INVALID_CLIENT
            );
        }
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
        if ($this->Request->containsKey('oauth_token')) {
            $Token = $this->getToken(
                $this->Consumer, $this->Request->get('oauth_token'), OAuthToken::TYPE_REQUEST
            );
            if ($Token && $Token->getSecret() != ''
                && $Token->getType() == OAuthToken::TYPE_REQUEST
            ) {
                return new OAuthRequestToken($Token->getKey(), $Token->getSecret());
            }
        }

        throw new OAuthException(
            "Check request token failed",
            OAuthApiServer::E_OAUTH_INVALID_CLIENT
        );
    }

    /**
     * Load access token.
     *
     * @return OAuthAccessToken
     *
     * @throws OAuthException
     * @throws \Exception
     */
    protected function checkAccessToken()
    {
        if ($this->Request->containsKey('oauth_token')) {
            $Token = $this->getToken(
                $this->Consumer, $this->Request->get('oauth_token'), OAuthToken::TYPE_ACCESS
            );
            if ($Token && $Token->getSecret() != ''
                && $Token->getType() == OAuthToken::TYPE_ACCESS
            ) {
                return new OAuthAccessToken($Token->getKey(), $Token->getSecret());
            }
        }

        throw new OAuthException(
            "Check access token failed",
            OAuthApiServer::E_OAUTH_INVALID_CLIENT
        );
    }

    /**
     * @param OAuthToken|null $Token
     * @return bool
     *
     * @throws OAuthException
     * @throws \Exception
     */
    protected function checkSignature(OAuthToken $Token = null)
    {
        $this->checkConsumer();
        // Check mandatory params
        if (!$this->Request->containsKeys(
            'oauth_signature',
            'oauth_signature_method',
            'oauth_timestamp',
            'oauth_nonce'
        )
        ) {
            throw new OAuthException(
                'missing parammeter',
                self::E_OAUTH_INVALID_REQUEST
            );
        }
        // check timestamp
        $timestamp = $this->Request->get('oauth_timestamp');
        if (!$this->checkTimestamp($timestamp)) {
            throw new OAuthException(
                'timestamp check failed',
                self::E_OAUTH_INVALID_REQUEST
            );
        }
        // check nonce
        if ($Token != null) {
            $nonce = $this->Request->get('oauth_nonce');
            if ($this->isNonceUsed($this->Consumer, $Token, $nonce, $timestamp)) {
                throw new OAuthException(
                    'nonce check failed',
                    self::E_OAUTH_INVALID_REQUEST
                );
            }
        }
        // Check signature
        $OAuthSignature = $this->getOAuthSignature($Token);
        if (!$OAuthSignature->checkRequest($this->Request)) {
            throw new OAuthException(
                'Request signature is not valid',
                self::E_OAUTH_INVALID_REQUEST
            );
        }

        return true;
    }

    /**
     * Check timestamp to set lifetime.
     * Warning: Both client and server should use same timezone and be in sync (NTP + GMT).
     *
     * @param int $timestamp
     *
     * @return bool
     */
    protected function checkTimestamp($timestamp)
    {
        if (!$timestamp) {
            return false;
        }
        $now = time();
        if (abs($now - $timestamp) > self::OAUTH_TIMESTAMP_THRESHOLD) {
            return false;
        }

        return true;
    }

    /**
     * Build OAuthSignature in order to verify requests.
     *
     * @param OAuthToken $Token
     *
     * @return OAuthSignature
     *
     * @throws \Exception
     */
    protected function getOAuthSignature(OAuthToken $Token = null)
    {
        $signatureMethod = $this->Request->get('oauth_signature_method');
        $OAuthSignature = OAuthSignature::getOAuthSignature($signatureMethod, $this->Consumer, $Token);
        if ($signatureMethod == OAuthSignature::SIGNATURE_METHOD_RSA_SHA1) {
            $publicKey = $this->getClientPublicKey();
            /* @var OAuthSignatureRsaSha1 $OAuthSignature */
            $OAuthSignature->setRsaPublicKey($publicKey);
        }

        return $OAuthSignature;
    }

    /**
     * This method must be subclassed to return the client public key.
     *
     * @return string Path to public key used to verify requests
     *
     * @throws \Exception
     */
    protected function getClientPublicKey()
    {
        throw new \Exception('This method must be subclassed !');
    }

    //=====================================================================
    // OAuth data store interface

    /**
     * Check nonce is not already used for this consumer and token.
     * This can protected against replay attack.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthToken $Token
     * @param string $nonce
     * @param int $timestamp
     *
     * @return bool True is nonce has been already used for this consumer and token
     */
    abstract protected function isNonceUsed(OAuthConsumer $Consumer, OAuthToken $Token, $nonce, $timestamp);
}

