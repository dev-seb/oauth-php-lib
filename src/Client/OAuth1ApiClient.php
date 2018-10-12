<?php
namespace DevSeb\OAuthPhpLib\Client;

use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthSignature;
use DevSeb\OAuthPhpLib\OAuth\OAuthSignatureRsaSha1;
use DevSeb\OAuthPhpLib\OAuth\OAuthToken;
use DevSeb\OAuthPhpLib\Server\HttpResponse;
use DevSeb\OAuthPhpLib\Server\OAuthApiServer;

/**
 * OAuth1ApiClient.
 */
class OAuth1ApiClient extends OAuthApiClient
{
    /**
     * Default signature method (most commonly used).
     */
    private $signatureMethod = OAuthSignature::SIGNATURE_METHOD_HMAC_SHA1;

    /**
     * @var bool
     */
    private $signToHeader = false;

    /**
     * OAuthApiClient constructor.
     *
     * @param $url
     * @param OAuthConsumer $Consumer
     *
     * @throws \Exception
     */
    public function __construct($url, OAuthConsumer $Consumer = null)
    {
        parent::__construct($url, $Consumer);
        $this->setVersion(OAuthApiServer::OAUTH_VERSION_1);
    }

    /**
     * @param $signatureMethod
     *
     * @throws \Exception
     */
    public function setSignatureMethod($signatureMethod)
    {
        if (!in_array($signatureMethod, array(
            OAuthSignature::SIGNATURE_METHOD_PLAINTEXT,
            OAuthSignature::SIGNATURE_METHOD_HMAC_SHA1,
            OAuthSignature::SIGNATURE_METHOD_RSA_SHA1,
        ))
        ) {
            throw new \Exception("'$signatureMethod': not a valid oauth 1 signature method");
        }
        $this->signatureMethod = $signatureMethod;
    }

    public function setSignToHeader($signToHeader)
    {
        $this->signToHeader = $signToHeader;
    }

    /**
     * Return response from signed OAuth request.
     *
     * @param OAuthRequest $Request
     * @param OAuthToken $Token
     *
     * @return HttpResponse
     *
     * @throws \Exception
     */
    public function getOAuthResponse(OAuthRequest $Request, OAuthToken $Token = null)
    {
        // Get signature for request
        $oauthParams = array(
            'oauth_consumer_key' => $this->Consumer->getKey(),
            'oauth_timestamp' => $this->getTimestamp(),
            'oauth_nonce' => $this->getNonce(),
            'oauth_version' => $this->version,
        );
        if ($Token) {
            // Can be RequestToken or AccessToken
            $oauthParams['oauth_token'] = $Token->getKey();
            // Add verifier
            if ($Token->getType() == OAuthToken::TYPE_REQUEST) {
                /** @var OAuthRequestToken $Token */
                if ($Token->getVerifier() != '') {
                    $oauthParams['oauth_verifier'] = $Token->getVerifier();
                }
            }
        }
        // Add params :
        // - oauth_signature
        // - oauth_signature_method
        $OAuthSignature = $this->getOAuthSignature($Token);
        $OAuthSignature->signRequest($Request, $oauthParams, $this->signToHeader);

        // Return response
        return $this->getResponse($Request);
    }

    /**
     * Get a request token.
     *
     * @param string $callback Use only for the 3-legged OAuth 1.0 flow
     *
     * @return OAuthRequestToken
     *
     * @throws \Exception
     */
    public function getRequestToken($callback = '')
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/request_token');
        // Optional param
        if ($callback) {
            $Request->set('oauth_callback', $callback);
        }
        // Get response
        $Response = $this->getOAuthResponse($Request);
        if ($Request->isOk() && $Response->isOk() && !$this->isError()) {
            $json = json_decode($Response->getBody());
            if ($json) {
                $RequestToken = new OAuthRequestToken(
                    $json->oauth_token,
                    $json->oauth_token_secret
                );

                return $RequestToken;
            }
        }

        return null;
    }

    /**
     * Exchange Request Token with Access Token.
     *
     * @param OAuthRequestToken $RequestToken
     *
     * @return OAuthAccessToken
     *
     * @throws \Exception
     */
    public function getAccessToken(OAuthRequestToken $RequestToken)
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/access_token');
        // Get response
        $Response = $this->getOAuthResponse($Request, $RequestToken);
        if ($Request->isOk() && $Response->isOk() && !$this->isError()) {
            $json = json_decode($Response->getBody());
            if ($json) {
                $AccessToken = new OAuthAccessToken(
                    $json->oauth_token,
                    $json->oauth_token_secret
                );

                return $AccessToken;
            }
        }

        return null;
    }

    /**
     * Start 3-legged OAuth 1.0a flow.
     *
     * @param OAuthRequestToken $RequestToken
     * @param array $extraParams
     */
    public function authenticate(OAuthRequestToken $RequestToken, $extraParams = array())
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/authenticate');
        $Request->setParams($extraParams);
        // Set Request Token
        $Request->set('oauth_token', $RequestToken->getKey());
        // Redirect to login form
        $Response = new HttpResponse();
        $Response->redirect($Request->getUrl());
    }

    /**
     * Return from callback after user logged in
     * and grant access to consumer.
     *
     * @return null|OAuthAccessToken
     *
     * @throws \Exception
     */
    public function authenticateBack()
    {
        $Request = new OAuthRequest();
        if ($Request->containsKeys('oauth_token', 'oauth_verifier')) {
            $RequestToken = new OAuthRequestToken(
                $Request->get('oauth_token')
            );
            $RequestToken->setVerifier($Request->get('oauth_verifier'));

            return $this->getAccessToken($RequestToken);
        }

        return null;
    }

    // TODO: implement Echo and xAuth

    //==========================================================================================
    // Private methods

    /**
     * Build OAuthSignature in order to sign requests.
     *
     * @param OAuthToken $Token
     *
     * @return OAuthSignature
     *
     * @throws \Exception
     */
    protected function getOAuthSignature(OAuthToken $Token = null)
    {
        $OAuthSignature = OAuthSignature::getOAuthSignature(
            $this->signatureMethod, $this->Consumer, $Token
        );
        if ($this->signatureMethod == OAuthSignature::SIGNATURE_METHOD_RSA_SHA1) {
            /* @var OAuthSignatureRsaSha1 $OAuthSignature */
            $OAuthSignature->setRsaPrivateKey($this->getClientPrivateKey());
        }

        return $OAuthSignature;
    }

    /**
     * This method must be subclassed to return client private key.
     *
     * @return string Path to client private key used to sign requests
     *
     * @throws \Exception
     */
    protected function getClientPrivateKey()
    {
        throw new \Exception('This method must be subclassed');
    }

    private function getNonce()
    {
        return md5(microtime() . mt_rand());
    }

    private function getTimestamp()
    {
        return time();
    }
}

