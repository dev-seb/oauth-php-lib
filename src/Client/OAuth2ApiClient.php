<?php
namespace DevSeb\OAuthPhpLib\Client;

use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthRefreshToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\Server\HttpResponse;
use DevSeb\OAuthPhpLib\Server\OAuth2ApiServer;
use DevSeb\OAuthPhpLib\Server\OAuthApiServer;

/**
 * OAuth2ApiClient.
 */
class OAuth2ApiClient extends OAuthApiClient
{
    /**
     * @var bool
     */
    private $useAuthorizationHeader = true;

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
        $this->setVersion(OAuthApiServer::OAUTH_VERSION_2);
    }

    /**
     * @param $useAuthorizationHeader
     */
    public function setUseAuthorizationHeader($useAuthorizationHeader)
    {
        $this->useAuthorizationHeader = $useAuthorizationHeader;
    }

    /**
     * Return response from signed OAuth request.
     *
     * @param OAuthRequest $Request
     * @param OAuthAccessToken $AccessToken
     *
     * @return HttpResponse
     *
     * @throws \Exception
     */
    public function getOAuthResponse(OAuthRequest $Request, OAuthAccessToken $AccessToken = null)
    {
        if ($AccessToken) {
            if ($this->useAuthorizationHeader) {
                $Request->setHeader('Authorization', OAuth2ApiServer::TOKEN_TYPE_BEARER . ' ' . $AccessToken->getKey());
            } else {
                $Request->set('access_token', $AccessToken->getKey());
            }
        }
        return $this->getResponse($Request);
    }

    /**
     * Return Access Token using credentials grant type.
     *
     * @return OAuthAccessToken
     *
     * @throws \Exception
     */
    public function getAccessTokenFromClientCredentials()
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/token');
        // Set params
        $Request->setParams(array(
            'grant_type' => OAuth2ApiServer::GRANT_TYPE_CREDENTIALS,
        ));
        // Add credentials
        if ($this->useAuthorizationHeader) {
            // Use BasicAuth in headers
            $this->setCredentials(
                $this->Consumer->getKey(),
                $this->Consumer->getSecret()
            );
        } else {
            // Use query params
            $Request->setParams(array(
                'client_id' => $this->Consumer->getKey(),
                'client_secret' => $this->Consumer->getSecret(),
            ));
        }
        // Get response
        $Response = $this->getResponse($Request);
        if ($Request->isOk() && $Response->isOk() && !$this->isError()) {
            $json = json_decode($Response->getBody());
            if ($json) {
                //$token_type = $json->token_type;
                $AccessToken = new OAuthAccessToken(
                    $json->access_token,
                    $json->expires_in
                );

                return $AccessToken;
            }
        }

        return null;
    }

    /**
     * Return Access Token using password grant type.
     *
     * @param $username
     * @param $password
     *
     * @return OAuthAccessToken
     *
     * @throws \Exception
     */
    public function getAccessTokenFromPassword($username, $password)
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/token');
        // Set params
        $Request->setParams(array(
            'grant_type' => OAuth2ApiServer::GRANT_TYPE_PASSWORD,
            'username' => $username,
            'password' => $password,
        ));
        // Add credentials
        if ($this->useAuthorizationHeader) {
            // Use BasicAuth in headers
            $this->setCredentials(
                $this->Consumer->getKey(),
                $this->Consumer->getSecret()
            );
        } else {
            // Use query params
            $Request->setParams(array(
                'client_id' => $this->Consumer->getKey(),
                'client_secret' => $this->Consumer->getSecret(),
            ));
        }
        // Get response
        $Response = $this->getResponse($Request);
        if ($Request->isOk() && $Response->isOk() && !$this->isError()) {
            $json = json_decode($Response->getBody());
            if ($json) {
                //$token_type = $json->token_type;
                $AccessToken = new OAuthAccessToken(
                    $json->access_token,
                    $json->expires_in
                );

                return $AccessToken;
            }
        }

        return null;
    }

    /**
     * Exchange code (Request Token) with Access Token using authorization_code grant type.
     *
     * @param OAuthRequestToken $RequestToken
     *
     * @return array array(OAuthAccessToken, OAuthRefreshToken)
     *
     * @throws \Exception
     */
    public function getAccessTokenFromAuthorizationCode(OAuthRequestToken $RequestToken)
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/token');
        // Set params
        $Request->setParams(array(
            'client_id' => $this->Consumer->getKey(),
            'client_secret' => $this->Consumer->getSecret(),
            'code' => $RequestToken->getKey(),
            'grant_type' => OAuth2ApiServer::GRANT_TYPE_AUTHORIZATION,
        ));
        // Get response
        $Response = $this->getOAuthResponse($Request);
        if ($Request->isOk() && $Response->isOk()) {
            $json = json_decode($Response->getBody());
            if ($json) {
                $RefreshToken = new OAuthRefreshToken($json->refresh_token);
                $AccessToken = new OAuthAccessToken(
                    $json->access_token,
                    $json->expires_in
                );

                return array($AccessToken, $RefreshToken);
            }
        }

        return array(null, null);
    }

    /**
     * Exchange Refresh Token with Access Token.
     *
     * @param OAuthRefreshToken $RefreshToken
     * @param string $scope
     *
     * @return array array(OAuthRefreshToken, OAuthAccessToken)
     *
     * @throws \Exception
     */
    public function getAccessTokenFromRefreshToken(OAuthRefreshToken $RefreshToken, $scope = '')
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/token');
        // Set params
        $Request->setParams(array(
            'client_id' => $this->Consumer->getKey(),
            'client_secret' => $this->Consumer->getSecret(),
            'refresh_token' => $RefreshToken->getKey(),
            'scope' => $scope,
            'grant_type' => OAuth2ApiServer::GRANT_TYPE_REFRESH_TOKEN,
        ));
        // Get response
        $Response = $this->getOAuthResponse($Request);
        if ($Request->isOk() && $Response->isOk()) {
            $json = json_decode($Response->getBody());
            if ($json) {
                $RefreshToken = new OAuthRequestToken($json->refresh_token);
                $RequestToken = new OAuthRequestToken(
                    $json->access_token,
                    $json->expires_in
                );

                return array($RequestToken, $RefreshToken);
            }
        }

        return null;
    }

    /**
     * Authenticate user to get request token.
     *
     * @param string $redirect_uri
     * @param string $scope
     * @param string $state
     * @param array $extraParams
     */
    public function authenticate($redirect_uri, $scope = '', $state = '', $extraParams = array())
    {
        // Build Request
        $Request = new OAuthRequest($this->url . 'oauth/auth');
        $Request->setParams($extraParams);
        // Add params
        $oauthParams = array(
            'client_id' => $this->Consumer->getKey(),
            'redirect_uri' => $redirect_uri,
            'state' => $state,
            'scope' => $scope,
        );
        $Request->setParams($oauthParams);
        $Response = new HttpResponse();
        $Response->redirect($Request->getUrl());
    }

    /**
     * @param HttpRequest $Request
     *
     * @return array|null
     *
     * @throws \Exception
     */
    public function authenticateBack(HttpRequest $Request)
    {
        // Get response
        if ($Request->containsKey('code')) {
            if ($Request->get('code') != '') {
                $RequestToken = new OAuthRequestToken(
                    $Request->get('code')
                );

                return $this->getAccessTokenFromAuthorizationCode($RequestToken);
            }
        }

        return null;
    }
}

