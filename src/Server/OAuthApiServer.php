<?php
namespace DevSeb\OAuthPhpLib\Server;

use DevSeb\OAuthPhpLib\Client\HttpRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthRefreshToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthToken;

/**
 * OAuthApiServer.
 */
abstract class OAuthApiServer extends HttpServer
{
    const OAUTH_VERSION_1 = '1.0a';
    const OAUTH_VERSION_2 = '2.0';

    /**s
     * @var string
     */
    private $oauthVersion;

    /**
     * @var OAuthConsumer
     */
    protected $Consumer;

    /**
     * OAuthApiServer constructor.
     *
     * @param HttpRequest $Request
     */
    public function __construct(HttpRequest $Request)
    {
        parent::__construct($Request);
    }

    /**
     * Init
     */
    protected function init()
    {
        $this->Consumer = new OAuthConsumer();
    }

    /**
     * @param $version
     *
     * @throws \Exception
     */
    public function setVersion($version)
    {
        if (!in_array($version, array(
            self::OAUTH_VERSION_1,
            self::OAUTH_VERSION_2,
        ))
        ) {
            throw new \Exception("'$version': this OAuth version is not allowed");
        }
        $this->oauthVersion = $version;
    }

    /**
     * @throws \Exception
     */
    public function authenticate()
    {
        $error = '';
        // Load consumer
        if ($this->oauthVersion == self::OAUTH_VERSION_1) {
            $request_token = $this->Request->get('oauth_token');
            $this->Consumer = $this->getConsumerFromToken($request_token);
        } elseif ($this->oauthVersion == self::OAUTH_VERSION_2) {
            $client_id = $this->Request->get('client_id');
            $this->Consumer = $this->getConsumer($client_id);
        }
        if (!$this->Consumer) {
            $error = "Can't get consumer";
        } else {
            if ($this->Request->containsKey('form_sent')) {
                $username = $this->Request->get('username');
                $password = $this->Request->get('password');
                if (!$this->authenticateUser($this->Consumer, $username, $password)) {
                    $error = 'Authentication failed';
                } else {
                    // v1 : load request token
                    if ($this->oauthVersion == self::OAUTH_VERSION_1) {
                        $request_token = $this->Request->get('oauth_token');
                        /** @var OAuthRequestToken $RequestToken */
                        $RequestToken = $this->getToken(
                            $this->Consumer, $request_token, OAuthToken::TYPE_REQUEST
                        );
                        if ($RequestToken) {
                            $redirectUri = $RequestToken->getRedirectUri();
                            if ($redirectUri) {
                                $separator = (strpos($redirectUri, '?') > 0) ? '&' : '?';
                                $redirectUri .= $separator . http_build_query(array(
                                    'oauth_token' => $RequestToken->getKey(),
                                    'oauth_verifier' => $RequestToken->getVerifier(),
                                ));
                                $this->Response->redirect($redirectUri);
                            }
                            else {
                                $error = 'Redirect URI is not set';
                            }
                        }
                        else {
                            $error = 'RequestToken is not set';
                        }
                    }
                    // v2 : create request token
                    else if ($this->oauthVersion == self::OAUTH_VERSION_2) {
                        $redirectUri = $this->Request->get('redirect_uri');
                        if ($redirectUri) {
                            /** @var OAuthRequestToken $RequestToken */
                            $RequestToken = $this->newRequestToken($this->Consumer);
                            if ($RequestToken) {
                                // Redirect to redirect URI
                                $separator = (strpos($redirectUri, '?') > 0) ? '&' : '?';
                                $redirectUri .= $separator . http_build_query(array(
                                    'code' => $RequestToken->getKey(),
                                    'state' => $this->Request->get('state'),
                                ));
                                $this->Response->redirect($redirectUri);
                            }
                            else {
                                $error = 'RequestToken is not set';
                            }
                        }
                        else {
                            $error = 'Redirect URI is not set';
                        }
                    }
                    if($error == '') {
                        // Something went wrong
                        $error = 'Internal server error';
                    }
                }
            }
            $this->Request->set('error', $error);
            $this->showLoginPage();
        }
        if ($error != '') {
            echo "Error: $error";
        }
    }

    //=====================================================================
    // OAuth data store interface

    /**
     * Check that a consumer exists with given consumer key.
     *
     * @param string $consumerKey
     *
     * @return OAuthConsumer
     */
    abstract protected function getConsumer($consumerKey);

    /**
     * Check that a consumer exists from a key.
     *
     * @param string $tokenKey
     *
     * @return OAuthConsumer
     */
    abstract protected function getConsumerFromToken($tokenKey);

    /**
     * @param OAuthConsumer $Consumer
     * @param string $tokenKey
     * @param string $tokenType
     *
     * @return OAuthToken
     */
    abstract protected function getToken(OAuthConsumer $Consumer, $tokenKey, $tokenType);

    /**
     * Create a new request token for this consumer.
     *
     * @param OAuthConsumer $Consumer
     * @param string $redirectUri
     *
     * @return OAuthRequestToken
     */
    abstract protected function newRequestToken(OAuthConsumer $Consumer, $redirectUri = '');

    /**
     * Create a new access token for this consumer.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthRequestToken $RequestToken
     * @param OAuthRefreshToken|null $RefreshToken
     *
     * @return OAuthAccessToken
     */
    abstract protected function newAccessToken(OAuthConsumer $Consumer, OAuthRequestToken $RequestToken = null, OAuthRefreshToken $RefreshToken = null);

    /**
     * Show HTML login page for 3-legged authentication
     */
    abstract protected function showLoginPage();

    /**
     * Use for 3-legged flows or OAuth 2 grant_type password.
     *
     * @param OAuthConsumer $Consumer
     * @param $username
     * @param $password
     *
     * @return mixed
     */
    abstract protected function authenticateUser(OAuthConsumer $Consumer, $username, $password);

    //=====================================================================
    // HttpServer overrides

    /**
     * @Override
     */
    public function render()
    {
        try {
            $this->init();
            parent::render();
        } catch(\Exception $e) {
            $this->error(self::E_OAUTH_SERVER_ERROR, $e->getMessage(), $e->getTraceAsString());
        }
    }

    /**
     * @Override
     */
    public function showResponse()
    {
        $this->Response->sendHeaders();
        parent::showResponse();
    }

    //=====================================================================
    // Errors

    const E_OAUTH_INVALID_REQUEST = 'invalid_request';
    const E_OAUTH_UNAUTHORIZED_CLIENT = 'unauthorized_client';
    const E_OAUTH_ACCESS_DENIED = 'access_denied';
    const E_OAUTH_UNSUPPORTED_RESPONSE_TYPE = 'unsupported_response_type';
    const E_OAUTH_INVALID_SCOPE = 'invalid_scope';
    const E_OAUTH_SERVER_ERROR = 'server_error';
    const E_OAUTH_TEMPORARILY_UNAVAILABLE = 'temporarily_unavailable';
    const E_OAUTH_INVALID_CLIENT = 'invalid_client';
    const E_OAUTH_INVALID_GRANT = 'invalid_grant';
    const E_OAUTH_UNSUPPORTED_GRANT_TYPE = 'unsupported_grant_type';

    /**
     * Display error number and message.
     *
     * @param string $error
     * @param string $error_description
     * @param string $trace
     *
     * @Override
     */
    public function error($error = '', $error_description = '', $trace = '')
    {
        if (!$error) {
            $error = self::E_OAUTH_SERVER_ERROR;
        }
        if ($error == self::E_OAUTH_INVALID_CLIENT) {
            $this->Response->setCode(HttpResponse::HTTP_CODE_UNAUTHORIZED);
        }
        $this->ResponseNode = new ResponseNode();
        $this->ResponseNode->setNode('error', $error);
        $this->ResponseNode->setNode('error_description', $error_description);
        if($trace != '') {
            $this->ResponseNode->setNode('stacktrace', explode("\n", $trace));
            $this->ResponseNode->setNode('headers', $this->Request->getHeaders());
            $this->ResponseNode->setNode('request', $this->Request->getBody());
        }
        $this->showResponse();
    }
}
