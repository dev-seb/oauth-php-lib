<?php
namespace DevSeb\OAuthPhpLib\Client;

use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthError;
use DevSeb\OAuthPhpLib\Server\HttpResponse;
use DevSeb\OAuthPhpLib\Server\OAuthApiServer;

/**
 * OAuthApiClient.
 */
abstract class OAuthApiClient extends HttpClient
{
    /**
     * @var string
     */
    protected $version;
    /**
     * @var
     */
    protected $url;
    /**
     * @var OAuthConsumer
     */
    protected $Consumer;
    /**
     * @var bool
     */
    protected $isError = false;
    /**
     * @var OAuthError
     */
    protected $Error;

    /**
     * OAuthApiClient constructor.
     *
     * @param $url
     * @param OAuthConsumer $Consumer
     */
    public function __construct($url, OAuthConsumer $Consumer = null)
    {
        $this->version = OAuthApiServer::OAUTH_VERSION_1;
        $this->url = $url;
        $this->Consumer = $Consumer;
    }

    /**
     * @return bool
     */
    public function isError()
    {
        return $this->isError;
    }

    /**
     * @return OAuthError
     */
    public function getOAuthError()
    {
        return $this->Error;
    }

    /**
     * Override to check OAuth specific errors.
     *
     * @param HttpRequest $Request
     *
     * @return HttpResponse
     *
     * @throws \Exception
     */
    public function getResponse(HttpRequest $Request)
    {
        $this->isError = false;
        $Response = parent::getResponse($Request);
        // Check for OAuth errors
        if ($Request->isOk()
            && ($Response->isOk() || in_array($Response->getCode(), array(
                HttpResponse::HTTP_CODE_NOT_FOUND,
                HttpResponse::HTTP_CODE_FORBIDDEN,
                HttpResponse::HTTP_CODE_UNAUTHORIZED
         )))) {
            $body = $Response->getBody();
            $response = json_decode($body);
            if ($response && isset($response->error)) {
                $error = $response->error;
                $errorDescription = $errorUri = '';
                if (isset($response->error_description)) {
                    $errorDescription = $response->error_description;
                }
                if (isset($response->error_uri)) {
                    $errorUri = $response->error_uri;
                }
                $this->isError = true;
                $this->Error = new OAuthError($error, $errorDescription, $errorUri);
            }
        }

        return $Response;
    }

    /**
     * @param $version
     *
     * @throws \Exception
     */
    public function setVersion($version)
    {
        if (!in_array($version, array(
            OAuthApiServer::OAUTH_VERSION_1,
            OAuthApiServer::OAUTH_VERSION_2,
        ))
        ) {
            throw new \Exception("'$version': this OAuth version is not allowed");
        }
        $this->version = $version;
    }

    public function setConsumer(OAuthConsumer $Consumer)
    {
        $this->Consumer = $Consumer;
    }
}

