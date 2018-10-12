<?php
namespace DevSeb\OAuthPhpLib\Client;

use DevSeb\OAuthPhpLib\Server\HttpResponse;

/**
 * Class HttpClient
 */
class HttpClient
{
    const HTTP_ADAPTER_CURL = 'Curl';

    /**
     * @var string
     */
    private $adapter = self::HTTP_ADAPTER_CURL;

    /**
     * @var int
     */
    private $timeout = 10;

    /**
     * @var string
     */
    private $credentials = '';

    /**
     * @var string
     */
    private $userAgent = 'oauth-php-lib/0.0.1 HttpClient';

    /**
     * @var string
     */
    private $cookiePath = '';

    /**
     * @var string
     */
    private $cacerts = '';

    /**
     * @var bool
     */
    private $checkSSL = true;

    /**
     * @var string
     */
    private $sslCert = '';

    /**
     * @var string
     */
    private $sslKey = '';

    /**
     * @var string
     */
    private $sslPassword = '';

    /**
     * @var bool
     */
    private $followLocation = false;

    /**
     * HttpClient constructor.
     */
    public function __construct()
    {
    }
    
    /**
     * Get response using selected HTTP adapter.
     *
     * @param HttpRequest $Request
     *
     * @return HttpResponse
     *
     * @throws \Exception
     */
    public function getResponse(HttpRequest $Request)
    {
        // Curl
        if ($this->adapter == self::HTTP_ADAPTER_CURL) {
            return $this->getResponseCurl($Request);
        }

        // Should not be here !
        throw new \Exception($this->adapter . ': not a valid Http Client adapter');
    }

    //====================================================================================
    // Getters / Setters

    public function setTimeout($timeout)
    {
        $this->timeout = $timeout;
    }

    public function getTimeout()
    {
        return $this->timeout;
    }

    /**
     * @param $adapter
     *
     * @throws \Exception
     */
    public function setHttpAdapter($adapter)
    {
        if (in_array($adapter, array(
            self::HTTP_ADAPTER_CURL,
        ))) {
            $this->adapter = $adapter;
        } else {
            throw new \Exception("'$adapter': not a valid HTTP adapter");
        }
    }

    public function getHttpAdapter()
    {
        return $this->adapter;
    }

    public function setCredentials($user, $pass)
    {
        $this->credentials = $user . ':' . $pass;
    }

    public function getCredentials()
    {
        $user = $pass = '';
        $parts = explode(':', $this->credentials);
        if (count($parts) == 2) {
            list($user, $pass) = $parts;
        }

        return array($user, $pass);
    }

    public function setUserAgent($userAgent)
    {
        $this->userAgent = $userAgent;
    }

    public function getUserAgent()
    {
        return $this->userAgent;
    }

    public function setCookiePath($cookiePath)
    {
        $this->cookiePath = $cookiePath;
    }

    public function getCookiePath()
    {
        return $this->cookiePath;
    }

    public function setCACerts($cacerts)
    {
        if(file_exists($cacerts)) {
            $this->cacerts = $cacerts;
        }
    }

    public function setCheckSSL($checkSSL)
    {
        $this->checkSSL = $checkSSL;
    }

    /**
     * Set SSL certificate
     *
     * @param $sslCert
     * @throws \Exception
     */
    public function setSSLCert($sslCert)
    {
        // SSL Certificate
        if(!file_exists($sslCert)) {
            throw new \Exception("$sslCert : file not found");
        }
        $this->sslCert = $sslCert;
    }

    /**
     * Set SSL Key
     *
     * @param $sslKey
     * @throws \Exception
     */
    public function setSSLKey($sslKey)
    {
        // SSL Key
        if(!file_exists($sslKey)) {
            throw new \Exception("$sslKey : file not found");
        }
        $this->sslKey = $sslKey;
    }

    /**
     * Set SSL certificate password
     *
     * @param $sslPassword
     */
    public function setSSLPassword($sslPassword)
    {
        // SSL Password
        if($sslPassword) {
            $this->sslPassword = $sslPassword;
        }
    }

    public function setFollowLocation($followLocation)
    {
        $this->followLocation = $followLocation;
    }

    //====================================================================================
    // Private method

    /**
     * Execute HTTP request using Curl adapter.
     *
     * @param HttpRequest $Request
     *
     * @return HttpResponse
     */
    private function getResponseCurl(HttpRequest $Request)
    {
        // Build header lines
        $httpHeaders = array();
        $headers = $Request->getHeaders();
        if (!empty($headers)) {
            foreach ($headers as $key => $val) {
                $httpHeaders[] = "$key: $val";
            }
        }

        //echo $Request->getUrl()."<br />\n";

        // Set options
        $options = array(
            // CURLOPT_VERBOSE => true,
            CURLOPT_URL => $Request->getUrl(true, false),
            CURLOPT_HTTPHEADER => $httpHeaders,
            CURLOPT_CONNECTTIMEOUT => $this->timeout,
            CURLOPT_TIMEOUT => $this->timeout,
            CURLOPT_HEADER => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_ENCODING => 'gzip',
        );
        if ($this->credentials != '') {
            $options[CURLOPT_USERPWD] = $this->credentials;
        }
        if ($this->userAgent != '') {
            $options[CURLOPT_USERAGENT] = $this->userAgent;
        }
        if ($this->cookiePath != '') {
            $options[CURLOPT_COOKIEJAR] = $this->cookiePath;
            $options[CURLOPT_COOKIEFILE] = $this->cookiePath;
        }
        if ($this->followLocation && !ini_get('open_basedir')) {
            $options[CURLOPT_FOLLOWLOCATION] = true;
        }
        // SSL
        if ($Request->isSSL()) {
            if ($this->checkSSL) {
                // Provided client certificate
                if($this->sslCert) {
                    $options[CURLOPT_SSLCERT] = $this->sslCert;
                    // Check if private key is provided for this certificate
                    if($this->sslKey) {
                        $options[CURLOPT_SSLKEY] = $this->sslKey;
                    }
                    // Check if password is required for this certificate
                    if($this->sslPassword) {
                        $options[CURLOPT_SSLCERTPASSWD] = $this->sslPassword;
                    }
                }
                else {
                    // Windows needs explicit path to load cacerts
                    if($this->cacerts) {
                        $options[CURLOPT_CAINFO] = $this->cacerts;
                        $options[CURLOPT_CAPATH] = dirname($this->cacerts);
                    }
                }
                // Enabled SSL host verification
                $options[CURLOPT_SSL_VERIFYHOST] = 2;
                $options[CURLOPT_SSL_VERIFYPEER] = true;
            } else {
                // Disable SSL host verification
                $options[CURLOPT_SSL_VERIFYHOST] = 0;
                $options[CURLOPT_SSL_VERIFYPEER] = false;
            }
        }
        // Add params according to HTTP method
        $params = $Request->getParams();

        switch ($Request->getMethod()) {
            case HttpRequest::METHOD_DELETE:
                $options[CURLOPT_CUSTOMREQUEST] = 'DELETE';
                break;
            // no break
            case HttpRequest::METHOD_GET:
                if (!empty($params)) {
                    $options[CURLOPT_URL] .= '?' . http_build_query($params);
                }
                break;
            case HttpRequest::METHOD_POST:
                $body = $Request->getBody();
                $params = $Request->getParams();
                if (!empty($params)) {
                    $body = http_build_query($params);
                }
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_POSTFIELDS] = $body;
                break;
        }

        // Send request
        $ch = curl_init();
        curl_setopt_array($ch, $options);
        $response = curl_exec($ch);

        // Parse response
        $responseCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $responseTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);

        // Init HttpResponse to be returned
        $Response = new HttpResponse();
        $Response->setCode($responseCode);
        $Response->setTime($responseTime);

        // Error
        $error = curl_errno($ch);
        if ($error > 0) {
            // An error occured
            $Request->setStatus(HttpRequest::STATUS_ERROR);
            // Check timeout
            if ($error == 28 || $responseTime > $this->timeout) {
                $Request->setStatus(HttpRequest::STATUS_TIMEOUT);
                $Response->setCode(HttpResponse::HTTP_CODE_REQUEST_TIMEOUT);
            }
        } else {
            // Extract headers and body from result
            $headerSize = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
            $responseHead = substr($response, 0, $headerSize);
            $responseBody = substr($response, $headerSize);
            // Set headers and body to response
            $Response->parseHeaders($responseHead);
            $Response->setBody($responseBody);
        }

        // Close
        curl_close($ch);

        return $Response;
    }
    
}