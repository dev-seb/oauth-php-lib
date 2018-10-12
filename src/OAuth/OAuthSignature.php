<?php
namespace DevSeb\OAuthPhpLib\OAuth;

use DevSeb\OAuthPhpLib\Client\HttpRequest;


/**
 * OAuthSignature
 * Helper class to handle OAuth signature method.
 */
abstract class OAuthSignature
{
    const SIGNATURE_METHOD_PLAINTEXT = 'PLAINTEXT';
    const SIGNATURE_METHOD_HMAC_SHA1 = 'HMAC-SHA1';
    const SIGNATURE_METHOD_RSA_SHA1 = 'RSA-SHA1';

    /**
     * @var OAuthConsumer
     */
    protected $Consumer;
    /**
     * @var OAuthToken
     */
    protected $Token;
    /**
     * @var string
     */
    protected $signatureMethod;

    /**
     * OAuthSignature constructor.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthToken|null $Token
     */
    public function __construct(OAuthConsumer $Consumer, OAuthToken $Token = null)
    {
        $this->Consumer = $Consumer;
        $this->Token = $Token;
    }

    /**
     * Factory.
     *
     * @param $signatureMethod
     * @param OAuthConsumer $Consumer
     * @param OAuthToken $Token
     *
     * @return OAuthSignature
     *
     * @throws \Exception
     */
    public static function getOAuthSignature($signatureMethod, OAuthConsumer $Consumer, OAuthToken $Token = null)
    {
        if ($signatureMethod == self::SIGNATURE_METHOD_PLAINTEXT) {
            return new OAuthSignaturePlainText($Consumer, $Token);
        } elseif ($signatureMethod == self::SIGNATURE_METHOD_HMAC_SHA1) {
            return new OAuthSignatureHmacSha1($Consumer, $Token);
        } elseif ($signatureMethod == self::SIGNATURE_METHOD_RSA_SHA1) {
            return new OAuthSignatureRsaSha1($Consumer, $Token);
        } else {
            throw new \Exception("'$signatureMethod': not a valid oauth signature method");
        }
    }

    /**
     * @param $signatureMethod
     *
     * @throws \Exception
     */
    public function setSignatureMethod($signatureMethod)
    {
        if (in_array($signatureMethod, array(
            self::SIGNATURE_METHOD_PLAINTEXT,
            self::SIGNATURE_METHOD_HMAC_SHA1,
            self::SIGNATURE_METHOD_RSA_SHA1,
        ))) {
            $this->signatureMethod = $signatureMethod;
        } else {
            throw new \Exception("'$signatureMethod': not a valid oauth signature method");
        }
    }

    /**
     * @return string
     */
    public function getSignatureMethod()
    {
        return $this->signatureMethod;
    }

    /**
     * Check request signature.
     *
     * @param HttpRequest $Request
     *
     * @return bool
     *
     * @throws \Exception
     */
    public function checkRequest(HttpRequest $Request)
    {
        $OAuthRequest = new OAuthRequest($Request->getUrl());
        $OAuthRequest->setHeaders($Request->getHeaders());
        $OAuthRequest->setParams($Request->getParams());
        // Get signature from request
        $requestSignature = $Request->get('oauth_signature');
        $requestSignature = urldecode($requestSignature);
        // Get a local signature for this request using same method
        $oauthSignature = $this->getSignature($OAuthRequest, $OAuthRequest->getOAuthParams());
        $oauthSignature = urldecode($oauthSignature);

        return $oauthSignature == $requestSignature;
    }

    /**
     * Get signature for request and add to request params.
     *
     * @param OAuthRequest $Request
     * @param array $oauthParams
     * @param bool $signToHeader
     *
     * @throws \Exception
     */
    public function signRequest(OAuthRequest $Request, $oauthParams, $signToHeader = true)
    {
        // Add Signature method
        $oauthParams['oauth_signature_method'] = $this->getSignatureMethod();
        // Add Oauth params
        if ($signToHeader) {
            $Request->setOAuthAuthorizationHeader($oauthParams);
        } else {
            // As params (GET or POST)
            $Request->setParams($oauthParams);
        }
        // Sign request
        $oauthSignature = $this->getSignature($Request, $Request->getOAuthParams());
        // Add signature to request
        $oauthParams['oauth_signature'] = $oauthSignature;
        // Finaly add params to our base request
        $Request->setParams($oauthParams);
    }

    /**
     * Return OAuth signature.
     *
     * @param OAuthRequest $Request
     * @param array $params
     *
     * @return string oauth_signature
     *
     * @throws \Exception
     */
    abstract public function getSignature(OAuthRequest $Request, $params);

    //==========================================================================================
    // Private method

    /**
     * Return OAuth base signature string.
     *
     * @param string $url
     * @param array $params
     * @param string $method
     *
     * @return string
     */
    protected function getBaseSignature($url, $params = array(), $method = 'GET')
    {
        $parts = array(
            self::urlEncode($this->getNormalizedMethod($method)),
            self::urlEncode($this->getNormalizedUrl($url)),
            self::urlEncode($this->getNormalizedParams($params)),
        );

        return implode('&', $parts);
    }

    /**
     * Normalize HTTP method.
     *
     * @param string $method
     *
     * @return string
     */
    protected function getNormalizedMethod($method)
    {
        return strtoupper($method);
    }

    /**
     * Normalize URL.
     *
     * @param string $url
     *
     * @return string
     */
    protected function getNormalizedUrl($url)
    {
        return strtolower($url);
    }

    /**
     * Normalize params.
     *
     * @param array $params
     *
     * @return string
     */
    protected function getNormalizedParams($params)
    {
        ksort($params);
        $normalized = null;
        foreach ($params as $key => $val) {
            if ($key != 'oauth_signature') {
                if ($normalized) {
                    $normalized .= '&';
                }
                $normalized .= self::urlEncode($key) . '=' . self::urlEncode($val);
            }
        }

        return $normalized;
    }

    /**
     * Return encrypted key.
     *
     * @return string
     */
    protected function getEncryptKey()
    {
        $parts = array(
            self::urlEncode($this->Consumer->getSecret()),
        );
        if ($this->Token) {
            $parts[] = $this->Token->getSecret();
        }

        return implode('&', $parts);
    }

    /**
     * Url encoding RFC 3986.
     *
     * @param string $input
     *
     * @return string
     */
    public static function urlEncode($input)
    {
        $input = rawurldecode($input);
        $input = str_replace('+', ' ', $input);
        $input = str_replace('%7E', '~', $input);

        return $input;
    }
}

