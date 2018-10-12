<?php
namespace DevSeb\OAuthPhpLib\OAuth;

use DevSeb\OAuthPhpLib\Client\HttpRequest;

/**
 * OAuthRequest
 * OAuth request sent by a client, parse params
 * from header or GET/POST parameters.
 */
class OAuthRequest extends HttpRequest
{

    /**
     * Build OAuth Authorization header from oauth params.
     *
     * @param array $oauthParams
     */
    public function setOAuthAuthorizationHeader($oauthParams)
    {
        // To header
        $oauthHeader = 'OAuth';
        $first = true;
        foreach ($oauthParams as $key => $val) {
            if (substr($key, 0, 6) != 'oauth_') {
                continue;
            }
            $oauthHeader .= ($first) ? ' ' : ',';
            $oauthHeader .= OAuthSignature::urlEncode($key) . '="' . OAuthSignature::urlEncode($val) . '"';
            $first = false;
        }
        $this->setHeader('Authorization', $oauthHeader);
    }

    public function getOAuthParams()
    {
        if ($this->hasHeader('Authorization')) {
            return $this->getOAuthParamsFromHeader();
        }

        return $this->getOAuthParamsFromQuery();
    }

    public function getOAuthParamsFromQuery()
    {
        $oauthParams = array();
        $params = $this->getParams();
        foreach ($params as $key => $val) {
            if (substr($key, 0, 6) == 'oauth_') {
                $oauthParams[$key] = urldecode($val);
            }
        }

        return $oauthParams;
    }

    /**
     * Extract OAuth params from Authorization header.
     *
     * @return array
     */
    public function getOAuthParamsFromHeader()
    {
        $oauthParams = array();
        $headers = $this->getHeaders();
        if (isset($headers['Authorization'])) {
            $authHeader = $headers['Authorization'];
            if (substr($authHeader, 0, 6) == 'OAuth ') {
                $pairs = explode(',', substr($authHeader, 7));
                if (!empty($pairs)) {
                    foreach ($pairs as $pair) {
                        if (preg_match('/([^=]+)="([^"]+)"/', $pair, $matches)) {
                            $key = trim($matches[1]);
                            $val = trim($matches[2]);
                            if (substr($key, 0, 6) == 'oauth_') {
                                $oauthParams[$key] = urldecode($val);
                            }
                        }
                    }
                }
            }
        }

        return $oauthParams;
    }

    /**
     * @param string $body
     */
    public function setBody($body)
    {
        $this->setMethod(HttpRequest::METHOD_POST);
        $this->setHeader('Content-Type', 'application/json');
        //$this->setHeader('Accept-Encoding', 'identity'); // Disable gzip for tcpdump
        parent::setBody($body);
    }
}

