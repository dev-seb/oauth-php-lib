<?php
namespace DevSeb\OAuthPhpLib\OAuth;

class OAuthSignatureHmacSha1 extends OAuthSignature
{
    /**
     * OAuthSignatureHmacSha1 constructor.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthToken|null $Token
     *
     * @throws \Exception
     */
    public function __construct(OAuthConsumer $Consumer, OAuthToken $Token = null)
    {
        parent::__construct($Consumer, $Token);
        $this->setSignatureMethod(OAuthSignature::SIGNATURE_METHOD_HMAC_SHA1);
    }

    //=====================================================================================
    // OAuthSignature implementation

    /**
     * @param OAuthRequest $Request
     * @param array $params
     * @return string
     */
    public function getSignature(OAuthRequest $Request, $params)
    {
        $url = $Request->getUrl(true, false);
        $method = $Request->getMethod();
        $baseSignature = $this->getBaseSignature($url, $params, $method);
        $encryptKey = $this->getEncryptKey();
        $signature = hash_hmac('sha1', $baseSignature, $encryptKey, true);

        return base64_encode($signature);
    }
}

