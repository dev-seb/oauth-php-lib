<?php
namespace DevSeb\OAuthPhpLib\OAuth;

class OAuthSignaturePlainText extends OAuthSignature
{
    /**
     * OAuthSignaturePlainText constructor.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthToken|null $Token
     *
     * @throws \Exception
     */
    public function __construct(OAuthConsumer $Consumer, OAuthToken $Token = null)
    {
        parent::__construct($Consumer, $Token);
        $this->setSignatureMethod(OAuthSignature::SIGNATURE_METHOD_PLAINTEXT);
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
        return $this->getEncryptKey();
    }
}

