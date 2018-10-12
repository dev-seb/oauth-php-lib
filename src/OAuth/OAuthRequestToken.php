<?php
namespace DevSeb\OAuthPhpLib\OAuth;

/**
 * OAuthRequestToken.
 */
class OAuthRequestToken extends OAuthToken
{
    /**
     * @var string
     */
    private $verifier;

    /**
     * @var string
     */
    private $redirectUri;

    /**
     * OAuthRequestToken constructor.
     *
     * @param string $key
     * @param string $secret
     * @throws \Exception
     */
    public function __construct($key = '', $secret = '')
    {
        parent::__construct(OAuthToken::TYPE_REQUEST);
        $this->setKey($key);
        $this->setSecret($secret);
        $this->setVerifier('');
        $this->setRedirectUri('');
    }

    /**
     * @return mixed
     */
    public function getVerifier()
    {
        return $this->verifier;
    }

    /**
     * @param mixed $verifier
     */
    public function setVerifier($verifier)
    {
        $this->verifier = $verifier;
    }

    /**
     * @return mixed
     */
    public function getRedirectUri()
    {
        return $this->redirectUri;
    }

    /**
     * @param mixed $redirectUri
     */
    public function setRedirectUri($redirectUri)
    {
        $this->redirectUri = $redirectUri;
    }
}

