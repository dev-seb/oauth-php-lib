<?php
namespace DevSeb\OAuthPhpLib\OAuth;

/**
 * Class OAuthRefreshToken.
 *
 * RefreshToken for OAuth 2.0 implementation
 */
class OAuthRefreshToken extends OAuthToken
{
    /**
     * OAuthRefreshToken constructor.
     *
     * @param string $key
     *
     * @throws \Exception
     */
    public function __construct($key = '')
    {
        parent::__construct(OAuthToken::TYPE_REFRESH);
        $this->setKey($key);
        $this->setSecret('');
    }
}

