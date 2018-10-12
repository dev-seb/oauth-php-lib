<?php
namespace DevSeb\OAuthPhpLib\OAuth;

/**
 * OAuthToken.
 *
 * Wrapper for OAuth tokens :
 *  - Request tokens
 *  - Access tokens
 *  - Refresh tokens
 */
abstract class OAuthToken
{
    const TYPE_REQUEST = 'RequestToken';
    const TYPE_ACCESS = 'AccessToken';
    const TYPE_REFRESH = 'RefreshToken';

    /**
     * @var string
     */
    private $type;

    /**
     * @var string
     */
    private $key;

    /**
     * @var string
     */
    private $secret;

    /**
     * OAuthToken constructor.
     *
     * @param $type
     *
     * @throws \Exception
     */
    public function __construct($type)
    {
        $this->setType($type);
        $this->key = '';
        $this->secret = '';
    }

    /**
     * @return array
     * @throws \Exception
     */
    public static function getSecureToken()
    {
        // check dependencies
        if (!extension_loaded('openssl')) {
            throw new \Exception('openssl extension is not loaded');
        }
        if (!extension_loaded('gmp')) {
            throw new \Exception('gmp extension is not loaded');
        }
        // Get a strong random binary entropy
        $entropy = openssl_random_pseudo_bytes(32);
        // Concatenate with random number based on current time
        $entropy .= uniqid(mt_rand(), true);
        // Hash the binary entropy
        $hash = hash('sha512', $entropy);
        // Base62 Encode the hash, resulting in an 86 or 85 character string
        $hash = gmp_strval(gmp_init($hash, 16), 62);
        // Return secure token key/secret pairs
        return array(
            'key' => substr($hash, 0, 32),
            'secret' => substr($hash, 32, 48),
        );
    }

    /**
     * Factory.
     *
     * @param $type
     *
     * @return OAuthToken
     *
     * @throws \Exception
     */
    public static function getToken($type)
    {
        if ($type == self::TYPE_REQUEST) {
            return new OAuthRequestToken();
        } elseif ($type == self::TYPE_ACCESS) {
            return new OAuthAccessToken();
        } elseif ($type == self::TYPE_REFRESH) {
            return new OAuthRefreshToken();
        } else {
            throw new \Exception("'$type': not a valid oauth token type");
        }
    }

    /**
     * @param $type
     *
     * @throws \Exception
     */
    public function setType($type)
    {
        if (in_array($type, array(
            self::TYPE_REQUEST,
            self::TYPE_ACCESS,
            self::TYPE_REFRESH,
        ))) {
            $this->type = $type;
        } else {
            throw new \Exception("'$type': not a valid oauth token type");
        }
    }

    /**
     * @return string
     */
    public function getType()
    {
        return $this->type;
    }

    /**
     * @param $key
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * @return string
     */
    public function getKey()
    {
        return $this->key;
    }

    /**
     * @param $secret
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;
    }

    /**
     * @return string
     */
    public function getSecret()
    {
        return $this->secret;
    }
}

