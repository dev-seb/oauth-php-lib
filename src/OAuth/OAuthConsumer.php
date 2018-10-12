<?php
namespace DevSeb\OAuthPhpLib\OAuth;

/**
 * OAuthConsumer.
 */
class OAuthConsumer
{
    /**
     * @var string
     */
    private $name;

    /**
     * @var string
     */
    private $key = '';

    /**
     * @var string
     */
    private $secret = '';

    public function __construct($key = '', $secret = '')
    {
        $this->key = $key;
        $this->secret = $secret;
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @param string $name
     */
    public function setName($name)
    {
        $this->name = $name;
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

