<?php
namespace DevSeb\OAuthPhpLib\OAuth;

/**
 * OAuthAccessToken.
 */
class OAuthAccessToken extends OAuthToken
{
    /**
     * @var string Date GMT
     */
    private $dateExpiration;

    /**
     * OAuthAccessToken constructor.
     *
     * @param string $key
     * @param string $secret
     * @param string $dateExpiration
     *
     * @throws \Exception
     */
    public function __construct($key = '', $secret = '', $dateExpiration = '')
    {
        parent::__construct(OAuthToken::TYPE_ACCESS);
        $this->setKey($key);
        $this->setSecret($secret);
        $this->setExpires($dateExpiration);
    }

    /**
     * @param $dateExpiration
     */
    public function setExpires($dateExpiration)
    {
        $this->dateExpiration = $dateExpiration;
    }

    /**
     * @return string Datetime
     */
    public function getDateExpiration()
    {
        return $this->dateExpiration;
    }

    /**
     * @return int
     */
    public function getExpiresIn()
    {
        $timeExpiration = strtotime($this->dateExpiration);
        $timeCurrent = time();
        if ($timeExpiration && $timeCurrent > $timeCurrent) {
            return $timeExpiration - $timeCurrent;
        }

        return 0;
    }
}

