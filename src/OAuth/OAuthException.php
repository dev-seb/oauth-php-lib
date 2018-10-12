<?php
namespace DevSeb\OAuthPhpLib\OAuth;

/**
 * Class OAuthException
 */
class OAuthException extends \Exception
{
    /**
     * @var int
     */
    private $error;

    /**
     * OAuthException constructor.
     *
     * @param string $message
     * @param int $error
     */
    public function __construct($message = '', $error = 0)
    {
        parent::__construct($message);
        $this->error = $error;
    }

    /**
     * @return int
     */
    public function getOAuthError()
    {
        return $this->error;
    }
}
