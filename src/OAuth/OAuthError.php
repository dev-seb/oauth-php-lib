<?php
namespace DevSeb\OAuthPhpLib\OAuth;

class OAuthError
{
    /**
     * @var string
     */
    private $error;

    /**
     * @var string
     */
    private $errorDescription;

    /**
     * @var string
     */
    private $errorUri;

    /**
     * OAuthError constructor.
     *
     * @param string $error
     * @param string $errorDescription
     * @param string $errorUri
     */
    public function __construct($error = '', $errorDescription = '', $errorUri = '')
    {
        $this->error = $error;
        $this->errorDescription = $errorDescription;
        $this->errorUri = $errorUri;
    }

    /**
     * @return string
     */
    public function getError()
    {
        return $this->error;
    }

    /**
     * @param string $error
     */
    public function setError($error)
    {
        $this->error = $error;
    }

    /**
     * @return string
     */
    public function getErrorDescription()
    {
        return $this->errorDescription;
    }

    /**
     * @param string $errorDescription
     */
    public function setErrorDescription($errorDescription)
    {
        $this->errorDescription = $errorDescription;
    }

    /**
     * @return string
     */
    public function getErrorUri()
    {
        return $this->errorUri;
    }

    /**
     * @param string $errorUri
     */
    public function setErrorUri($errorUri)
    {
        $this->errorUri = $errorUri;
    }
}

