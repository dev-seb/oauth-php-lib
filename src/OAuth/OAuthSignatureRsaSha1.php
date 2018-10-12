<?php
namespace DevSeb\OAuthPhpLib\OAuth;
use DevSeb\OAuthPhpLib\Client\HttpRequest;


/**
 * Class OAuthSignatureRsaSha1.
 *
 * To generate key pairs with openssl:
 * $ openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
 * $ openssl rsa -pubout -in private.pem -out public.pem
 *
 * To convert existing RSA .pub public key from .pem X.509 public key:
 * $ openssl req -x509 -key /path/to/id_rsa -nodes -days 365 -newkey rsa:2048 -out id_rsa.pem
 *
 * The client has to provide the public key to server in order to verify signature
 */
class OAuthSignatureRsaSha1 extends OAuthSignature
{
    /**
     * @var resource
     */
    private $rsaPublicKey;

    /**
     * @var resource
     */
    private $rsaPrivateKey;

    /**
     * OAuthSignatureRsaSha1 constructor.
     *
     * @param OAuthConsumer $Consumer
     * @param OAuthToken|null $Token
     *
     * @throws \Exception
     */
    public function __construct(OAuthConsumer $Consumer, OAuthToken $Token = null)
    {
        parent::__construct($Consumer, $Token);
        $this->setSignatureMethod(OAuthSignature::SIGNATURE_METHOD_RSA_SHA1);
    }

    /**
     * Free resources
     */
    public function __destruct()
    {
        if ($this->rsaPublicKey) {
            openssl_free_key($this->rsaPublicKey);
        }
        if ($this->rsaPrivateKey) {
            openssl_free_key($this->rsaPrivateKey);
        }
    }

    //=====================================================================================
    // OAuthSignature implementation

    /**
     * @param OAuthRequest $Request
     * @param array $params
     * @return string
     * @throws \Exception
     */
    public function getSignature(OAuthRequest $Request, $params)
    {
        $url = $Request->getUrl(true, false);
        $method = $Request->getMethod();
        $baseSignature = $this->getBaseSignature($url, $params, $method);
        $privateKey = $this->getRsaPrivateKey();
        if (!$privateKey) {
            throw new \Exception('Private key is not set');
        }
        openssl_sign($baseSignature, $signature, $privateKey);

        return base64_encode($signature);
    }

    //=====================================================================================
    // OAuthSignature overrides

    /**
     * Check request signature.
     *
     * @param HttpRequest $Request
     *
     * @return bool
     *
     * @throws \Exception
     */
    public function checkRequest(HttpRequest $Request)
    {
        // Get signature from request
        $requestSignature = $Request->get('oauth_signature');
        // Create clear signature
        $url = $Request->getUrl(true, false);
        // Convert HttpRequest to OAuthRequest
        $OAuthRequest = new OAuthRequest($Request->getUrl());
        $OAuthRequest->setHeaders($Request->getHeaders());
        $OAuthRequest->setParams($Request->getParams());
        $params = $OAuthRequest->getOAuthParams();
        $method = $OAuthRequest->getMethod();
        unset($params['oauth_signature']);
        $baseSignature = $this->getBaseSignature($url, $params, $method);
        // Check signature
        $publicKey = $this->getRsaPublicKey();
        if (!$publicKey) {
            throw new \Exception('Public key is not set');
        }

        return openssl_verify($baseSignature, $requestSignature, $publicKey);
    }

    //=====================================================================================
    // Public methods

    /**
     * Public key used by server to verify request.
     *
     * @param $rsaPublicKeyFile
     *
     * @throws \Exception
     */
    public function setRsaPublicKey($rsaPublicKeyFile)
    {
        if (!file_exists($rsaPublicKeyFile)) {
            throw new \Exception("'$rsaPublicKeyFile': file not found");
        }
        $this->rsaPublicKey = openssl_pkey_get_public(file_get_contents($rsaPublicKeyFile));
    }

    /**
     * Private key used by client to sign request.
     *
     * @param $rsaPrivateKeyFile
     *
     * @throws \Exception
     */
    public function setRsaPrivateKey($rsaPrivateKeyFile)
    {
        if (!file_exists($rsaPrivateKeyFile)) {
            throw new \Exception("'$rsaPrivateKeyFile': file not found");
        }
        $this->rsaPrivateKey = openssl_pkey_get_private(file_get_contents($rsaPrivateKeyFile));
    }

    /**
     * @return resource
     */
    public function getRsaPublicKey()
    {
        return $this->rsaPublicKey;
    }

    /**
     * @return resource
     */
    public function getRsaPrivateKey()
    {
        return $this->rsaPrivateKey;
    }
}

