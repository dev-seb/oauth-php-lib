<?php
namespace DevSeb\OAuthPhpLib\Examples;

use DevSeb\OAuthPhpLib\Client\HttpSession;
use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthRefreshToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthToken;
use DevSeb\OAuthPhpLib\Server\HttpRoute;
use DevSeb\OAuthPhpLib\Server\OAuth1ApiServer;
use DevSeb\OAuthPhpLib\Client\HttpRequest;

class MyOAuth1ApiServer extends OAuth1ApiServer
{
    /**
     * @var HttpSession
     */
    private $Session;

    public function __construct(HttpRequest $Request)
    {
        parent::__construct($Request);
        $this->setRoutes();

        // Use session as datastore
        $this->Session = new HttpSession();
        $this->Session->setPath(dirname(__DIR__).'/var/sessions/');
        if($this->Request->containsKey('PHPSESSID')) {
            $session_id = $this->Request->get('PHPSESSID');
            $this->Session->setID($session_id);
        }
        $this->Session->start();
    }

    private function setRoutes()
    {
        $this->addRoutes(array(
            new HttpRoute('/test', 'test'),
        ));
    }

    //================================================================================================
    // Interface

    public function test()
    {
        $this->ResponseNode->setNode('Success', '1');
        $this->showResponse();
    }

    // TODO: implement API methods

    //================================================================================================
    // OAuth2ApiServer implementation

    /**
     * @see OAuth1ApiServer::isNonceUsed()
     */
    protected function isNonceUsed(OAuthConsumer $Consumer, OAuthToken $Token, $nonce, $timestamp)
    {
        // TODO: Check from database

        return false;
    }

    /**
     * @see OAuth1ApiServer::getConsumer()
     */
    protected function getConsumer($consumerKey)
    {
        // TODO: Load consumer from database using consumerKey

        return new OAuthConsumer(API_CONSUMER_KEY, API_CONSUMER_SECRET);
    }

    /**
     * @see OAuth1ApiServer::getConsumerFromToken()
     */
    protected function getConsumerFromToken($tokenKey)
    {
        // TODO: Load consumer from database using tokenKey

        return new OAuthConsumer(API_CONSUMER_KEY, API_CONSUMER_SECRET);
    }

    /**
     * @see OAuth1ApiServer::getToken()
     *
     * @throws \Exception
     */
    protected function getToken(OAuthConsumer $Consumer, $tokenKey, $tokenType)
    {
        // TODO: Load token from database

        $Token = null;

        if($tokenType == OAuthToken::TYPE_REQUEST) {
            $Token = unserialize($this->Session->get('RequestToken'));
        }
        else if($tokenType == OAuthToken::TYPE_ACCESS) {
            $Token = unserialize($this->Session->get('AccessToken'));
        }

        return $Token;
    }

    /**
     * @see OAuth1ApiServer::newRequestToken()
     *
     * @throws \Exception
     */
    protected function newRequestToken(OAuthConsumer $Consumer, $redirectUri = '')
    {
        // TODO: Insert token in database

        $token = OAuthToken::getSecureToken();

        $RequestToken = new OAuthRequestToken($token['key'], $token['secret']);
        $RequestToken->setVerifier(uniqid());
        $RequestToken->setRedirectUri($redirectUri);

        $this->Session->set('RequestToken', serialize($RequestToken));

        return $RequestToken;
    }

    /**
     * @see OAuth1ApiServer::newAccessToken()
     *
     * @throws \Exception
     */
    protected function newAccessToken(OAuthConsumer $Consumer, OAuthRequestToken $RequestToken = null, OAuthRefreshToken $RefreshToken = null)
    {
        // TODO: Insert token in database

        $token = OAuthToken::getSecureToken();

        $AccessToken = new OAuthAccessToken($token['key'], $token['secret']);
        $AccessToken->setExpires(date('Y-m-d H:i:s', strtotime("+1 hour")));

        $this->Session->set('AccessToken', serialize($AccessToken));

        return $AccessToken;
    }

    /**
     * @see OAuth1ApiServer::showLoginPage()
     */
    protected function showLoginPage()
    {
        echo 'Grant access to : ' . $this->Consumer->getName() . "<br />\n"; ?>
        <form action="<?= $this->Request->getUrl(true, false) . '?' . http_build_query($_GET); ?>" method="POST">
            <input type="text" name="username" value="<?=USER_USERNAME?>" title="username"/><br/>
            <input type="password" name="password" title="password" value="<?=USER_PASSWORD?>"/><br/>
            <input type="submit" name="form_sent"/>
        </form>
        <?php
    }

    /**
     * @see OAuth1ApiServer::authenticateUser()
     */
    protected function authenticateUser(OAuthConsumer $Consumer, $username, $password)
    {
        // TODO: Check credentials from database

        return ($username == USER_USERNAME && $password == USER_PASSWORD);
    }
}