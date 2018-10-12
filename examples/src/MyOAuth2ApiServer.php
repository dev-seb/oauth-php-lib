<?php
namespace DevSeb\OAuthPhpLib\Examples;

use DevSeb\OAuthPhpLib\Client\HttpRequest;
use DevSeb\OAuthPhpLib\Client\HttpSession;
use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthRefreshToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthToken;
use DevSeb\OAuthPhpLib\Server\HttpRoute;
use DevSeb\OAuthPhpLib\Server\OAuth2ApiServer;

class MyOAuth2ApiServer extends OAuth2ApiServer
{
    /**
     * @var HttpSession
     */
    private $Session;

    public function __construct(HttpRequest $Request)
    {
        parent::__construct($Request);
        $this->setRoutes();

        // Uses session as database
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
     * @see OAuth2ApiServer::getConsumer()
     */
    protected function getConsumer($consumerKey)
    {
        // TODO: Load consumer from database using consumerKey

        return new OAuthConsumer(API_CONSUMER_KEY, API_CONSUMER_SECRET);
    }

    /**
     * @see OAuth2ApiServer::getConsumerFromToken()
     */
    protected function getConsumerFromToken($tokenKey)
    {
        // TODO: Load consumer from database using tokenKey

        return new OAuthConsumer(API_CONSUMER_KEY, API_CONSUMER_SECRET);
    }

    /**
     * @see OAuth2ApiServer::getToken()
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
        else if($tokenType == OAuthToken::TYPE_REFRESH) {
            $Token = unserialize($this->Session->get('RefreshToken'));
        }

        return $Token;
    }

    /**
     * @see OAuth2ApiServer::newRequestToken()
     *
     * @throws \Exception
     */
    protected function newRequestToken(OAuthConsumer $Consumer, $redirectUri = '')
    {
        // TODO: Insert token in database

        $token = OAuthToken::getSecureToken();

        $RequestToken = new OAuthRequestToken($token['key'], $token['secret']);

        $this->Session->set('RequestToken', serialize($RequestToken));

        return $RequestToken;
    }

    /**
     * @see OAuth2ApiServer::newAccessToken()
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
     * @see OAuth2ApiServer::newRefreshToken()
     *
     * @throws \Exception
     */
    protected function newRefreshToken(OAuthConsumer $Consumer, OAuthAccessToken $RequestToken = null)
    {
        // TODO: Insert token in database

        $token = OAuthToken::getSecureToken();

        $RefreshToken = new OAuthRefreshToken($token['key']);

        $this->Session->set('RefreshToken', serialize($RefreshToken));

        return $RefreshToken;
    }

    /**
     * @see OAuth2ApiServer::showLoginPage()
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
     * @see OAuth2ApiServer::authenticateUser()
     */
    protected function authenticateUser(OAuthConsumer $Consumer, $username, $password)
    {
        // TODO: Check credentials from database

        return ($username == USER_USERNAME && $password == USER_PASSWORD);
    }
}