<?php

use DevSeb\OAuthPhpLib\Client\HttpSession;
use DevSeb\OAuthPhpLib\Client\OAuth1ApiClient;
use DevSeb\OAuthPhpLib\Client\OAuth2ApiClient;
use DevSeb\OAuthPhpLib\Client\HttpRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthAccessToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthConsumer;
use DevSeb\OAuthPhpLib\OAuth\OAuthRefreshToken;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthRequestToken;

require_once '../../vendor/autoload.php';

define('API_URL_1', 'http://oauth1-server.local/');
define('API_URL_2', 'http://oauth2-server.local/');

define('AUTHENTICATE_CALLBACK_1', 'http://'.$_SERVER['HTTP_HOST'].'?a=authenticateCallback1-3&v=1');
define('AUTHENTICATE_CALLBACK_2', 'http://'.$_SERVER['HTTP_HOST'].'?a=authenticateCallback2-3&v=2');

define('API_CONSUMER_KEY',      'myconsumerkey');
define('API_CONSUMER_SECRET',   'myconsumersecret');
define('USER_USERNAME',         'myusername');
define('USER_PASSWORD',         'mypassword');

$action = isset($_GET['a']) ? $_GET['a'] : '';
$version = isset($_GET['v']) ? $_GET['v'] : '';
$method = isset($_GET['m']) ? $_GET['m'] : 'test';

$cookiesPath = dirname(__DIR__).'/var/cookies/';
$sessionsPath = dirname(__DIR__).'/var/sessions/';

// Start session
$Session = new HttpSession();
$Session->setPath($sessionsPath);
$Session->start();

// Reset session
if ($action == 'reset') {
    foreach(glob($cookiesPath.'/*') as $cookiePath) {
        unlink($cookiePath);
    }
    foreach(glob($sessionsPath.'/*') as $sessionPath) {
        unlink($sessionPath);
    }
    $Session->clear();
    $Session->newID();
    header('Location: /');
}

// Get Consumer
$Consumer = new OAuthConsumer(API_CONSUMER_KEY, API_CONSUMER_SECRET);

$Client = null;

// Get Api Client
if ($version == 1) {
    try {
        $Client = new OAuth1ApiClient(API_URL_1, $Consumer);
        $Client->setCookiePath($cookiesPath.'/cookie-1.txt');
    } catch (Exception $e) {
        echo $e->getTraceAsString()."<br />";
    }
} elseif ($version == 2) {
    try {
        $Client = new OAuth2ApiClient(API_URL_2, $Consumer);
        $Client->setCookiePath($cookiesPath.'/cookie-2.txt');
    } catch (Exception $e) {
        echo $e->getTraceAsString()."<br />";
    }
}

$extraParams = array();
if($Client != null) {
    // Create cookie
    $url = $version == 1 ? API_URL_1 : API_URL_2;
    $Request = new OAuthRequest($url.'test');
    $Response = $Client->getOAuthResponse($Request);
    // Get Http Client session ID
    $cookiePath = $Client->getCookiePath();
    if (file_exists($cookiePath)) {
        $content = file_get_contents($cookiePath);
        if (preg_match('/PHPSESSID\s+(.*)/', $content, $matches)) {
            $session_id = trim($matches[1]);
            $extraParams = array('PHPSESSID' => $session_id);
        }
    }
}

function showApiTest($a, $v, $t)
{
    ?>
    <a href="?a=<?=$a?>&v=<?=$v?>&tab=<?=$t?>&m=test">test/</a><br />
    <?php
}

?>
<html>
<head>
    <title></title>
    <style>
        .tabs {
            list-style: none;
            padding: 5px;
            margin: 0;
        }
        .tab {
            cursor: pointer;
            display: inline;
            border: 1px solid black;
            padding: 5px 10px;
        }
        .tab.active {
            border-width: 1px 1px 0 1px;
        }
        .content {
            display: none;
        }
    </style>
</head>
<body>
<div>

    <ul class="tabs">
        <li class="tab active" id="oauth_1-2_tab" onclick="showTab('oauth_1-2')">1.0a: 2-legged</li>
        <li class="tab" id="oauth_1-3_tab" onclick="showTab('oauth_1-3')">1.0a: 3-legged</li>
        <li class="tab" id="oauth_2-2_tab" onclick="showTab('oauth_2-2')">2.0: 2-legged</li>
        <li class="tab" id="oauth_2-3_tab" onclick="showTab('oauth_2-3')">2.0: 3-legged</li>
    </ul>

    <br />
    <a href="?a=reset">reset</a>

    <p>Consumer Key : <?=API_CONSUMER_KEY?></p>

    <div class="content" id="oauth_1-2">

        <h2>2-legged OAuth 1.0a :</h2>

        <h3>Request Token</h3>
        <?php
        if ($action == 'getRequestToken1-2' && $version == 1) {
            // Get AccessToken
            try {
                $RequestToken = $Client->getRequestToken();
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            if ($RequestToken && $RequestToken->getKey() != '') {
                $Session->set('request_token_key_1-2', $RequestToken->getKey());
                $Session->set('request_token_secret_1-2', $RequestToken->getSecret());
                header('Location: /?tab=oauth_1-2');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $tokenKey = $Session->get('request_token_key_1-2');
        $tokenSecret = $Session->get('request_token_secret_1-2');
        echo "token: $tokenKey<br />\n";
        echo "secret: $tokenSecret<br />\n";
        ?>
        <br /><a href="?a=getRequestToken1-2&v=1&tab=oauth_1-2">new request token</a>

        <h3>Access Token</h3>
        <?php
        if ($action == 'getAccessToken1-2' && $version == 1) {
            // Build RequestToken
            try {
                $RequestToken = new OAuthRequestToken(
                    $Session->get('request_token_key_1-2'),
                    $Session->get('request_token_secret_1-2')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            // Get Access Token
            try {
                $AccessToken = $Client->getAccessToken($RequestToken);
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            if ($AccessToken && $AccessToken->getKey() != '') {
                $Session->set('access_token_key_1-2', $AccessToken->getKey());
                $Session->set('access_token_secret_1-2', $AccessToken->getSecret());
                header('Location: /?tab=oauth_1-2');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $tokenKey = $Session->get('access_token_key_1-2');
        $tokenSecret = $Session->get('access_token_secret_1-2');
        echo "token: $tokenKey<br />\n";
        echo "secret: $tokenSecret<br />\n";
        if ($Session->containsKey('request_token_key_1-2')) {
            ?><br /><a href="?a=getAccessToken1-2&v=1&tab=oauth_1-2">new access token</a><?php
        }
        ?>

        <h3>API response</h3>
        <?php
        $request = '';
        $request_json = '';
        $response = '';
        if ($action == 'getApiResponse1-2' && $version == 1) {
            try {
                $AccessToken = new OAuthAccessToken(
                    $Session->get('access_token_key_1-2'),
                    $Session->get('access_token_secret_1-2')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            $Request = new OAuthRequest(API_URL_1.$method);
            if(isset($_GET['json'])) {
                $Request->setBody($_GET['json']);
                $request_json = "\n\n".json_encode(json_decode($_GET['json']), JSON_PRETTY_PRINT);
            }
            $Response = $Client->getOAuthResponse($Request, $AccessToken);
            $request = $Request->getUrl().$request_json;
            if ($Request->isOk() && $Response->isOk() && !$Client->isError()) {
                $response = $Response->getBody();
                $response = json_encode(json_decode($response), JSON_PRETTY_PRINT);
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                $response = 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        if ($Session->containsKey('access_token_key_1-2')) {
            showApiTest('getApiResponse1-2', '1', 'oauth_1-2');
        }
        echo "<br /><br />\n";
        echo "request:<pre><code>$request</code></pre><br />\n";
        echo "response:<pre><code>$response</code></pre><br />\n";
        ?>

    </div>

    <div class="content" id="oauth_1-3">

        <h2>3-legged OAuth 1.0a :</h2>

        <h3>Request Token</h3>
        <?php
        if ($action == 'getRequestToken1-3' && $version == 1) {
            // Get AccessToken
            try {
                $RequestToken = $Client->getRequestToken(AUTHENTICATE_CALLBACK_1 . '&v=1');
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            if ($RequestToken && $RequestToken->getKey() != '') {
                $Session->set('request_token_key_1-3', $RequestToken->getKey());
                $Session->set('request_token_secret_1-3', $RequestToken->getSecret());
                header('Location: /?tab=oauth_1-3');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $tokenKey = $Session->get('request_token_key_1-3');
        $tokenSecret = $Session->get('request_token_secret_1-3');
        echo "token: $tokenKey<br />\n";
        echo "secret: $tokenSecret<br />\n";
        ?>
        <br /><a href="?a=getRequestToken1-3&v=1&tab=oauth_1-3">new request token</a>

        <h3>Authentication</h3>
        <?php
        if ($action == 'authenticate1-3' && $version == 1) {
            // Build RequestToken
            try {
                $RequestToken = new OAuthRequestToken(
                    $Session->get('request_token_key_1-3'),
                    $Session->get('request_token_secret_1-3')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            $Client->authenticate($RequestToken, $extraParams); // => redirect
        } elseif ($action == 'authenticateCallback1-3' && $version == 1) {
            $Request = HttpRequest::getCurrentRequest();
            if ($Request->containsKey('oauth_verifier')) {
                $Session->set('request_token_verifier_1-3', $Request->get('oauth_verifier'));
                header('Location: /?tab=oauth_1-3');
            }
        }
        $tokenVerifier = $Session->get('request_token_verifier_1-3');
        echo "verifier: $tokenVerifier<br />\n";
        if ($Session->containsKey('request_token_key_1-3')) {
            ?><br/><a href="?a=authenticate1-3&v=1&tab=oauth_1-3&PHPSESSID=<?=$session_id?>">authenticate</a><?php
        }
        ?>

        <h3>Access Token</h3>
        <?php
        if ($action == 'getAccessToken1-3' && $version == 1) {
            // Build RequestToken
            try {
                $RequestToken = new OAuthRequestToken(
                    $Session->get('request_token_key_1-3'),
                    $Session->get('request_token_secret_1-3')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            $RequestToken->setVerifier($Session->get('request_token_verifier_1-3'));
            // Get Access Token
            try {
                $AccessToken = $Client->getAccessToken($RequestToken);
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            if ($AccessToken && $AccessToken->getKey() != '') {
                $Session->set('access_token_key_1-3', $AccessToken->getKey());
                $Session->set('access_token_secret_1-3', $AccessToken->getSecret());
                header('Location: /?tab=oauth_1-3');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $tokenKey = $Session->get('access_token_key_1-3');
        $tokenSecret = $Session->get('access_token_secret_1-3');
        echo "token: $tokenKey<br />\n";
        echo "secret: $tokenSecret<br />\n";
        if ($Session->containsKey('request_token_key_1-3')) {
            ?><br /><a href="?a=getAccessToken1-3&v=1&tab=oauth_1-3">new access token</a><?php
        }
        ?>

        <h3>API response</h3>
        <?php
        $request = '';
        $request_json = '';
        $response = '';
        if ($action == 'getApiResponse1-3' && $version == 1) {
            try {
                $AccessToken = new OAuthAccessToken(
                    $Session->get('access_token_key_1-3'),
                    $Session->get('access_token_secret_1-3')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            $Request = new OAuthRequest(API_URL_1.$method);
            if(isset($_GET['json'])) {
                $Request->setBody($_GET['json']);
                $request_json = "\n\n".json_encode(json_decode($_GET['json']), JSON_PRETTY_PRINT);
            }
            $Response = $Client->getOAuthResponse($Request, $AccessToken);
            $request = $Request->getUrl().$request_json;
            if ($Request->isOk() && $Response->isOk() && !$Client->isError()) {
                $response = $Response->getBody();
                $response = json_encode(json_decode($response), JSON_PRETTY_PRINT);
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                $response = 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        if ($Session->containsKey('access_token_key_1-3')) {
            showApiTest('getApiResponse1-3', '1', 'oauth_1-3');
        }
        echo "<br /><br />\n";
        echo "request:<pre><code>$request</code></pre><br />\n";
        echo "response:<pre><code>$response</code></pre><br />\n";
        ?>

    </div>

    <div class="content" id="oauth_2-2">

        <h2>2-legged OAuth 2.0 :</h2>

        <h3>Access Token</h3>
        <?php
        if ($action == 'getAccessToken2-2' && $version == 2) {
            // Build RequestToken
            try {
                $RequestToken = new OAuthRequestToken(
                    $Session->get('request_token_key_2-2'),
                    $Session->get('request_token_secret_2-2')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            // Get Access Token depending on grant type
            $AccessToken = null;
            $Request = HttpRequest::getCurrentRequest();
            $grant_type = $Request->get('grant_type');
            if ($grant_type == 'client_credentials') {
                try {
                    $AccessToken = $Client->getAccessTokenFromClientCredentials();
                } catch (Exception $e) {
                    echo $e->getTraceAsString()."<br />";
                }
            } elseif ($grant_type == 'password') {
                try {
                    $AccessToken = $Client->getAccessTokenFromPassword(USER_USERNAME, USER_PASSWORD);
                } catch (Exception $e) {
                    echo $e->getTraceAsString()."<br />";
                }
            }
            if ($AccessToken && $AccessToken->getKey() != '') {
                $Session->set('access_token_key_2-2', $AccessToken->getKey());
                header('Location: /?tab=oauth_2-2');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $tokenKey = $Session->get('access_token_key_2-2');
        echo "token: $tokenKey<br />\n";
        ?><br /><a href="?a=getAccessToken2-2&v=2&grant_type=client_credentials&tab=oauth_2-2">new access token (client_credentials)</a><?php
        ?><br /><a href="?a=getAccessToken2-2&v=2&grant_type=password&tab=oauth_2-2">new access token (password)</a><?php
        ?>

        <h3>API response</h3>
        <?php
        $request = '';
        $request_json = '';
        $response = '';
        if ($action == 'getApiResponse2-2' && $version == 2) {
            try {
                $AccessToken = new OAuthAccessToken(
                    $Session->get('access_token_key_2-2')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            $Request = new OAuthRequest(API_URL_2.$method);
            if(isset($_GET['json'])) {
                $Request->setBody($_GET['json']);
                $request_json = "\n\n".json_encode(json_decode($_GET['json']), JSON_PRETTY_PRINT);
            }
            $Response = $Client->getOAuthResponse($Request, $AccessToken);
            $request = $Request->getUrl().$request_json;
            if ($Request->isOk() && $Response->isOk() && !$Client->isError()) {
                $response = $Response->getBody();
                $response = json_encode(json_decode($response), JSON_PRETTY_PRINT);
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                $response = 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        if ($Session->containsKey('access_token_key_2-2')) {
            showApiTest('getApiResponse2-2', '2', 'oauth_2-2');
        }
        echo "<br /><br />\n";
        echo "request:<pre><code>$request</code></pre><br />\n";
        echo "response:<pre><code>$response</code></pre><br />\n";
        ?>

    </div>

    <div class="content" id="oauth_2-3">

        <h2>3-legged OAuth 2.0 :</h2>

        <h3>Authentication</h3>
        <?php
        if ($action == 'authenticate2-3' && $version == 2) {
            $Client->authenticate(AUTHENTICATE_CALLBACK_2, 'scope', 'state', $extraParams); // => redirect
        } elseif ($action == 'authenticateCallback2-3' && $version == 2) {
            $Request = HttpRequest::getCurrentRequest();
            if ($Request->containsKey('code')) {
                $Session->set('request_token_key_2-3', $Request->get('code'));
                header('Location: /?tab=oauth_2-3');
            }
        }
        $tokenKey = $Session->get('request_token_key_2-3');
        echo "code: $tokenKey<br />\n";
        ?><br/><a href="?a=authenticate2-3&v=2&tab=oauth_2-3">authenticate</a><?php
        ?>

        <h3>Access Token</h3>
        <?php
        if ($action == 'getAccessToken2-3' && $version == 2) {
            // Build RequestToken
            try {
                $RequestToken = new OAuthRequestToken(
                    $Session->get('request_token_key_2-3')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            // Get Access Token
            try {
                /** @var $AccessToken OAuthAccessToken */
                /** @var $RefreshToken OAuthRefreshToken */
                list($AccessToken, $RefreshToken) = $Client->getAccessTokenFromAuthorizationCode($RequestToken);
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            if ($AccessToken && $AccessToken->getKey() != '') {
                $Session->set('access_token_key_2-3', $AccessToken->getKey());
                $Session->set('refresh_token_key_2-3', $RefreshToken->getKey());
                header('Location: /?tab=oauth_2-3');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $accessTokenKey = $Session->get('access_token_key_2-3');
        echo "access token: $accessTokenKey<br />\n";
        if ($Session->containsKey('request_token_key_2-3')) {
            ?><br /><a href="?a=getAccessToken2-3&v=2&tab=oauth_2-3">new access token (from request token)</a><?php
        }
        ?>

        <h3>Refresh Token</h3>
        <?php
        if ($action == 'getNewAccessToken2-3' && $version == 2) {
            // Build RequestToken
            try {
                $RefreshToken = new OAuthRefreshToken(
                    $Session->get('refresh_token_key_2-3')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            try {
                list($AccessToken, $RefreshToken) = $Client->getAccessTokenFromRefreshToken($RefreshToken);
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            if ($AccessToken && $AccessToken->getKey() != '') {
                $Session->set('access_token_key_2-3', $AccessToken->getKey());
                $Session->set('refresh_token_key_2-3', $RefreshToken->getKey());
                header('Location: /?tab=oauth_2-3');
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                echo 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        $refreshTokenKey = $Session->get('refresh_token_key_2-3');
        echo "refresh token: $refreshTokenKey<br />\n";
        if ($Session->containsKey('refresh_token_key_2-3')) {
            ?><br /><a href="?a=getNewAccessToken2-3&v=2&tab=oauth_2-3">new access token (from refresh token)</a><?php
        }
        ?>

        <h3>API response</h3>
        <?php
        $request = '';
        $request_json = '';
        $response = '';
        if ($action == 'getApiResponse2-3' && $version == 2) {
            try {
                $AccessToken = new OAuthAccessToken(
                    $Session->get('access_token_key_2-3')
                );
            } catch (Exception $e) {
                echo $e->getTraceAsString()."<br />";
            }
            $Request = new OAuthRequest(API_URL_2.$method);
            if(isset($_GET['json'])) {
                $Request->setBody($_GET['json']);
                $request_json = "\n\n".json_encode(json_decode($_GET['json']), JSON_PRETTY_PRINT);
            }
            $Response = $Client->getOAuthResponse($Request, $AccessToken);
            $request = $Request->getUrl().$request_json;
            if ($Request->isOk() && $Response->isOk() && !$Client->isError()) {
                $response = $Response->getBody();
                $response = json_encode(json_decode($response), JSON_PRETTY_PRINT);
            } elseif ($Client->isError()) {
                $Error = $Client->getOAuthError();
                $response = 'Error: '.$Error->getError()." (".$Error->getErrorDescription().")<br />\n";
            }
        }
        if ($Session->containsKey('access_token_key_2-3')) {
            showApiTest('getApiResponse2-3', '2', 'oauth_2-3');
        }
        echo "<br /><br />\n";
        echo "request:<pre><code>$request</code></pre><br />\n";
        echo "response:<pre><code>$response</code></pre><br />\n";
        ?>

    </div>

</div>

<script>
    function showTab(tab) {
        // Get tab contents
        var oauth_1_2 = document.getElementById('oauth_1-2');
        var oauth_1_3 = document.getElementById('oauth_1-3');
        var oauth_2_2 = document.getElementById('oauth_2-2');
        var oauth_2_3 = document.getElementById('oauth_2-3');
        // Hide tabs
        oauth_1_2.style.display = 'none';
        oauth_1_3.style.display = 'none';
        oauth_2_2.style.display = 'none';
        oauth_2_3.style.display = 'none';
        // Tabs
        var oauth_1_2_tab = document.getElementById('oauth_1-2_tab');
        var oauth_1_3_tab = document.getElementById('oauth_1-3_tab');
        var oauth_2_2_tab = document.getElementById('oauth_2-2_tab');
        var oauth_2_3_tab = document.getElementById('oauth_2-3_tab');
        // Reset tabs
        oauth_1_2_tab.className = "tab";
        oauth_1_3_tab.className = "tab";
        oauth_2_2_tab.className = "tab";
        oauth_2_3_tab.className = "tab";
        // Show current tab
        var currentContent = document.getElementById(tab);
        currentContent.style.display = 'block';
        var currentTab = document.getElementById(tab+'_tab');
        currentTab.className = "tab active";
    }
    showTab('<?php echo isset($_GET['tab']) ? $_GET['tab'] : 'oauth_1-2'; ?>');
</script>
</body>
</html>