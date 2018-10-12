<?php

use DevSeb\OAuthPhpLib\Examples\MyOAuth1ApiServer;
use DevSeb\OAuthPhpLib\Client\HttpRequest;
use DevSeb\OAuthPhpLib\OAuth\OAuthException;

require_once '../../vendor/autoload.php';

define('API_CONSUMER_KEY',      'myconsumerkey');
define('API_CONSUMER_SECRET',   'myconsumersecret');
define('USER_USERNAME',         'myusername');
define('USER_PASSWORD',         'mypassword');


try {
    $OAuthApiServer = new MyOAuth1ApiServer(HttpRequest::getCurrentRequest());
    $OAuthApiServer->render();
} catch (Exception $e) {
    echo $e->getMessage()."<br />\n";
    echo nl2br($e->getTraceAsString());
}
