<?php
namespace DevSeb\OAuthPhpLib\Client;
use DevSeb\OAuthPhpLib\Server\HttpRoute;

/**
 * Class HttpRequest
 */
class HttpRequest implements Map
{
    const METHOD_GET = 'GET';
    const METHOD_POST = 'POST';
    const METHOD_DELETE = 'DELETE';

    const STATUS_OK = 'OK';
    const STATUS_ERROR = 'Error';
    const STATUS_TIMEOUT = 'Timeout';

    protected $status;
    /**
     * HTTP Method.
     *
     * @var string
     */
    protected $method;
    /**
     * Full URL.
     *
     * @var string
     */
    protected $url;
    /**
     * Http sheme.
     *
     * @var string
     */
    protected $scheme;
    /**
     * Host.
     *
     * @var string
     */
    protected $host;
    /**
     * Port number.
     *
     * @var int
     */
    protected $port;
    /**
     * Uri.
     *
     * @var string
     */
    protected $uri;
    /**
     * Current route.
     *
     * @var string
     */
    protected $path;
    /**
     * Merge GET and POST params.
     *
     * @var array
     */
    protected $params;

    /**
     * Cache for HTTP headers.
     *
     * @var array
     */
    protected $headers;
    /**
     * Post body.
     *
     * @var string
     */
    protected $body;

    /**
     * If enabled, escape quotes.
     *
     * @var bool
     */
    private $escapeQuotes = false;

    /**
     * Constructor.
     * @param string $url
     */
    public function __construct($url = '')
    {
        $this->method = self::METHOD_GET;
        $this->status = self::STATUS_OK;
        $this->url = '';
        $this->scheme = 'http';
        $this->host = '';
        $this->port = '80';
        $this->uri = '';
        $this->path = '';
        $this->params = array();
        $this->headers = array();
        $this->body = '';
        if ($url != '') {
            $this->setUrl($url);
        }
    }

    /**
     * @return bool
     */
    public function isOk()
    {
        return $this->status == self::STATUS_OK;
    }

    /**
     * Return current Http Request from Http Server
     *
     * @return HttpRequest
     */
    public static function getCurrentRequest()
    {
        $Request = new HttpRequest();

        // Scheme
        $scheme = 'http';
        if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] == 'on') {
            $scheme .= 's';
        }
        $Request->setScheme($scheme);

        // Url
        $url = $scheme.'://';
        $url .= $_SERVER['HTTP_HOST'];
        if ($_SERVER['SERVER_PORT'] != '80') {
            $url .= ':' . $_SERVER['SERVER_PORT'];
        }
        $url .= $_SERVER['REQUEST_URI'];
        $Request->setUrl($url);

        // Params
        $Request->setParams(array_merge($_POST, $_GET));

        // Method
        if (isset($_SERVER['REQUEST_METHOD'])) {
            $Request->setMethod($_SERVER['REQUEST_METHOD']);
        }

        // Headers
        $headers = array();
        if (function_exists('apache_request_headers')) {
            $headers = apache_request_headers();
        } else {
            foreach ($_SERVER as $key => $value) {
                if (substr($key, 0, 5) == 'HTTP_') {
                    $key = str_replace(' ', '-', ucwords(str_replace('_', ' ', strtolower(substr($key, 5)))));
                    $headers[$key] = $value;
                }
            }
        }
        $Request->setHeaders($headers);

        // Return Request
        return $Request;
    }

    //=====================================================================
    // Getter / Setter

    /**
     * Escape single quote in parameters.
     *
     * @param bool $escapeQuotes
     */
    public function setEscapeQuotes($escapeQuotes)
    {
        $this->escapeQuotes = $escapeQuotes;
    }

    /**
     * Set cur.
     *
     * @param string $status
     */
    public function setStatus($status)
    {
        if (in_array($status, array(
            self::STATUS_OK,
            self::STATUS_ERROR,
            self::STATUS_TIMEOUT,
        ))) {
            $this->status = $status;
        }
    }

    public function getStatus()
    {
        return $this->status;
    }

    /**
     * Set HTTP Method.
     *
     * @param string $method GET|POST
     */
    public function setMethod($method)
    {
        if (in_array($method, array(
            self::METHOD_GET,
            self::METHOD_POST,
            self::METHOD_DELETE,
        ))) {
            $this->method = $method;
        }
    }

    /**
     * Return current HTTP Method.
     *
     * @return string
     */
    public function getMethod()
    {
        return $this->method;
    }

    /**
     * @return bool
     */
    public function isGet()
    {
        return $this->method == self::METHOD_GET;
    }

    /**
     * @return bool
     */
    public function isPost()
    {
        return $this->method == self::METHOD_POST;
    }

    /**
     * Set request full url and parse data.
     *
     * @param string $url
     */
    public function setUrl($url)
    {
        $this->url = $url;
        $infos = parse_url($this->url);
        $this->scheme = strtolower($infos['scheme']);
        if (isset($infos['port'])) {
            $this->port = $infos['port'];
        }
        $this->host = $infos['host'];
        // Remove trailing port if set
        if (preg_match('/([^:]+):.*/', $this->host, $matches)) {
            $this->host = $matches[1];
        }
        $this->uri = '/';
        if (isset($infos['path'])) {
            $this->uri = $infos['path'];
        }
        if (isset($infos['query'])) {
            parse_str($infos["query"], $this->params);
        }
    }

    /**
     * Return url.
     *
     * @param bool $with_path
     * @param bool $with_params
     * @return string
     */
    public function getUrl($with_path = true, $with_params = true)
    {
        $infos = parse_url($this->url);
        $url = $infos['scheme'] . '://' . $infos['host'];
        if (isset($infos['port'])) {
            if ($infos['port'] != '80') {
                $url .= ':' . $infos['port'];
            }
        }
        if ($with_path) {
            $url .= (isset($infos['path'])) ? $infos['path'] : '/';
            if ($with_params && !empty($this->params) && $this->isGet()) {
                $url .= '?' . http_build_query($this->params);
            }
        }

        return $url;
    }

    /**
     * Return only the base url,
     * without path and params.
     *
     * @return string
     */
    public function getBaseUrl()
    {
        return $this->getUrl(false, false);
    }

    /**
     * Set current scheme.
     *
     * @param string $scheme http|https
     */
    public function setScheme($scheme)
    {
        $this->scheme = $scheme;
    }

    /**
     * Return scheme.
     *
     * @return string http|https
     */
    public function getScheme()
    {
        return $this->scheme;
    }

    /**
     * Set host.
     *
     * @param string $host
     */
    public function setHost($host)
    {
        $this->host = $host;
    }

    /**
     * Return host.
     *
     * @return string
     */
    public function getHost()
    {
        return $this->host;
    }

    /**
     * Set port.
     *
     * @param int $port
     */
    public function setPort($port)
    {
        $this->port = $port;
    }

    /**
     * Return port.
     *
     * @return int
     */
    public function getPort()
    {
        return $this->port;
    }

    /**
     * Set uri.
     *
     * @param string $uri
     */
    public function setUri($uri)
    {
        $this->uri = $uri;
    }

    /**
     * Returns uri.
     *
     * @return string
     */
    public function getUri()
    {
        return $this->uri;
    }

    /**
     * URI without leading or tailing "/".
     *
     * @return string
     */
    public function getPath()
    {
        return $this->getRoute();
    }

    public function getRoute()
    {
        $Route = new HttpRoute($this->uri);

        return $Route->getRoute();
    }

    /**
     * Return all parameters.
     *
     * @return array
     */
    public function getParams()
    {
        return $this->params;
    }

    /**
     * Set params from array.
     *
     * @param array $params
     */
    public function setParams($params)
    {
        if (!empty($params)) {
            foreach ($params as $key => $val) {
                $this->set($key, $val);
            }
        }
    }

    /**
     * Content to sent using POST.
     *
     * @param string $body
     */
    public function setBody($body)
    {
        $this->body = $body;
    }

    /**
     * Content to be setn using POST.
     *
     * @return string
     */
    public function getBody()
    {
        return $this->body;
    }

    /**
     * Build string from key / value pairs
     * for post or get queries.
     *
     * @return string http query
     */
    public function getHttpQuery()
    {
        return http_build_query($this->getParams());
    }

    /**
     * Retrn headers.
     *
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Set headers from array.
     *
     * @param array $headers
     */
    public function setHeaders($headers)
    {
        if (!empty($headers)) {
            foreach ($headers as $key => $val) {
                $this->setHeader($key, $val);
            }
        }
    }

    /**
     * Set single header from key value pair.
     *
     * @param string $key
     * @param string $val
     */
    public function setHeader($key, $val)
    {
        $this->headers[$key] = $val;
    }

    /**
     * Return single header value from name.
     *
     * @param string $key
     * @return mixed|string
     */
    public function getHeader($key)
    {
        if (isset($this->headers[$key])) {
            return $this->headers[$key];
        }

        return '';
    }

    /**
     * Return true if header is set.
     *
     * @param $key
     *
     * @return bool
     */
    public function hasHeader($key)
    {
        return array_key_exists($key, $this->headers);
    }

    /**
     * Return base64 decoded BasicAuth from Authorization header.
     *
     * @return string
     */
    public function getBasicAuth()
    {
        $basicAuth = '';
        $basicAuthHeader = trim($this->getHeader('Authorization'));
        if ($basicAuthHeader != '') {
            if (preg_match('/Basic (.*)/', $basicAuthHeader, $matches)) {
                $basicAuth = base64_decode($matches[1]);
            }
        }

        return $basicAuth;
    }

    /**
     * Return basic auth credentials as array.
     *
     * @return array
     */
    public function getBasicAuthCredentials()
    {
        $credentials = array('login' => '', 'password' => '');
        $basicAuth = $this->getBasicAuth();
        if ($basicAuth != '') {
            list($login, $password) = explode(':', $basicAuth);
            $credentials['login'] = $login;
            $credentials['password'] = $password;
        }

        return $credentials;
    }

    /**
     * Return true if current request
     * is using SSL (https).
     *
     * @return bool
     */
    public function isSSL()
    {
        return $this->scheme == 'https';
    }

    /**
     * Check is a list a liste of params are st.
     *
     * @return false is a less one param is not set
     */
    public function containsKeys()
    {
        $test_params = func_get_args();
        foreach ($test_params as $test_param) {
            if (!$this->containsKey($test_param)) {
                return false;
            }
        }

        return true;
    }

    //======================================================================
    // Map implementation

    /**
     * @see Map::clear()
     */
    public function clear()
    {
        $this->params = array();
    }

    /**
     * @see Map::containsKey()
     * @param $key
     * @return bool
     */
    public function containsKey($key)
    {
        return isset($this->params[$key]);
    }

    /**
     * @see Map::containsValue()
     * @param $value
     * @return bool
     */
    public function containsValue($value)
    {
        return in_array($value, array_values($this->params));
    }

    /**
     * @see Map::get()
     * @param $key
     * @param null $defaultValue
     * @return mixed|null
     */
    public function get($key, $defaultValue = null)
    {
        if ($this->containsKey($key)) {
            $param = $this->params[$key];
            if ($this->escapeQuotes) {
                $param = str_replace("'", "''", $param);
            }

            return $param;
        }

        return $defaultValue;
    }

    /**
     * @see Map::getKeys()
     */
    public function getKeys()
    {
        return array_keys($this->params);
    }

    /**
     * @see Map::getValues()
     */
    public function getValues()
    {
        return array_values($this->params);
    }

    /**
     * @see Map::isEmpty()
     */
    public function isEmpty()
    {
        return empty($this->params);
    }

    /**
     * @see Map::remove()
     * @param $key
     */
    public function remove($key)
    {
        if ($this->containsKey($key)) {
            unset($this->params[$key]);
        }
    }

    /**
     * @see Map::set()
     * @param $key
     * @param $value
     */
    public function set($key, $value)
    {
        if (!is_array($value)) {
            $value = trim(urldecode($value));
        }
        $this->params[$key] = $value;
    }

    /**
     * @see Map::size()
     */
    public function size()
    {
        return count($this->params);
    }
}