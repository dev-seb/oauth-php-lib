<?php
namespace DevSeb\OAuthPhpLib\Server;

class HttpResponse
{
    const HTTP_CODE_OK = 200;
    const HTTP_CODE_UNAUTHORIZED = 401;
    const HTTP_CODE_FORBIDDEN = 403;
    const HTTP_CODE_NOT_FOUND = 404;
    const HTTP_CODE_REQUEST_TIMEOUT = 408;
    const HTTP_CODE_INTERNAL_ERROR = 500;

    /**
     * @var int
     */
    protected $code;

    /**
     * @var array
     */
    protected $headers;

    /**
     * @var string
     */
    protected $head;

    /**
     * @var string
     */
    protected $body;

    /**
     * @var int
     */
    protected $time;

    public function __construct()
    {
        $this->code = self::HTTP_CODE_OK;
        $this->headers = array();
        $this->head = '';
        $this->body = '';
        $this->time = 0;
    }

    /**
     * @return bool
     */
    public function isOk()
    {
        return $this->code == self::HTTP_CODE_OK;
    }

    //=====================================================================
    // Getter / Setter

    /**
     * @return array
     */
    public function getHeaders()
    {
        return $this->headers;
    }

    /**
     * Parse raw headers.
     *
     * @param $headersRaw
     */
    public function parseHeaders($headersRaw)
    {
        $this->setHeadersRaw($headersRaw);
        $headers = array();
        foreach (explode("\r\n", $headersRaw) as $i => $line) {
            $i = strpos($line, ':');
            if (!empty($i)) {
                list($key, $value) = explode(': ', $line);
                $key = str_replace('-', '_', strtolower($key));
                $headers[$key] = trim($value);
            }
        }
        $this->setHeaders($headers);
    }

    /**
     * Set headers from array.
     *
     * @param array $headers
     */
    public function setHeaders($headers)
    {
        if (!empty($headres)) {
            foreach ($headers as $name => $value) {
                $this->setHeader($name, $value);
            }
        }
    }

    /**
     * Set header name and value.
     *
     * @param string $name
     * @param string $value
     */
    public function setHeader($name, $value)
    {
        $this->headers[$name] = $value;
    }

    /**
     * Return header value from name.
     *
     * @param string $name
     * @return mixed|string
     */
    public function getHeader($name)
    {
        if (isset($this->headers[$name])) {
            return $this->headers[$name];
        }

        return '';
    }

    /**
     * Set raw headers.
     *
     * @param string $head
     */
    public function setHeadersRaw($head)
    {
        $this->head = $head;
    }

    /**
     * Return raw headers.
     *
     * @return string
     */
    public function getHeadersRaw()
    {
        return $this->head;
    }

    /**
     * Set response body.
     *
     * @param string $body
     */
    public function setBody($body)
    {
        $this->body = $body;
    }

    /**
     * Append response body.
     *
     * @param string $body
     */
    public function appendBody($body)
    {
        $this->body .= $body;
    }

    /**
     * Return response body.
     *
     * @return string
     */
    public function getBody()
    {
        return $this->body;
    }

    /**
     * Set HTTP return code.
     *
     * @param int $code
     */
    public function setCode($code)
    {
        $this->code = $code;
    }

    /**
     * Return response HTTP Code.
     *
     * @return int
     */
    public function getCode()
    {
        return $this->code;
    }

    /**
     * Set response time in seconds.
     *
     * @param float $time
     */
    public function setTime($time)
    {
        $this->time = $time;
    }

    /**
     * Return response time in seconds.
     *
     * @return float
     */
    public function getTime()
    {
        return $this->time;
    }

    //=====================================================================
    // Public methods

    /**
     * Perform HTTP Redirect.
     *
     * @param string $path
     */
    public function redirect($path)
    {
        header("Location: $path");
        exit();
    }

    /**
     * Return true if header have
     * been sent already.
     *
     * @return bool
     */
    public function headersSent()
    {
        return headers_sent();
    }

    /**
     * Show response header according
     * to HTTP response code.
     *
     * @param int $code
     */
    public function showResponseHeader($code = null)
    {
        if ($code) {
            $this->code = $code;
        }
        if (PHP_VERSION_ID > 54000) {
            http_response_code($this->code);
        } else {
            switch ($this->code) {
                case self::HTTP_CODE_NOT_FOUND:
                    header('HTTP/1.1 404 Not Found');
                    break;
                case self::HTTP_CODE_FORBIDDEN:
                    header('HTTP/1.1 403 Forbidden');
                    break;
                case self::HTTP_CODE_INTERNAL_ERROR:
                    header('HTTP/1.1 500 Internal Server Error');
                    break;
                default:
                    header('HTTP/1.1 ' . $this->code);
            }
        }
    }

    /**
     * Show response header.
     */
    public function sendHeaders()
    {
        // Check if headers has been sent
        if ($this->headersSent()) {
            return;
        }
        // Show response first header
        if ($this->code != self::HTTP_CODE_OK) {
            $this->showResponseHeader();
        }
        // Show headers
        if (!empty($this->headers)) {
            foreach ($this->headers as $name => $value) {
                header("$name: $value");
            }
        }
    }

    /**
     * Send response body.
     */
    public function sendBody()
    {
        echo $this->body;
        flush();
        $this->body = '';
    }

    /**
     * Send response header and body.
     */
    public function send()
    {
        $this->sendHeaders();
        $this->sendBody();
    }

}