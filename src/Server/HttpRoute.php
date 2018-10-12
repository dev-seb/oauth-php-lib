<?php
namespace DevSeb\OAuthPhpLib\Server;

/**
 * Describes a route pattern.
 */
class HttpRoute
{
    /**
     * @var bool|string
     */
    protected $route = '';

    /**
     * @var string
     */
    private $action = '';

    /**
     * HttpRoute constructor.
     *
     * @param string $route
     * @param string $action
     */
    public function __construct($route = '', $action = 'defaultAction')
    {
        // Clean route
        if (substr($route, 0, 1) != '/') {
            $route = '/'.$route;
        }
        if (substr($route, -1) == '/') {
            $route = substr($route, 0, strlen($route) - 1);
        }
        // Init
        $this->route = $route;
        $this->action = $action;
    }

    /**
     * @return bool|string
     */
    public function getRoute()
    {
        return $this->route;
    }

    /**
     * Check if current match given route pattern.
     *
     * @param HttpRoute $Route
     *
     * @return bool
     */
    public function match($pattern)
    {
        // Same route
        if (preg_match($pattern, $this->route)) {
            return true;
        }

        return false;
    }

    /**
     * Extract params from pattern.
     *
     * @param string $pattern
     *
     * @return array
     */
    public function getParams($pattern)
    {
        $params = array();
        $matches = array();
        // Get params from route pattern
        if (preg_match($pattern, $this->route, $matches)) {
            if (count($matches) > 1) {
                for ($i = 1; $i < count($matches); ++$i) {
                    if ($i == count($matches) - 1) {
                        if (preg_match("/(\/[^\/]+\.html)/", $matches[$i])) {
                            break;
                        }
                    }
                    // Sanitize param
                    $param = $matches[$i];
                    // Remove all non alpha numeric chars (except "-" and "_")
                    $param_filtered = preg_replace("([^\w-\/]+)", '', $param);
                    $params[] = $param_filtered;
                }
            }
        }

        return $params;
    }

    /**
     * @return string
     */
    public function getAction()
    {
        return $this->action;
    }

    /**
     * @return string
     */
    public function getPattern()
    {
        $pattern = '/^';
        $pattern .= str_replace('/', "\/", $this->route);
        $pattern .= '(\/[^\/]+\.html)?$/';

        return $pattern;
    }

}

