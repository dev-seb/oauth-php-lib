<?php
namespace DevSeb\OAuthPhpLib\Server;

use DevSeb\OAuthPhpLib\Client\HttpRequest;

/**
 * Class HttpServer
 */
class HttpServer
{
    const OUTPUT_FORMAT_JSON = 'json';

    protected $format = self::OUTPUT_FORMAT_JSON;

    /**
     * @var HttpRequest
     */
    protected $Request;

    /**
     * @var HttpResponse
     */
    protected $Response;

    /**
     * @var ResponseNode
     */
    protected $ResponseNode;

    /**
     * @var array
     */
    private $routes = array();

    public function __construct(HttpRequest $Request)
    {
        $this->Request = $Request;
        $this->Response = new HttpResponse();
        $this->ResponseNode = new ResponseNode();
    }

    /**
     * Set output format
     *
     * @param $format
     */
    public function setFormat($format)
    {
        if(in_array($format, array(
            HttpServer::OUTPUT_FORMAT_JSON
        ))) {
            $this->format = $format;
        }
    }

    /**
     * Render request
     */
    public function render()
    {
        $path = $this->Request->getPath();
        $CurrentRoute = new HttpRoute($path);
        // Parse path
        $action = '';
        $params = array();
        $routes = $this->getRoutes();
        if (!empty($routes)) {
            foreach ($routes as $Route) {
                if ($CurrentRoute->match($Route->getPattern())) {
                    // The route match current route path
                    $action = $Route->getAction();
                    $params = $CurrentRoute->getParams($Route->getPattern());
                    break;
                }
            }
        }
        // Dispatch
        if(!$action) {
            $this->Response->setCode(HttpResponse::HTTP_CODE_NOT_FOUND);
            $this->showResponse();
        }
        if (!method_exists($this, $action)) {
            $this->Response->setCode(HttpResponse::HTTP_CODE_NOT_FOUND);
            $this->showResponse();
        }
        call_user_func_array(
            array($this, $action), $params
        );
    }

    /**
     * Show Response
     */
    public function showResponse()
    {
        header('Content-Type: application/json; charset=UTF-8');
        $response = json_encode($this->ResponseNode->getNode(), JSON_PRETTY_PRINT);
        $this->Response->setBody($response);
        $this->Response->sendHeaders();
        $this->Response->sendBody();
        exit();
    }

    /**
     * @return array
     */
    protected function getRoutes()
    {
        return $this->routes;
    }

    /**
     * @param HttpRoute $route
     */
    protected function addRoute(HttpRoute $route)
    {
        $this->routes[] = $route;
    }

    /**
     * @param $routes
     */
    protected function addRoutes($routes)
    {
        if (!empty($routes)) {
            foreach ($routes as $route) {
                $this->addRoute($route);
            }
        }
    }

}