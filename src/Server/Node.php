<?php
namespace DevSeb\OAuthPhpLib\Server;

class Node
{
    /**
     * @var array
     */
    private $node = array();

    /**
     * @var string
     */
    private $name = '';

    /**
     * Node constructor.
     * @param $name
     */
    public function __construct($name)
    {
        $this->node = array();
        $this->name = $name;
    }

    /**
     * @param $name
     * @param $value
     */
    public function setNode($name, $value)
    {
        $this->node[$name] = $value;
    }

    /**
     * @param Node $node
     */
    public function addNode(Node $node)
    {
        $this->node[$node->getName()] = $node->getNode();
    }

    /**
     * @return string
     */
    public function getName()
    {
        return $this->name;
    }

    /**
     * @return array
     */
    public function getNode()
    {
        return $this->node;
    }
}