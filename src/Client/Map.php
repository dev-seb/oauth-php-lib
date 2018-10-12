<?php
namespace DevSeb\OAuthPhpLib\Client;

interface Map
{
    public function clear();

    public function containsKey($key);

    public function containsValue($value);

    public function get($key, $defaultValue = null);

    public function getKeys();

    public function getValues();

    public function isEmpty();

    public function remove($key);

    public function set($key, $value);

    public function size();
}

