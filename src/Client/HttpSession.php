<?php
namespace DevSeb\OAuthPhpLib\Client;

/**
 * Class to handle HTTP session.
 */
class HttpSession implements Map
{
    private $isStarted = false;
    private $isClosed = false;

    /**
     * Constructor.
     */
    public function __construct()
    {
    }

    /**
     * @param $name
     */
    public function setName($name)
    {
        session_name($name);
    }

    /**
     * @return bool
     */
    public function isClosed()
    {
        return $this->isClosed;
    }

    /**
     * @return bool
     */
    public function isStarted()
    {
        return $this->isStarted;
    }

    /**
     * Start new session.
     */
    public function start()
    {
        if (!$this->isStarted() || $this->isClosed) {
            //Log::trace("start session");
            $ok = session_start();
            if (!$ok) {
                session_regenerate_id(true);
                session_start();
            }
            $this->isStarted = true;
            $this->isClosed = false;
        }
    }

    /**
     * Close current session
     */
    public function close()
    {
        if (!$this->isClosed()) {
            session_write_close();
            $this->isClosed = true;
        }
    }

    /**
     * Destroy current session.
     */
    public function destroy()
    {
        if ($this->isStarted()) {
            session_destroy();
        }
    }

    public function setID($session_id)
    {
        return session_id($session_id);
    }

    /**
     * Return the session id if session is registered.
     */
    public function getID()
    {
        return session_id();
    }

    /**
     * Reg�n�rate new session id.
     */
    public function newID()
    {
        return session_regenerate_id(true);
    }

    /**
     * Path where session file are saved.
     *
     * @param string $sessions_path
     */
    public function setPath($sessions_path)
    {
        session_save_path($sessions_path);
    }

    //======================================================================
    // Map implementation

    /**
     * @see Map::clear()
     */
    public function clear()
    {
        //$_SESSION = array();
        session_unset();
    }

    /**
     * @see Map::containsKey()
     * @param $key
     * @return bool
     */
    public function containsKey($key)
    {
        return isset($_SESSION[$key]);
    }

    /**
     * @see Map::containsValue()
     * @param $value
     * @return bool
     */
    public function containsValue($value)
    {
        $values = $this->getValues();
        if (!empty($values)) {
            return isset($values[$value]);
        }

        return false;
    }

    /**
     * @see Map::get()
     * @param $key
     * @param null $defaultValue
     * @return null
     */
    public function get($key, $defaultValue = null)
    {
        if ($this->containsKey($key)) {
            return $_SESSION[$key];
        }

        return $defaultValue;
    }

    /**
     * @see Map::getKeys()
     */
    public function getKeys()
    {
        return array_keys($_SESSION);
    }

    /**
     * @see Map::getValues()
     */
    public function getValues()
    {
        return array_values($_SESSION);
    }

    /**
     * @see Map::isEmpty()
     */
    public function isEmpty()
    {
        return empty($_SESSION);
    }

    /**
     * @see Map::remove()
     * @param $key
     */
    public function remove($key)
    {
        if ($this->containsKey($key)) {
            unset($_SESSION[$key]);
        }
    }

    /**
     * @see Map::set()
     * @param $key
     * @param $value
     */
    public function set($key, $value)
    {
        $_SESSION[$key] = $value;
        if ($this->isClosed) {
            // Warning
        }
    }

    /**
     * @see Map::size()
     */
    public function size()
    {
        return count($_SESSION);
    }

    //======================================================================
}

