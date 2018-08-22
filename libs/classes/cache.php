<?php
class HWLockCache {
	public $pool;
	static $instance;

	function __construct() {
		$options = array('path' => dirname(dirname(__DIR__)).'/data/cache/');
		// Create Driver with default options
		$driver = new Stash\Driver\FileSystem($options);

		// Inject the driver into a new Pool object.
		$this->pool = new Stash\Pool($driver);
	}
	static function getInstance() {
		if(!self::$instance) self::$instance = new self();
		return self::$instance;
	}
	function __call($func, $params) {
		if(method_exists($this, $func)) return call_user_func_array(array($this, $func), $params);
		if(method_exists($this->pool, $func)) {
			//return call_user_method_array($func, $this->pool, $params);
			return call_user_func_array(array($this->pool, $func), $params);
		}
	}
	function getData($name) {
		$item = $this->pool->getItem($name);
		return $item->get();
	}
	function saveData($name, $data) {
		$item = $this->pool->getItem($name);

		// Let other processes know that this one is rebuilding the data.
		$item->lock();
		// Store the expensive to generate data.
		$this->pool->save($item->set($data));
	}
	function existData($name) {
		$item = $this->pool->getItem($name);
		return !$item->isMiss();
	}
	function clearItem($name) {
		$item = $this->pool->getItem($name);
		return $item->clear();
	}
	function save_data_if_miss($name, $data) {
		$item = $this->pool->getItem($name);
		// Check to see if the data was a miss.
		if($item->isMiss())
		{
		    // Let other processes know that this one is rebuilding the data.
		    $item->lock();

		    // Run intensive code
		    //$data = ['a'=>1];

		    // Store the expensive to generate data.
		    $this->pool->save($item->set($data));
		}
	}
}