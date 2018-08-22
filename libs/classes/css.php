<?php
abstract class HCGS_CORE {
	function __construct(){}
}
class HCGS_CSS extends HCGS_CORE{
	protected $data=array();
	protected static $__data=array();

	function __construct() {
		$this->data= array();
	}
	public function add($alias, $code, $type='class', $args=[]) {
		if(!isset($this->data[$alias])) {
			$this->data[$alias] = array('selector'=> self::css_selector(isset($args['selector'])? $args['selector']:''),'code'=>array(),'type'=> $type);
		}
		$this->data[$alias]['code'][] = $code;
		if(count($args)) {
			if(isset($args['selector'])) unset($args['selector']);
			$this->data[$alias] = array_merge($this->data[$alias], $args);
		}
	}
	public function addMore($alias, $sufix,$code, $args=[]) {
		if(isset($this->data[$alias])) {
			$selector = $this->data[$alias]['selector']. $sufix;
			$type = $this->data[$alias]['type'];
			if(!isset($this->data[$alias.$sufix])) {
				$this->data[$alias.$sufix]= array('selector'=> $selector,'code'=>array(),'type'=> $type);
			}
			$this->data[$alias.$sufix]['code'][]= $code;
			if(count($args)) {
				if(isset($args['selector'])) unset($args['selector']);
				$this->data[$alias.$sufix] = array_merge($this->data[$alias.$sufix], $args);
			}
		}
	}
	public function getCSS($alias) {
		if(isset($this->data[$alias])) {
			return $this->data[$alias];
		}
	}
	public function getCSSCode($alias, $type='class') {
		$item = is_string($alias)? (isset($this->data[$alias])? $this->data[$alias]:''): $alias;
		if(!empty($item) && is_array($item)) {
			if(!empty($item['type'])) $type = $item['type'];
			$css=$this->prefixName($type).$item['selector']. "{\n";
			$css.=join($item['code'],"\n");
			$css.="}\n";
			return $css;
		}
	}
	function prefixName($type='class') {
		return ($type=='class')? '.': ($type=='id'? '#':'');
	}
	public function getSelector($alias) {#if($this->data){_print($this->data);die;}
		if(isset($this->data[$alias])) return $this->data[$alias]['selector'];
		else return self::css_selector($alias);
	}
	public static function css_selector($key='') {
		if($key && isset(self::$__data['css_selector_'.$key])) return self::$__data['css_selector_'.$key];
		$name= str_shuffle(hcgs_randomString(rand(3,20),'__'));
		if(is_numeric($name{0})) $name=@end(range('a', 'z')).$name;
		if($key) self::$__data['css_selector_'.$key] = $name;
		return $name;
	}
	public static function is_selector($key) {
		if($key && isset(self::$__data['css_selector_'.$key])) return true;
		return false;
	}
	public static function _set($k, $v=null) {
		if(is_string($k)) self::$__data[$k] = $v;
		if(is_array($k)) self::$__data = $k+self::$__data;
		return $v;
	}
	public static function _get($k) {
		if(isset(self::$__data[$k])) return self::$__data[$k];
	}
	public function print_css() {
		$css=['global'=>[], 'queries'=>[]];
		foreach($this->data as $alias=>$item) {
			if(!empty($item['media'])) {
				if(!isset($css['queries'][$item['media']])) $css['queries'][$item['media']]=[];
				$css['queries'][$item['media']][] = $this->getCSSCode($item);
			}
			else $css['global'][] = $this->getCSSCode($item);
		}
		echo '<style type="text/css">';
		echo join($css['global'],HCGS_DEBUGGING? "\n":'');
		if(count($css['queries'])) {
			$style='';
			foreach($css['queries'] as $media=> $items) {
				$style.= "$media {";
				$style.= join($items, HCGS_DEBUGGING? "\n":'');
				$style.= "}".(HCGS_DEBUGGING? "\n":'');
			}
			echo $style;
		}
		echo '</style>';
	}
	public static function loadFromFile($file='') {
		global $_css;
		if(!$file || self::_get('loadcss',false) || !file_exists($file)) return false;
		$xml = simplexml_load_string(file_get_contents($file));#_print($xml->css);
		foreach($xml->css as $css) {
			$name = (string)$css->name;
			$code = (string)$css->code;
			$args = ['selector'=> $name];
			if(!empty($css->media)) {
				$args['media'] = (string)$css->media;
				$name.= '-media';
			}
			if(!empty($css->type)) $type= (string) $css->type;
			else $type='class';

			if(!$code) continue;
			if($name) $_css->add($name, $code, $type, $args);
			else {
				$pr = (string)$css->parent;
				$suffix = (string)$css->more;
				$_css->addMore($pr, $suffix, $code);
			}
		}
		self::_set('loadcss',1);
		return true;
	}
}
global $_css;
$_css = new HCGS_CSS();