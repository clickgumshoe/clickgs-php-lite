<?php
use Monolog\Logger;
use Monolog\Formatter\LineFormatter;
use Monolog\Handler\SyslogUdpHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\FirePHPHandler;

//current URL
function hcgs_currentURL($includeParam=true, $param='') {
	$actual_link = (isset($_SERVER['HTTPS']) ? "https" : "http") . "://{$_SERVER['HTTP_HOST']}{$_SERVER['REQUEST_URI']}";;
	if(!$includeParam) {
		$url = explode('?', $actual_link);
		return rtrim($url[0], '/');
	}
	return $actual_link.($param? (strpos($actual_link,'?')!==false? '&':'?').$param:'');
}
function hcgs_homeURL() {
	return (isset($_SERVER['HTTPS']) ? "https" : "http") . "://{$_SERVER['HTTP_HOST']}";
}
function hcgs_getTargetURL($param='', $clean=false) {
	
	if(!empty($_GET['lpurl'])) {
		/*$p = parse_url($url);
		$p1 = parse_url($_GET['lpurl']);
		if($p['host'] !== $p['host']) */
			$url = $_GET['lpurl'];
	}
	else $url = hcgs_currentURL(false);
	//if(!$includeParam) return _clean_url($url);
	$url = hcgs_buildURL($url, !$clean? $param. (hcgs_gclid()? '&gclid='. hcgs_gclid(): ''):'' /*, 'lpurl,network,device,'*/);
	return $url;
}

function hcgs_clean_url($url) {
    $arr=parse_url($url);
    if(!isset($arr['scheme']) || !isset($arr['host'])) return rtrim($url, '/');
    $url = $arr['scheme']. '://'. $arr['host']. (isset($arr['path'])? $arr['path']:'');
    return rtrim($url, '/');
}

function hcgs_buildURL($url, $include_param=array(), $exclude_param=array()) {
	$p = parse_url($url);
	if(!isset($p['query'])) $params = array();	
	else parse_str($p['query'], $params);
	if(!empty($include_param)) {
		if(is_string($include_param)) {
			parse_str($include_param, $include_param);
		}
		if(is_array($include_param)) $params = array_merge($params, $include_param);
	}
	if(!empty($exclude_param)) {
		if(is_string($exclude_param)) $exclude_param = explode(',', $exclude_param);
		foreach($params as $k=>$v) {
			if(in_array($k, $exclude_param)) unset($params[$k]);
		}
	}
	$p['query'] = !empty($params)? '?'.http_build_query($params):'';
	
	return $p['scheme'].'://'. $p['host']. (isset($p['path'])?$p['path']:''). $p['query'].(isset($p['fragment'])?$p['fragment']:'');
}
function hcgs_getSiteKey() {
	return 'U2FsdGVkX1akfNM9RTnCOP3vxMxaPrOCx1e4u3BUEbg_LMg7kdvpY+uFJC9uZFaUBGaKgtJdPpMlHR4act94VY='.md5($_SERVER['HTTP_HOST']);
}
if(!function_exists('hcgs_is_diff_url')) :
function hcgs_is_diff_url($url1, $url2) {
	$p1=parse_url($url1);
	$p2=parse_url($url2);//print_r($p1);print_r($p2);

	if(isset($p1['path'])) $p1['path'] = trim($p1['path'],'/');
	else $p1['path']='';
	if(isset($p2['path'])) $p2['path'] = trim($p2['path'],'/');
	else $p2['path']='';

	if(!isset($p1['query'])) $p1['query']='';
	if(!isset($p2['query'])) $p2['query']='';

	if($p1['scheme']!==$p2['scheme']) return true;
	if($p1['host']!==$p2['host']) return true;
	if($p1['path']!==$p2['path']) return true;
	if($p1['query']!==$p2['query']) return true;
	return false;
}
endif;

if(!function_exists('hcgs_diff_host')) :
function hcgs_diff_host($url1, $url2) {
	$p1=parse_url($url1);
	$p2=parse_url($url2);
	if($p1['host']!==$p2['host']) return true;
}
endif;

//wp_doing_ajax
if(!function_exists('hcgs_is_ajax')):
function hcgs_is_ajax() {
	if(function_exists('wp_doing_ajax')) return wp_doing_ajax();
	return !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest';
}
endif;

function hcgs_asset($file, $ver=0) {
	$t = explode('.', $file);
	$ext = array_pop($t);
	if (filter_var($file, FILTER_VALIDATE_URL)) {
		$url = join($t,'.');
	}
	else $url = 'asset/'. join($t, '.');
	$url = $url. (HCGS_TEST_MODE || strpos($file,'.min')!==false? '.': '.min.').$ext;
	if(strpos('version=', $url)===false /*&& TEST_MODE*/)
		$url .= (strpos($url, '?')!==false? '&':'?') .'version=1.1'. hcgs_get_cache_prevent_string($ver);
	return $url;
}
function hcgs_referrer($url='') {
	$ref = isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']:'';
	return isset($_REQUEST['ref']) && !empty(trim($_REQUEST['ref'])) /*&& strpos($ref,'random')===false*/? urldecode($_REQUEST['ref']): ($ref? $ref:$url);
}
//test ads
function hcgs_is_debug_ad() {
	if(isset($_SERVER['HTTP_REFERER']) && !empty($_GET['_ad_debug'])) return true;//hcgs_option('test_from_organic_search') 
	return false;
}
function hcgs_is_organic_test() {
	$r = !empty($_GET['_organic_test']);
	return $r;
}
function hcgs_is_from_search($opt=0) {
	$se = array(
		'www.google.','www.bing','www.yahoo.','www.ask.','vn.search.yahoo.','yandex.','coccoc.',
		'www.aol.','www.baidu.','www.wolframalpha.','duckduckgo.','com.google.android.googlequicksearchbox'
	);
	$ref = hcgs_referrer();$from_s=0;
	if($ref)foreach($se as $s) {
		if(strpos($ref, $s)!==false) {$from_s=1;break;}
	}
	if( $from_s
		&& strpos($_SERVER['HTTP_USER_AGENT'], 'GrapeshotCrawler')===false &&
		strpos($_SERVER['HTTP_USER_AGENT'], 'adsbot')===false &&
		strpos($_SERVER['HTTP_USER_AGENT'], 'google.com')===false && (!$opt || hcgs_option('test_from_organic_search'))
	)
		return true;
	if(/*!empty($_GET['_organic_test']) ||*/ ($ref && (strpos($ref,'&_emulator=1')!==false || strpos($ref, '/test_visit.html')!==false))) return true;
	return false;
}

if(!function_exists('hcgs_is_from_adwords')) :
function hcgs_is_from_adwords($only_ads=false) {
	if(hcgs_is_from_search() ||hcgs_is_debug_ad()) {		
		//clear_expire_user();	//empty session if over 30m: @deprecated will destroy current old client if access more times
		if(!empty($_SESSION['hcgs__users_data']['real_ip'])) unset($_SESSION['hcgs__users_data']['real_ip']);
		$ip = hcgs_getClientIP();
		//if user nerver complete popup, and re-click my ad
		if(isset($_SESSION['hcgs-user-session-guid'])) unset($_SESSION['hcgs-user-session-guid']);
		if(!empty($_SESSION['hcgs_lock']['track_data'])) unset($_SESSION['hcgs_lock']['track_data']);
		if(!empty($_SESSION['hcgs__users_data']['ips'][$ip]['click'])) $_SESSION['hcgs__users_data']['ips'][$ip]['click'] = 0;
		hcgs_update_visitor(['is_from_adwords'=> 0,'gclid'=>'']);

	}
	if(empty($_SESSION['hcgs__users_data']) && !empty($_COOKIE['hcgs__users_data'])) {	//fix web server
		//@session_start();
		$_SESSION['hcgs__users_data'] = json_decode(stripslashes($_COOKIE['hcgs__users_data']), true);
		if(!HCGS_TEST_MODE) unset($_COOKIE['hcgs__users_data']);
	}
	//log_to_file($_SESSION);#test
	
	$result = false;
	if(hcgs_is_from_search() || hcgs_is_debug_ad()) {
		if(!empty($_GET['gclid'])) {	//adwords detecting by auto-tagging
			//$ip = getClientIP();
			hcgs_set_visit_ad();			
			$result = true;
		}
		elseif(!empty($_GET['campaignid']) && !empty($_GET['network'])) {
			$result = true;	//by tracking template
		}
		elseif(!$only_ads && hcgs_option('test_from_organic_search')) {
			$result = true;	//from test setting
		}
	};
	
	//if(!isset($_SERVER['HTTP_REFERER'])) $result= true;	//direct access, no wrong logic
	/*if(!empty($_SERVER['HTTP_REFERER'])) {
		static $log;
		//$h=parse_url($_SERVER['HTTP_REFERER']);
		//if(in_array($h['host'], array('google.com','google.com.vn','www.google.com','www.google.com.vn') )) return true;
		if(!$log) {
			//send_remote_syslog('HTTP_REFERER='.$_SERVER['HTTP_REFERER']);
			log_to_file('HTTP_REFERER='.$_SERVER['HTTP_REFERER']);$log=1;
		}
	}*/
	if($result) {
		hcgs_update_visitor(['is_from_adwords'=>1]);//_set_persist('is_from_adwords',1);
		if(hcgs_is_from_search() ||hcgs_is_debug_ad()) {
			@setcookie('hcgs__users_data', json_encode($_SESSION['hcgs__users_data']) ,time() + (86400 * 30));
		}
	}
	if((hcgs_is_from_search() || hcgs_is_debug_ad()) || (!$only_ads && hcgs_get_visitor_data('is_from_adwords', false))) return true;
	return $result;
}
endif;

function hcgs_gclid() {
	if(!empty($_GET['gclid'])) return $_GET['gclid'];
	//if(!empty($_SESSION['hcgs-my-gclid'])) return $_SESSION['hcgs-my-gclid'];
	return hcgs_get_visitor_data('gclid');
}
function hcgs_visit_id() {
	if(!empty($_GET['random'])) return $_GET['random'];
	//if(!empty($_SESSION['hcgs-my-visit_unique'])) return $_SESSION['hcgs-my-visit_unique'];
	return hcgs_get_visitor_data('visit_unique');
}

function hcgs_set_visit_ad() {
	if(!empty($_GET['gclid'])) {
		//$_SESSION['hcgs-my-gclid'] = $_GET['gclid'];	//first priority
		hcgs_update_visitor(['gclid'=> $_GET['gclid']]);
	}
	elseif(!empty($_GET['random'])) hcgs_update_visitor(['visit_unique' => $_GET['random']]);
}
function hcgs_is_from_ads() {
	return isset($_GET['gclid']) && isset($_GET['campaignid']);
}
function hcgs_get_visit_unique() {
	$id = hcgs_gclid();
	$id.= hcgs_visit_id();
	//elseif(visit_id()) return visit_id();
	/*if(isset($_REQUEST['campaignid'])) $id.=$_REQUEST['campaignid'];
	if(isset($_REQUEST['adgroupid'])) $id.=$_REQUEST['adgroupid'];
	if(isset($_REQUEST['creative'])) $id.=$_REQUEST['creative'];*/
	return $id;
}
//@deprecated
/*function detect_goback_from_adscreen($ip='') {
	//if(function_exists('hcgs_option') && hcgs_option('test_from_organic_search')) return false;
	if(!$ip) $ip = getClientIP();
	if(!isset($_SESSION['hcgs-ads-histories'])) $_SESSION['hcgs-ads-histories']=array();
	$unid = get_visit_unique();
	if($unid && isset($_SESSION['hcgs-ads-histories'][$unid.'-'.$ip])) return true;
	$_SESSION['hcgs-ads-histories'][$unid.'-'.$ip] = 1;
}*/
function hcgs_parseReferer($url='') {
	static $r=0;
	if(!$url && isset($_SERVER['HTTP_REFERER'])) $url = hcgs_referrer();//$_SERVER['HTTP_REFERER'];
	if(!$r && $url) {
		$t=parse_url($url);
		if(isset($t['query'])) {
			parse_str($t['query'],$q);
			if(isset($q['gclid']) && empty($_GET['gclid'])) $_GET = array_merge($_GET, $q);
		}
		$r=1;
	}
	
}
function hcgs_getValueTrack() {
	hcgs_parseReferer(hcgs_referrer());
	if(hcgs_get_persist('track_data') && count(array_filter(hcgs_get_persist('track_data')))) return hcgs_get_persist('track_data');

	$gclid = isset($_GET['gclid'])? $_GET['gclid']: '';	//if enable auto-tagging
	$lpurl = isset($_GET['lpurl'])? $_GET['lpurl']: '';
	$campaignid = isset($_GET['campaignid'])? $_GET['campaignid']: '';
	$adgroupid = isset($_GET['adgroupid'])? $_GET['adgroupid']: '';
	$device = isset($_GET['device'])? $_GET['device']: '';
	$network = isset($_GET['network'])? $_GET['network']: '';
	$keyword = isset($_GET['keyword'])? $_GET['keyword']: '';
	$matchtype = isset($_GET['matchtype'])? $_GET['matchtype']: '';
	$creative = isset($_GET['creative'])? $_GET['creative']: '';
	$placement = isset($_GET['placement'])? $_GET['placement']: '';
	$devicemodel = isset($_GET['devicemodel'])? $_GET['devicemodel']: '';
	$random_id = isset($_GET['random'])? $_GET['random']: '';
	$adposition = isset($_GET['adposition'])? $_GET['adposition']: '';
	$loc_physical_ms = isset($_GET['loc_physical_ms'])? $_GET['loc_physical_ms']: '';

	$track_data = array(
		'lpurl'=>$lpurl,'adgroupid'=> $adgroupid, 'campaignid'=> $campaignid,
		'device'=> $device, 'network'=> $network, 'keyword'=> $keyword, 'matchtype'=> $matchtype,
		'creative'=> $creative, 'placement'=> $placement, 'devicemodel'=> $devicemodel,
		'random_id'=> $random_id, 'adposition'=> $adposition,'loc_physical_ms'=> $loc_physical_ms,
		'gclid'=> $gclid
	);
	$track_data = array_filter($track_data);	//remove empty value
	if($gclid) {
		hcgs_set_persist('track_data', $track_data);
		return $track_data;
	}
	return array();
}
function hcgs_generateIP() {
	//return long2ip(rand(0, "4294967295"));
	$randIP = "".mt_rand(0,255).".".mt_rand(0,255).".".mt_rand(0,255).".".mt_rand(0,255);
	return $randIP;
}

if(!function_exists('hcgs_randomString')) :
function hcgs_randomString($length=10, $prefix='') {

    $keys = array_merge(range(0,9), range('a', 'z'));
    $key='';
    for($i=0; $i < $length; $i++) {

        $key .= $keys[array_rand($keys)];

    }
    return $prefix.$key;
}
endif;

function hcgs_getClientIP($multi=false) {
	static $ip;
	if($ip) {
		return !$multi && is_array($ip)? $ip[0]:$ip;
	}
	//test
	if(hcgs_is_debug_ad() || hcgs_is_organic_test() || hcgs_exist_test_ip()) $ip = hcgs_get_test_ip();
	else {
		if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
		    $ip = $_SERVER['HTTP_CLIENT_IP'];
		} elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
		    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
		} elseif(isset($_SERVER['REMOTE_ADDR'])) {
		    $ip = $_SERVER['REMOTE_ADDR'];
		}
		else $ip='127.0.0.1';
	}
		//try with other service: wrong
		/*if(!_user_persist('real_ip')) {
			$r = curl_get('https://api.ipify.org/?format=json', [CURLOPT_CONNECTTIMEOUT=> 5]);//important: set timeout 5s, not 1s
			if($r) {//echo '[p]'.$r.'<>'.$ip;
				$r = json_decode($r, true);
				if(!empty($r['ip'])) {
					if($r['ip']!== $ip) _user_persist('fake_ip', $ip);
					$ip = $r['ip'];					
				}
				_user_persist('real_ip', isset($r['ip'])? $r['ip']: $ip);
			}
			else _set_persist('real_ip', $ip);
		}
		else $ip= _user_persist('real_ip');
	//}*/
	if(strpos($ip,',')!==false) {
		$ip = preg_split('#[\s,]+#',$ip);if(!$multi) return $ip[0];
	}
	return $ip;
}
function hcgs_getPhonenumber() {
	$header = apache_request_headers();
	if(!empty($header['x-up-calling-line-id'])) return $header['x-up-calling-line-id'];
}
function hcgs_getSiteName($name='', $valid_slug=true) {
	/*static $n;
	if($n) return $n;*/
	if($name) $n= $name;
	elseif(!empty($_GET['lpurl'])) {	//by value track
		$p=parse_url($_GET['lpurl']);
		$n = $p['host'];
	}
	elseif(!empty($_SERVER['SERVER_NAME'])) $n= $_SERVER['SERVER_NAME'];
	elseif(defined('SITE_NAME') && SITE_NAME) $n= SITE_NAME;
	else {
		$dt = _get('current_user_data',array());
		if(isset($dt['domain'])) $n=$dt['domain'];
		else $n='localhost';
	}
	if($valid_slug) $n = str_replace('.','_', $n);
	return $n;
}

function hcgs_loadCSS() {
	global $_css;
	if(HCGS_CSS::loadFromFile(dirname(__DIR__).'/data/css.xml'))
		$_css->print_css();
}
function hcgs_css_name($name, $echo=1) {
	global $_css;
	if($echo) echo $_css->getSelector($name);
	else return $_css->getSelector($name);
}
//get setting value
function hcgs_get_setting($name, $value='') {
	if(function_exists('hcgs_option')) return hcgs_option($name, $value);
	if(isset($GLOBALS[$name])) return $GLOBALS[$name];
	return $value;
}

function hcgs_collect_client_data($override=array()) {
	$referer = hcgs_referrer('direct');//isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']: 'direct';
	$browser = hcgs_getBrowser();
	$os = hcgs_getOSVersion();
	hcgs_parseReferer($referer);

	$data = array(
		'referer'=> $referer, 'url'=> hcgs_getTargetURL(),//'adwordsCampaign'=> get_setting('adwords_campaign_id'),
    	'uid'=> hcgs_prepare_user_session(), 'domain'=> hcgs_getSiteName('', false), 'gclid'=> hcgs_gclid(),
    	'token'=> hcgs_get_setting('site_token'), 'webhook'=> hcgs_get_setting('tracking_url'),//'cookie_site'=> CRYPTTO_PASSPHRASE
    	'browser'=> array(
    		'browser'=> $browser['name'],'browserVersion'=>$browser['version'],
    		'os'=> /*$browser['platform']*/$os['name'], 'osVersion'=> $os['version'],
    		'userAgent'=> $browser['userAgent'],
    		'mobile'=> hcgs_is_mobile()? true: false, 
    	),'time'=> time()
    	//tracking value
    	//'valueTrack'=> isset($track_data)? $track_data: array()
	);
	if(hcgs__req('_ad_debug')) $data['test']=1;
	$adlock_data = isset($GLOBALS['hw_adlock_data'])? $GLOBALS['hw_adlock_data']: get_option('_had_adlock_data');
	if(!empty($adlock_data)) {
		$data['api'] = $adlock_data;
		if(isset($data['api']['pushover_token'])) unset($data['api']['pushover_token']);
		if(isset($data['api']['cloudinary'])) unset($data['api']['cloudinary']);
	}
	if(!empty($override)) $data = array_merge($data, $override);//_print($data);
	return $data;
}
//@deprecated
function hcgs_send_check_BadIP_1($ip, $errorCallback=null) {
	$loop = React\EventLoop\Factory::create();
	$connector = new React\Socket\Connector($loop);

	React\Promise\Timer\timeout($connector->connect(TRACKING_SERVER), 1.0, $loop)->then(function ($conn) use ($loop, $ip) {
	//$connector->connect('127.0.0.1:8080')->then(function (/*ConnectionInterface*/ $conn) use ($loop) {
		
	    //$conn->pipe(new React\Stream\WritableResourceStream(STDOUT, $loop));
	    #$conn->write("Hello World!\n");
	    //$referer = isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']: 'direct';
	    
	    $conn->write(json_encode(hcgs_collect_client_data(array(
	    	'task'=>'checkIP','ip'=> $ip, //'adwordsCampaign'=> get_setting('adwords_campaign_id'),	    	
	    	))));
	    $conn->end();
	}, function ($error) use($errorCallback) {
		//echo 'error';	//error to connect to adword server
		if(is_callable($errorCallback)) call_user_func($errorCallback, 1);
	});

	$loop->run();
}

function hcgs_send_check_IP($ip, $errorCallback=null) {
	$server=array('host'=> '', 'port'=> 0);
	if(is_array($ip) && isset($ip['active_servers'])) {
		$server = count($ip['active_servers'])? $ip['active_servers'][0]: array();	//get first server
		unset($ip['active_servers']);
	}
	else {
		$active_servers = hcgs_get_active_servers();
		$server = count($active_servers)? $active_servers[0]: array();
	}
	//$h=explode(':', TRACKING_SERVER);
	//$referer = isset($_SERVER['HTTP_REFERER'])? $_SERVER['HTTP_REFERER']: 'direct';
	if(empty($server['host']) ) return;

	$ws = new HCGS_WS(array(
		'host' => $server['host'],
		'port'=> isset($server['port'])? $server['port']:'80',
		'path' => ''
	));//
	$args = hcgs_collect_client_data(array(
	    	'task'=>'checkIP',/*'referer'=> $referer,*/ //'adwordsCampaign'=> get_setting('adwords_campaign_id'),	    
	    ));
	if(is_string($ip)) $args['ip'] = $ip;
	elseif(is_array($ip)) $args = array_merge($ip, $args);
	$ips = hcgs_getClientIP(true);
	if(is_array($ips) && count($ips)>=2) {
		foreach($ips as $_ip) if($_ip!=$ip) $args['ip_host'] = $_ip;if(TEST_MODE) hcgs_log_to_file(print_r($ips,1));
	}

	$args['no_send'] = ($args['task']=='checkIP' && strpos($args['referer'],hcgs_getTargetURL('',true))!==false && strpos($args['referer'],'&gclid=')===false);

	try {
		if(!$args['no_send']) {
			$result = $ws->send(json_encode(hcgs_array_exclude_keys($args,['no_send'])), $errorCallback);
			$ws->close();
		}
		
		return $args;
	}
	catch(Exception $e){
		//echo $e->getMessage();
	}
	return null;
}
//@deprecated
function hcgs_send_update_ip_1($ip, $errorCallback=null) {
	$loop = React\EventLoop\Factory::create();
	$connector = new React\Socket\Connector($loop);

	React\Promise\Timer\timeout($connector->connect(TRACKING_SERVER), 2.0, $loop)->then(function ($conn) use ($loop, $ip) {
		$conn->write(json_encode(hcgs_collect_client_data(array(
			'task'=>'human_interactive','ip'=> $ip, //'adwordsCampaign'=> get_setting('adwords_campaign_id'),			
		))));
	    $conn->end();
	}, function ($error) use($errorCallback) {
		//error to connect to adword server
		if(is_callable($errorCallback)) call_user_func($errorCallback, 1);
	});
	$loop->run();
}

function hcgs_send_update_ip($ip, $errorCallback=null) {
	$active_servers = hcgs_get_active_servers();
	if(count($active_servers)==0) return;
	$server = $active_servers[0];
	
	hcgs_update_visitor( array('click'=>1), $ip);

	/*$ws = new ws(array(
		'host' => $server['host'],
		'port'=> isset($server['port'])? $server['port']:'80',
		'path' => ''
	));
	$result = $ws->send(json_encode(collect_client_data(array(
			'task'=>'human_interactive','ip'=> $ip,//'adwordsCampaign'=> get_setting('adwords_campaign_id'),			
		))), $errorCallback);
	$ws->close();
	return $result;*/
}
function hcgs_send_to_server( $data, $errorCallback=null) {
	if(!isset($data['server'])) {
		$data['server'] = hcgs_get_active_servers();//$active_servers
		if(count($data['server'])!=0) 
			$data['server'] = $data['server'][0];
	}
	
	$ws = new HCGS_WS(array(
		'host' => $data['server']['host'],
		'port'=> !empty($data['server']['port'])? $data['server']['port']:'80',
		'path' => '',
		'allow_server_response'=> false
	));
	$result = $ws->send(json_encode($data), $errorCallback);
	$ws->close();
	return $result;
}

function hcgs_crypto_rand_secure($min, $max) {
        $range = $max - $min;
        if ($range < 0) return $min; // not so random...
        $log = log($range, 2);
        $bytes = (int) ($log / 8) + 1; // length in bytes
        $bits = (int) $log + 1; // length in bits
        $filter = (int) (1 << $bits) - 1; // set all lower bits to 1
        do {
            $rnd = hexdec(bin2hex(openssl_random_pseudo_bytes($bytes)));
            $rnd = $rnd & $filter; // discard irrelevant bits
        } while ($rnd >= $range);
        return $min + $rnd;
}

function hcgs_getToken($length=32){
    $token = "";
    $codeAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    $codeAlphabet.= "abcdefghijklmnopqrstuvwxyz";
    $codeAlphabet.= "0123456789";
    for($i=0;$i<$length;$i++){
        $token .= $codeAlphabet[hcgs_crypto_rand_secure(0,strlen($codeAlphabet))];
    }
    return $token;
}

function hcgs_pick_one($arr, &$id=null, $notMatch=null) {
	if(!count($arr)) return '';
	$id = array_rand($arr);
	if($notMatch && $arr[$id]==$notMatch) return hcgs_pick_one($arr, $id, $notMatch);
	return $arr[$id];
}

/**
* Decrypt data from a CryptoJS json encoding string
*
* @param mixed $passphrase
* @param mixed $jsonString
* @return mixed
*/
function hcgs_cryptoJsAesDecrypt( $jsonString, $passphrase=''){
	if(!$passphrase) $passphrase = hcgs_getSiteKey();
	if(hcgs_is_base64($jsonString)) $jsonString = base64_decode($jsonString);
    $jsondata = json_decode($jsonString, true);
    try {
        $salt = hex2bin($jsondata["s"]);
        $iv  = hex2bin($jsondata["iv"]);
    } catch(Exception $e) { return null; }
    $ct = base64_decode($jsondata["ct"]);
    $concatedPassphrase = $passphrase.$salt;
    $md5 = array();
    $md5[0] = md5($concatedPassphrase, true);
    $result = $md5[0];
    for ($i = 1; $i < 3; $i++) {
        $md5[$i] = md5($md5[$i - 1].$concatedPassphrase, true);
        $result .= $md5[$i];
    }
    $key = substr($result, 0, 32);
    $data = openssl_decrypt($ct, 'aes-256-cbc', $key, true, $iv);
    $data = json_decode($data, true);
    return is_string($data) && hcgs_is_JSON($data)? json_decode($data, true): $data;
}

/**
* Encrypt value to a cryptojs compatiable json encoding string
*
* @param mixed $passphrase
* @param mixed $value
* @return string
*/
function hcgs_cryptoJsAesEncrypt( $value, $passphrase=''){
	if(!$passphrase) $passphrase = hcgs_getSiteKey();
    $salt = openssl_random_pseudo_bytes(8);
    $salted = '';
    $dx = '';
    while (strlen($salted) < 48) {
        $dx = md5($dx.$passphrase.$salt, true);
        $salted .= $dx;
    }
    $key = substr($salted, 0, 32);
    $iv  = substr($salted, 32,16);
    $encrypted_data = openssl_encrypt(json_encode($value), 'aes-256-cbc', $key, true, $iv);
    $data = array("ct" => base64_encode($encrypted_data), "iv" => bin2hex($iv), "s" => bin2hex($salt));
    return json_encode($data);
}
function hcgs_is_base64($data) {
	return (base64_encode(base64_decode($data)) === $data);
}
function hcgs_is_JSON(...$args) {
    json_decode(...$args);
    return (json_last_error()===JSON_ERROR_NONE);
}
//Generate a globally unique identifier (GUID)
function hcgs_guid()
{
    if (function_exists('com_create_guid') === true)
    {
        return trim(com_create_guid(), '{}');
    }

    return sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
}
function hcgs_guidv4()
{
    if (function_exists('com_create_guid') === true)
        return trim(com_create_guid(), '{}');

    $data = openssl_random_pseudo_bytes(16);
    $data[6] = chr(ord($data[6]) & 0x0f | 0x40); // set version to 0100
    $data[8] = chr(ord($data[8]) & 0x3f | 0x80); // set bits 6-7 to 10
    return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
}
function hcgs__post($name, $val='') {
    if(isset($_POST[$name])) return $_POST[$name];
    return $val;
}
function hcgs__get($name, $val='') {
    if(isset($_GET[$name])) return $_GET[$name];
    return $val;
}

function hcgs__req($name, $val='') {
    if(isset($_REQUEST[$name])) return $_REQUEST[$name];
    return $val;
}
function hcgs_set_persist($key, $val='') {
	if(!isset($_SESSION['hcgs_lock'])) $_SESSION['hcgs_lock']=array();
	if(is_string($key)) $_SESSION['hcgs_lock'][$key] = $val;
}
function hcgs_get_persist($key, $val='') {
	if(!isset($_SESSION['hcgs_lock'])) $_SESSION['hcgs_lock']=array();
	if(isset($_SESSION['hcgs_lock'][$key])) return $_SESSION['hcgs_lock'][$key];
	return $val;
}
function hcgs_user_persist($key, $value=null) {
	$dt = isset($_SESSION['hcgs__users_data'])? $_SESSION['hcgs__users_data']: [];
	if($key && $value!==null) $_SESSION['hcgs__users_data'][$key] = $value;
	else return isset($dt[$key])? $dt[$key]: '';
}
function hcgs_check_times($name) {
	if(!isset($_SESSION['hcgs_lock'])) $_SESSION['hcgs_lock']=array();
	if(!isset($_SESSION['hcgs_lock'][$name])) $_SESSION['hcgs_lock'][$name]=0;
	$_SESSION['hcgs_lock'][$name]++;
	return $_SESSION['hcgs_lock'][$name];
}
//\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
//check for exist visitor
function hcgs_visitor_is_done($ip='') {
	if(!$ip) $ip = hcgs_getClientIP();

	if(empty($_SESSION['hcgs__users_data']['ips'])) $_SESSION['hcgs__users_data']['ips']=array();
	$user = isset($_SESSION['hcgs__users_data']['ips'][$ip])? $_SESSION['hcgs__users_data']['ips'][$ip]: null;
	if(!$user) $user = $_SESSION['hcgs__users_data']['ips'][$ip] = array('click'=>0);
	return (int)$user['click'];
}

function hcgs_update_visitor($dt, $ip='' ) {
	if(!$ip) $ip = hcgs_getClientIP();
	if(hcgs_visitor_is_done($ip)) return;	//not populate data on complete visitor
	//_set_persist('visitor_click_popup', array('click'=> 1));	//use common session data,will clear
	if($dt && isset($_SESSION['hcgs__users_data']['ips'][$ip]) && count($dt)) {
		$_SESSION['hcgs__users_data']['ips'][$ip] = array_merge(
			$_SESSION['hcgs__users_data']['ips'][$ip],
			(array)$dt);
	}
}

function hcgs_get_visitor_data($item='', $val='') {
	$ip = hcgs_getClientIP();
	$dt = (!empty($_SESSION['hcgs__users_data']['ips'][$ip]))? $_SESSION['hcgs__users_data']['ips'][$ip]:[];
	if($item && isset($dt[$item])) return $dt[$item];
	return $val;
}

function hcgs_reset_current_visitor($ip='') {
	if(!$ip) $ip = hcgs_getClientIP();
	
	//because session only work with single machine 
	if(isset($_SESSION['hcgs__users_data'])) unset($_SESSION['hcgs__users_data']);
	if(isset($_SESSION['hcgs_lock'])) unset($_SESSION['hcgs_lock']);
	if(isset($_COOKIE['hcgs__users_data'])) unset($_COOKIE['hcgs__users_data']);
}

function hcgs_is_show_cover_for_ip($ip='') {
	if(!$ip) $ip= hcgs_getClientIP();
	return (hcgs_is_from_adwords() && hcgs_get_visit_unique()) || !hcgs_visitor_is_done($ip) ;
}

function hcgs_prepare_user_session() {
	static $sid;@session_start();
	if($sid) return $sid;
	if(!empty($_SESSION['hcgs-user-session-guid'])) return $_SESSION['hcgs-user-session-guid'];
	
	$sid= md5(session_id().hcgs_get_visit_unique().microtime().rand(0, time()));	//still need unique generation,guidv4()

	if(empty($_SESSION['hcgs-user-session-guid']) /*|| time()-$_SESSION['hcgs-user-session-guid']['time']>=5*/) {
		// array('uid'=>,'time'=>time() );
		$_SESSION['hcgs-user-session-guid'] = $sid;
	}
	return $_SESSION['hcgs-user-session-guid']/*['uid']*/;
}

function hcgs_is_first_user_session() {//return false;//test
	return !isset($_SESSION['hcgs-user-session-guid']);
}

function hcgs_clear_user_data() {
	if(isset($_SESSION['hcgs-cid-token'])) unset($_SESSION['hcgs-cid-token']);
	if(isset($_SESSION['hcgs-user-session-guid'])) unset($_SESSION['hcgs-user-session-guid']);
	//if(isset($_SESSION['hcgs-my-gclid'])) unset($_SESSION['hcgs-my-gclid']);
	//if(isset($_SESSION['hcgs-my-visit_unique'])) unset($_SESSION['hcgs-my-visit_unique']);
	#if(isset($_SESSION['hcgs_lock'])) unset($_SESSION['hcgs_lock']);
	//destroy whole session
	//session_destroy();	//don't, since we use 'hcgs-ads-histories' data->deprecated
}
/*
 * @deprecated 
 * Because not store sensitive info. Session will auto expire after a time.
	prevent clear new click ad session for old user
//https://stackoverflow.com/questions/520237/how-do-i-expire-a-php-session-after-30-minutes
//http://thisinterestsme.com/expire-php-sessions/ 
*/
function hcgs_clear_expire_user() {
	if (isset($_SESSION['LAST_ACTIVITY']) && (time() - $_SESSION['LAST_ACTIVITY'] > 1800)) {
	    // last request was more than 30 minutes ago
	    session_unset();     // unset $_SESSION variable for the run-time 
	    session_destroy();   // destroy session data in storage
	}
	$_SESSION['LAST_ACTIVITY'] = time(); // update last activity time stamp
}

function hcgs_exist_test_ip() {
	if(!isset($_SESSION['hcgs__users_data'])) $_SESSION['hcgs__users_data']=[];
	#if(!empty($_COOKIE['hcgs__users_data']['test_ip'])) return $_COOKIE['hcgs__users_data']['test_ip'];
	return !empty($_SESSION['hcgs__users_data']['test_ip']);//isset($_SESSION['save_rand_ip']);
}
function hcgs_get_test_ip() {
	static $ip;
	if($ip) return $ip;	
	if(hcgs_is_debug_ad() || hcgs_is_organic_test() || !hcgs_exist_test_ip()) {	//isset($_SESSION['save_rand_ip']
		if(!empty($_REQUEST['_test_ip'])) $ip = $_REQUEST['_test_ip'];
		else $ip = hcgs_generateIP();	#$ip = '33.85.80.143';	#test
		hcgs_user_persist('test_ip' , $ip);
	}
	else $ip = hcgs_user_persist('test_ip');

	return $ip;
}
function hcgs_get_popup_button($_data=array()) {
	if(empty($_data['disable_css'])) hcgs_loadCSS();
	extract($_data);

	if(!isset($_SESSION['hcgs-cid-token'])) {
		$token = hcgs_getToken();
		$_SESSION['hcgs-cid-token'] = $token;
	}
	else $token = $_SESSION['hcgs-cid-token'];

	$paragraphs= array(
		//'Thiết kế web chuyên nghiệp, tối ưu quảng cáo Adword!',
		//'Nhấn vào nút này để truy cập vào trang web của chúng tôi!',
		'Chào bạn! Mình là Hoàng, kỹ thuật phát triển web tại clickgumshoe.com, Vui lòng bấm nút bên dưới để vào trang chủ!',
		'Xin chào! Bạn đang có nhu cầu phát triển web và quảng cáo trực tuyến. Vui lòng bấm nút bên dưới để xem các dịch vụ của Hoàng!',
		'Chào! Bạn đang có nhu cầu phát triển trang web, vui lòng bấm nút bên dưới để xem các dịch vụ của Hoàng!'
	);
	
	$button_labels = array(
		'Bấm vào đây để tiếp tục','Vào trang web','Click vào đây để tiếp tục',
		//'Truy cập ngay','Tiếp tục', 'Tiếp tục >>','Vào trang web'
	);
	if(!hcgs_get_visit_unique()) $button_labels= array('Đăng ký');
	else $button_labels = array('Yêu cầu tư vấn');

	$disable_text = true;
	$tags=array('div','span',);	//'p'
	$intro_text = hcgs_pick_one($paragraphs);

	$doc = new FluentDOM\Document();
	$doc->loadHtml(
	  '<!DOCTYPE html>
	   <html><body><div id="cgs-wrapper"></div></body></html>'
	);
	$doc->preserveWhiteSpace = false;
	$doc->formatOutput = true;

	$dom = FluentDOM::QueryCss($doc, 'text/html');

	$_ = FluentDOM::create();
	$_->formatOutput = TRUE;
	/*echo $_(
	  'ul',
	  ['class' => 'navigation'],
	  $_('li', 'FluentDOM')
	)->document->saveHTML();*/

	$root=$dom->formatOutput()->find('#cgs-wrapper')->eq(0);
	$nodes = array();
	$num = rand(3,10);

	for($i=0;$i< $num;$i++) {
		$tag = $tags[array_rand($tags)];
		$id = HCGS_CSS::css_selector();//echo $id;
		$ele = $_($tag, ['class'=> $id]);//$ele->document->append($_('a','A'));
		if(isset($lastEle)) {
			$lastEle->append($ele->document->firstChild);
			//$lastEle=$lastEle->find('//'.$tag.'[@class="'.$id.'"]')->eq(0);//->item(0);	
			$lastEle=$lastEle->find($tag.'.'.$id)->eq(0);
		}
		else {
			$root->append($ele->document->firstChild);
			//$lastEle = $root->find('//'.$tag.'[@class="'.$id.'"]')->eq(0);//->item(0);
			$lastEle = $root->find($tag.'.'.$id)->eq(0);
		}
		$nodes[] = $lastEle;
	}
	$lastEle->addClass(HCGS_TEST_MODE?'cgs-last-e':HCGS_CSS::css_selector('last_e'));#->append('&nbsp;');//->attr('style','height:0px');	//prevent empty element. Important!:hcgs_css_name('hidden',0)

	$ix_button=0;
	$ix_button_pos='';
	$rEle = hcgs_pick_one($nodes, $ix_button);
	$style = hcgs_pick_one(array('style0','style1','style2'));
	//add continue button
	$btn_label = hcgs_pick_one($button_labels);
	$btn_link_params = 'utm_source=clickgumshoe&utm_medium=button&utm_campaign=ads_click&_cid_ad_confirm='. $token;
	$btn_link = hcgs_getTargetURL($btn_link_params);
	//not use A tag
	//$btn_continue = $_('a', ['href'=> $btn_link,'onclick'=>"hit_button('".css_name('button_continue_'.$style, 0)."',this)",'class'=>css_name('button_continue_'.$style, 0),'ga-on'=>'click,contextmenu,auxclick','ga-event-category'=>'ad_screen','ga-event-action'=>'visit_home'], $btn_label);
	$btn_continue = $_('div', ['class'=>hcgs_css_name('button_continue_'.$style, 0).' '.hcgs_css_name('hidden', 0).' '.hcgs_css_name('noselect',0)], $btn_label);

	if(rand(0,1)) {
		$rEle->prepend($btn_continue->document->firstChild);
		$ix_button_pos='prepend';
	}
	else {
		$rEle->append($btn_continue->document->firstChild);
		$ix_button_pos='append';
	}

	for($i=0;$i<2;$i++) {
		$token = hcgs_getToken();
		$cEle = hcgs_pick_one($nodes);
		$link = hcgs_getTargetURL('utm_source=clickgumshoe&utm_medium=button&utm_campaign=ads_click&_cid_ad_confirm='. $token);
		//use A tag here
		$btn = $_('a', ['href'=> $link, 'onclick'=>"hit_button('".hcgs_css_name('button_continue_'.$style, 0)."',this)",'class'=>hcgs_css_name('hidden', 0).' '.hcgs_css_name('noselect',0),'ga-on'=>'click,contextmenu,auxclick','ga-event-category'=>'ad_screen','ga-event-action'=>'visit_home'], $btn_label);
		if(rand(0,1)) $cEle->append($btn->document->firstChild);
		else $cEle->prepend($btn->document->firstChild);
	}
	//last element
	if(!$disable_text) $nodes[count($nodes)-1]->append($_('div', $intro_text)->document->firstChild);
	if(!$lastEle->find('span,div,a')->length) $lastEle->attr('style','display:none')->append('&nbsp;');
	//pick_one($nodes)->append($_('span', pick_one($paragraphs))->document->firstChild);

	#$root->append($_('a')->document->firstChild);
	//echo $root->document->saveHTML();
	//echo $root->outerHTML();
	//echo $ix_button.'-'.$ix_button_pos."\n";
	//echo ($num-1)."\n";
	if($ix_button_pos=='append' ) {
		if($ix_button< $num-1) $position = 'button_bellow_text';
		else $position = 'button_above_text';	//equals
	}
	if($ix_button_pos=='prepend' ) $position='button_above_text';
	if(isset($position)) HCGS_CSS::_set('button_position', $position);
	HCGS_CSS::_set('html_popup', $doc->saveXML($root->item(0)));
	if(!empty($cache)) {
		unset($_data);
		hcgs_print_head(1);
		//hcgs_loadhead(compact('adlock_data','ga_dimension3','ga_dimension1','active_servers','ip'));
	}

	return array('doc'=> $doc, 'style'=> $style,'btn_link_params'=> $btn_link_params,'btn_link'=> $btn_link);
}
//@deprecated
function hcgs_loadhead($_data=array()){
	$h = apache_request_headers();
	$adlock_data = get_option('_had_adlock_data');
	$ga_dimension3 = get_option('_had_ga_dimension3');
	$ga_dimension1 = get_option('_had_ga_dimension1');
	$active_servers = hcgs_get_active_servers();
	$ip = hcgs_getClientIP();
	$submit_ajax_url = HCGS_AJAX_URL.'?action=hcgs_lock_submit&nonce='.wp_create_nonce("user_hit_button_nonce") ;
	$GLOBALS['hw_adlock_data'] = $adlock_data;
	$is_send = hcgs_is_from_adwords(true)? 1: (hcgs_is_from_search(1) ||hcgs_is_debug_ad());
	$GLOBALS['_had_show_popup'] = $show_popup = (int)hcgs_option('popup') && $is_send;
	$show_cover = hcgs_is_show_cover_for_ip($ip);
	$GLOBALS['_had_is_show_popup'] = $is_show_popup = ($show_cover && $show_popup && !hcgs_visitor_is_done($ip));

	echo '<script type="text/javascript">/*[hoangweb-keep-js]*/
		var hcgs_lock = {ajax_url: "'.HCGS_AJAX_URL.'",hit_submit_url: "'.$submit_ajax_url.'", adwords_url: "'.HCGS_MANAGER.'", nonce_userdata: "'.wp_create_nonce("authorize_service_nonce").'"};
		</script>';
	$_data['entity_script']=1;
	
	ob_start();
	extract($_data);
	include dirname(__DIR__). '/layout/top_head.php';//
	$html = ob_get_contents();ob_end_clean();
	if($html) print_r ((str_replace('__text__/javascript','text/javascript',$html)));
}
if(!function_exists('hcgs_isSSL')) :
function hcgs_isSSL() {
  if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] != 'off') return true;
  if(isset($_ENV['HTTPS']) && $_ENV['HTTPS']=='on') return true;
  //on heroku
  if(isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO']=='https') return true;
  return false;
}
endif;

function hcgs_is_cli() {
	return php_sapi_name() == "cli";
}

function hcgs_pageWasRefreshed() {
	$pageWasRefreshed = isset($_SERVER['HTTP_CACHE_CONTROL']) && $_SERVER['HTTP_CACHE_CONTROL'] === 'max-age=0';
	return $pageWasRefreshed;
}

function hcgs_ajax_result(array $data) {
	header('Content-type: application/json; charset=utf-8');
	echo json_encode($data);
	die();
}

function hcgs_getImagebase64Size($base64) {
	if(strpos($base64, ';base64')!==false){
		$base64 = explode(';base64,', $base64);
		$base64 = $base64[1];
	}
	$s = getimagesize('data://application/octet-stream;base64,'. $base64);
	return $s['bits'];
}

function hcgs_base64_to_image($base64_string, $output_file) {
    // open the output file for writing
    $ifp = fopen( $output_file, 'wb' ); 

    // split the string on commas
    // $data[ 0 ] == "data:image/png;base64"
    // $data[ 1 ] == <actual base64 string>
    $data = str_replace('data:image/jpeg;base64,', '', $base64_string);
    //$data = explode( ',', $base64_string );
    $data = str_replace(' ', '+', $data);

    // we could add validation here with ensuring count( $data ) > 1
    fwrite( $ifp, base64_decode( $data ) );	//$data[ 1 ]

    // clean up the file resource
    fclose( $ifp ); 

    return $output_file; 
}

function hcgs_deleteDir($dirPath, $itself=false) {
    if (! is_dir($dirPath)) {
        throw new InvalidArgumentException("$dirPath must be a directory");
    }
    if (substr($dirPath, strlen($dirPath) - 1, 1) != '/') {
        $dirPath .= '/';
    }
    $files = glob($dirPath . '/*', GLOB_MARK);
    foreach ($files as $file) {
        if (is_dir($file)) {
            hcgs_deleteDir($file, true);
        } else {
            unlink($file);
        }
    }
    if($itself) rmdir($dirPath);
}
function hcgs_format_tel($tel) {
	$lz = substr($tel,0,1)=='0';
  	return ($lz?'0':'').str_replace(',','.',number_format($tel));
}
function hcgs_renderList($dt, $arg=array()) {
	$exclude = isset($arg['exclude'])? $arg['exclude']: array();
	$att = isset($arg['att'])? hcgs_htmlAttrs($arg['att']): '';
	$style = isset($arg['style'])? $arg['style']: 'html';
	
	$ui= ($style=='html'? "<ul $att>":'');
	if(is_array($dt))
	foreach($dt as $k=> $v) {
		if(count($exclude) && in_array($k, $exclude)) continue;
		if($style=='html') $ui.="<li><strong>{$k}</strong>: {$v}</li>";
		else $ui.= "- {$k}: $v\n";
	}
	if($style=='html') $ui.='</ul>';
	if(is_array($dt) && count($dt)) return $ui;
}
function hcgs_array_exclude_keys($arr, $keys=[]) {
    #foreach($arr as $k=>$v) if(in_array($k, $keys)) unset($arr[$k]);
    foreach($keys as $k) if(isset($arr[$k])) unset($arr[$k]);
    return $arr;
}
function hcgs_htmlAttrs($attrs) {
	$ui='';
	foreach ($attrs as $key => $value) {
		$ui.= $key. '="'. addslashes($value) .'" ';
	}
	return $ui;
}

//send remote log
function hcgs_send_remote_syslog($message, $component = "web", $program = "web") {
	$PAPERTRAIL_HOSTNAME = 'logs4.papertrailapp.com';
	$PAPERTRAIL_PORT = 52471;
	//if(!PAPERTRAIL_HOSTNAME || !PAPERTRAIL_PORT) return;
	if(isset($_SERVER['SERVER_NAME'])) $program = $_SERVER['SERVER_NAME'];else $program=hcgs_getSiteName();
  	$sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
  	foreach(explode("\n", $message) as $line) {
    	$syslog_message = "<22>" . date('M d H:i:s ') . $program . ' ' . $component . ': ' . $line;
    	socket_sendto($sock, $syslog_message, strlen($syslog_message), 0, $PAPERTRAIL_HOSTNAME, $PAPERTRAIL_PORT);
  	}
  	socket_close($sock);
}
/**
 * write log to file
 * @param $type info|warning|error
*/
function hcgs_log_to_file($message, $type='info',$program = "web") {
	if($_SERVER['SERVER_NAME']) $program = $_SERVER['SERVER_NAME'];
	if(is_array($message)) $message = json_encode($message);
	if(!class_exists('LineFormatter')) return;

	// the default date format is "Y-m-d H:i:s"
	$dateFormat = "Y n j, g:i a";
	// the default output format is "[%datetime%] %channel%.%level_name%: %message% %context% %extra%\n"
	$output = "[%datetime%] %level_name% > %message% %context% %extra%\n";
	// finally, create a formatter
	$formatter = new LineFormatter($output, $dateFormat);

	// create a log channel
	$stream = new StreamHandler(dirname(__DIR__). '/data/logs.txt', Logger::DEBUG);
	//$stream->setFormatter($formatter);

	$log = new Logger($program);
	$log->pushHandler($stream);
	$log->pushHandler(new FirePHPHandler());

	// add records to the log
	if($type=='info') $log->info($message);
	if($type=='warning') $log->warning($message);
	if($type=='error') $log->error($message);
}

if(!function_exists('hcgs_print')):
function hcgs_print($s, $att='')	 {
	printf('<textarea %s>', $att);
	print_r($s);
	echo '</textarea>';
}
endif;

/**
 * Devices info
*/
function hcgs_getBrowser() 
{ 
    $u_agent = $_SERVER['HTTP_USER_AGENT']; 
    $bname = 'Unknown';
    $platform = 'Unknown';
    $version= "";

    //First get the platform?
    if (preg_match('/linux/i', $u_agent)) {
        $platform = 'linux';
    }
    elseif (preg_match('/macintosh|mac os x/i', $u_agent)) {
        $platform = 'mac';
    }
    elseif (preg_match('/windows|win32/i', $u_agent)) {
        $platform = 'windows';
    }

    // Next get the name of the useragent yes seperately and for good reason
    if(preg_match('/MSIE/i',$u_agent) && !preg_match('/Opera/i',$u_agent)) 
    { 
        $bname = 'ie';//'Internet Explorer'; 
        $ub = "MSIE"; 
    } 
    elseif(preg_match('/Firefox/i',$u_agent)) 
    { 
        $bname = 'Firefox'; //Mozilla Firefox
        $ub = "Firefox"; 
    }
    elseif(preg_match('/OPR/i',$u_agent)) 
    { 
        $bname = 'Opera'; 
        $ub = "Opera"; 
    } 
    elseif(preg_match('/Chrome/i',$u_agent)) 
    { 
        $bname = 'Chrome';//'Google Chrome'; 
        $ub = "Chrome"; 
    } 
    elseif(preg_match('/Safari/i',$u_agent)) 
    { 
        $bname = 'Safari'; //Apple
        $ub = "Safari"; 
    } 
    elseif(preg_match('/Netscape/i',$u_agent)) 
    { 
        $bname = 'Netscape'; 
        $ub = "Netscape"; 
    } 
    else $ub='';

    // finally get the correct version number
    $known = array('Version', $ub, 'other');
    $pattern = '#(?<browser>' . join('|', $known) .
    ')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
    if (!preg_match_all($pattern, $u_agent, $matches)) {
        // we have no matching number just continue
    }

    // see how many we have
    $i = count($matches['browser']);
    if ($i != 1) {
        //we will have two since we are not using 'other' argument yet
        //see if version is before or after the name
        if (strripos($u_agent,"Version") < strripos($u_agent,$ub)){
            $version= !empty($matches['version'][0])? $matches['version'][0]: '';
        }
        else {
            $version= !empty($matches['version'][1])? $matches['version'][1]:'';
        }
    }
    else {
        $version= $matches['version'][0];
    }

    // check if we have a number
    if ($version==null || $version=="") {$version="?";}
    
    return array(
        'userAgent' => $u_agent,
        'name'      => $bname,
        'version'   => $version,
        'platform'  => $platform,
        'pattern'    => $pattern,
        //'mobile'=> is_mobile()	//detect mobile device
    );
} 

function hcgs_is_mobile() {
	$useragent = $_SERVER['HTTP_USER_AGENT']; 
	if(preg_match('/(android|bb\d+|meego).+mobile|avantgo|bada\/|blackberry|blazer|compal|elaine|fennec|hiptop|iemobile|ip(hone|od)|iris|kindle|lge |maemo|midp|mmp|netfront|opera m(ob|in)i|palm( os)?|phone|p(ixi|re)\/|plucker|pocket|psp|series(4|6)0|symbian|treo|up\.(browser|link)|vodafone|wap|windows (ce|phone)|xda|xiino/i',$useragent)||preg_match('/1207|6310|6590|3gso|4thp|50[1-6]i|770s|802s|a wa|abac|ac(er|oo|s\-)|ai(ko|rn)|al(av|ca|co)|amoi|an(ex|ny|yw)|aptu|ar(ch|go)|as(te|us)|attw|au(di|\-m|r |s )|avan|be(ck|ll|nq)|bi(lb|rd)|bl(ac|az)|br(e|v)w|bumb|bw\-(n|u)|c55\/|capi|ccwa|cdm\-|cell|chtm|cldc|cmd\-|co(mp|nd)|craw|da(it|ll|ng)|dbte|dc\-s|devi|dica|dmob|do(c|p)o|ds(12|\-d)|el(49|ai)|em(l2|ul)|er(ic|k0)|esl8|ez([4-7]0|os|wa|ze)|fetc|fly(\-|_)|g1 u|g560|gene|gf\-5|g\-mo|go(\.w|od)|gr(ad|un)|haie|hcit|hd\-(m|p|t)|hei\-|hi(pt|ta)|hp( i|ip)|hs\-c|ht(c(\-| |_|a|g|p|s|t)|tp)|hu(aw|tc)|i\-(20|go|ma)|i230|iac( |\-|\/)|ibro|idea|ig01|ikom|im1k|inno|ipaq|iris|ja(t|v)a|jbro|jemu|jigs|kddi|keji|kgt( |\/)|klon|kpt |kwc\-|kyo(c|k)|le(no|xi)|lg( g|\/(k|l|u)|50|54|\-[a-w])|libw|lynx|m1\-w|m3ga|m50\/|ma(te|ui|xo)|mc(01|21|ca)|m\-cr|me(rc|ri)|mi(o8|oa|ts)|mmef|mo(01|02|bi|de|do|t(\-| |o|v)|zz)|mt(50|p1|v )|mwbp|mywa|n10[0-2]|n20[2-3]|n30(0|2)|n50(0|2|5)|n7(0(0|1)|10)|ne((c|m)\-|on|tf|wf|wg|wt)|nok(6|i)|nzph|o2im|op(ti|wv)|oran|owg1|p800|pan(a|d|t)|pdxg|pg(13|\-([1-8]|c))|phil|pire|pl(ay|uc)|pn\-2|po(ck|rt|se)|prox|psio|pt\-g|qa\-a|qc(07|12|21|32|60|\-[2-7]|i\-)|qtek|r380|r600|raks|rim9|ro(ve|zo)|s55\/|sa(ge|ma|mm|ms|ny|va)|sc(01|h\-|oo|p\-)|sdk\/|se(c(\-|0|1)|47|mc|nd|ri)|sgh\-|shar|sie(\-|m)|sk\-0|sl(45|id)|sm(al|ar|b3|it|t5)|so(ft|ny)|sp(01|h\-|v\-|v )|sy(01|mb)|t2(18|50)|t6(00|10|18)|ta(gt|lk)|tcl\-|tdg\-|tel(i|m)|tim\-|t\-mo|to(pl|sh)|ts(70|m\-|m3|m5)|tx\-9|up(\.b|g1|si)|utst|v400|v750|veri|vi(rg|te)|vk(40|5[0-3]|\-v)|vm40|voda|vulc|vx(52|53|60|61|70|80|81|83|85|98)|w3c(\-| )|webc|whit|wi(g |nc|nw)|wmlb|wonu|x700|yas\-|your|zeto|zte\-/i',substr($useragent,0,4)))
		return true;
}

function hcgs_getOS() { 

    $user_agent = $_SERVER['HTTP_USER_AGENT'];

    $os_platform    =   "Unknown OS Platform";

    $os_array       =   array(
                            '/windows nt 10/i'     =>  'Windows 10',
                            '/windows nt 6.3/i'     =>  'Windows 8.1',
                            '/windows nt 6.2/i'     =>  'Windows 8',
                            '/windows nt 6.1/i'     =>  'Windows 7',
                            '/windows nt 6.0/i'     =>  'Windows Vista',
                            '/windows nt 5.2/i'     =>  'Windows Server 2003/XP x64',
                            '/windows nt 5.1/i'     =>  'Windows XP',
                            '/windows xp/i'         =>  'Windows XP',
                            '/windows nt 5.0/i'     =>  'Windows 2000',
                            '/windows me/i'         =>  'Windows ME',
                            '/win98/i'              =>  'Windows 98',
                            '/win95/i'              =>  'Windows 95',
                            '/win16/i'              =>  'Windows 3.11',
                            '/macintosh|mac os x/i' =>  'Mac OS X',
                            '/mac_powerpc/i'        =>  'Mac OS 9',
                            '/linux/i'              =>  'Linux',
                            '/ubuntu/i'             =>  'Ubuntu',
                            '/iphone/i'             =>  'iPhone',
                            '/ipod/i'               =>  'iPod',
                            '/ipad/i'               =>  'iPad',
                            '/android/i'            =>  'Android',
                            '/blackberry/i'         =>  'BlackBerry',
                            '/webos/i'              =>  'Mobile'
                        );

    foreach ($os_array as $regex => $value) { 

        if (preg_match($regex, $user_agent)) {
            $os_platform    =   $value;
        }

    }   

    return $os_platform;

}
function hcgs_getOSVersion() {
	$os = hcgs_getOS();
	$os = explode(' ', $os);
	$version = join(array_splice($os,-1),'');
	$os = join($os,' ');
	return array('name'=> $os, 'version'=> $version);
}

/*function connectToClientDB(){
	static $db;
	if($db) return $db;

	$url = parse_url(CLIENT_DB); 
	$db_type = $url['scheme'];
	$db_server = $url["host"];
	$db_username = $url["user"];
	$db_password = $url["pass"];
	$db_name = substr($url["path"], 1);

	try {
		// Initialize
		$db = new Medoo\Medoo([
		    'database_type' => $db_type,
		    'database_name' => $db_name,
		    'server' => $db_server,
		    'username' => $db_username,
		    'password' => $db_password,
		    'charset' => 'utf8'
		]);
		//create tables
		$db->query('CREATE TABLE IF NOT EXISTS `heroku_socket_servers` (
 `id` int(11) NOT NULL AUTO_INCREMENT,
 `provider` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
 `host` varchar(100) COLLATE utf8_unicode_ci NOT NULL,
 `port` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
 `status` int(11) NOT NULL,
 `hits` double NOT NULL,
 `data` longtext COLLATE utf8_unicode_ci NOT NULL,
 `_group` varchar(50) COLLATE utf8_unicode_ci NOT NULL,
 `last_modified` double NOT NULL,
 PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci');


	}
	catch(Exception $e){
		echo $e->getMessage();
	}
	return $db;
}
*/
if(!function_exists('hcgs_set_no_cache_header')):
function hcgs_set_no_cache_header() {
	header('Expires: Sun, 01 Jan 2014 00:00:00 GMT');
	header("Last-Modified: " . gmdate("D, d M Y H:i:s") . " GMT");
	header("Cache-Control: no-store, no-cache, must-revalidate, max-age=0");
	header("Cache-Control: post-check=0, pre-check=0", false);
	header("Pragma: no-cache");
	//header("Connection: close");
}
endif;

function hcgs_get_cache_prevent_string( $always = false ) {
    return (HCGS_DEBUGGING || $always) ? date('ymd-Gi'/*,'_Y-m-d_H:i:s'*/) : "";
}

function hcgs_fake_value_track($query=true) {
	$campIds = function_exists('get_option')? get_option('_had_campaigns',array()): array('1014894911');
	$params = array(
		'gclid'=> hcgs_randomString(),
		'lpurl'=> 'https://'.$_SERVER['SERVER_NAME'],
		'network'=>'g',
		'device'=>'c',
		'devicemodel'=>'',
		'keyword'=> isset($_SERVER['HTTP_HOST'])? $_SERVER['HTTP_HOST']:'',
		'matchtype'=>'e',
		'creative'=> mt_rand(0, mt_getrandmax() - 1),
		'placement'=>'',
		'campaignid'=> $campIds && count(array_filter($campIds))? hcgs_pick_one($campIds): '1014894911',
		'adgroupid'=> mt_rand(0, mt_getrandmax() - 1),
		'loc_physical_ms'=>'',
		'random'=> mt_rand(0, mt_getrandmax() - 1),
		'adposition'=> '1t1',
	);
	return $query? http_build_query($params): $params;
}
/*
function get_active_server($val='', $port='') {
	$cache = HLockCache::getInstance();
	//$data = $cache->existData('active_server');
	$data = $cache->getData('active_server');
	if( !$data  || time() - $data['time'] > strtotime( '+7 days' )-time()) {
		$data = request_api('client_get_active_server', array('site'=> getSiteName('',false) ));
		if(!empty($data)) $data = $data['data'];
		else $data = $val;//.':'. $port;

		$cache->saveData('active_server', array('data'=>$data, 'time'=> time()) );		
		
	}
	
	return $data? $data['data']:'';
}*/

function hcgs_get_active_servers() {
	//static $result;
	/*if(defined('TRACKING_SERVER')) {	//test server @deprecated
		$h = explode(':',TRACKING_SERVER);
		$data=[['host'=> $h[0], 'port'=> $h[1] ]];
		return $data;//['data'=> $data, 'time'=> time()];
	}*/
	$cache = HWLockCache::getInstance();
	$data = $cache->getData('active_servers');
	if(!$data) $data = get_option('_had_servers');

	if(/*empty($data)*/!$data /*|| (!empty($data['time']) && $data['time'] < strtotime( '-7 days' ))*/ ) {
		$data = hcgs_request_api('client_get_active_servers', array('site'=> hcgs_getSiteName('', false),'token'=> hcgs_get_setting('site_token')));
		if(!empty($data['data'])) $data = $data['data'];
		else $data = array();

		if(count($data)) $cache->saveData('active_servers', $data);//array('data'=>$data, 'time'=> time())
	}
	if(HCGS_TEST_MODE) $data['data'] = [['host'=>'192.168.205.13','port'=>'8080']];	//test, just use TRACKING_SERVER
	//$data['data'] = [['host'=>'hwadsrv-qh2005.herokuapp.com','port'=>'80']];
	if(isset($data['data'])) return $data['data'];
	elseif(HCGS_TEST_MODE) hcgs_send_remote_syslog('Empty servers!');
}

function hcgs_lock_clear_cache() {
	$cache = HWLockCache::getInstance();
	$cache->pool->clear();	//clear everything
}
function hcgs_cache_set($name, $data) {
	$cache = HWLockCache::getInstance();
	$cache->saveData($name, $data);
}
function hcgs_request_api($action, $post) {
	set_time_limit(0);

	$ch=curl_init();
	curl_setopt($ch,CURLOPT_URL, rtrim(HCGS_MANAGER,'/'). '/task/'. $action);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER,true);
	curl_setopt($ch,CURLOPT_POST,true);
	curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0); 
	curl_setopt($ch, CURLOPT_TIMEOUT, 400); //timeout in seconds
	//curl_setopt($ch,CURLOPT_POSTFIELDS,$post);
	#or query string ie: “a=A&b=B”
	curl_setopt($ch,CURLOPT_POSTFIELDS, http_build_query($post));

	$result = curl_exec($ch);
	curl_close($ch);
	if($result) return json_decode($result, true);
	return '';
}
function hcgs_curl_get($url, $opts = array() ,$refresh_cookie = false){
     $ch = curl_init();
     curl_setopt($ch, CURLOPT_URL, $url);
     curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
     //curl_setopt($ch, CURLOPT_HTTPHEADER, array( 'Authorization: Client-ID ' . client_id ));
     curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
     curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 0); 
    curl_setopt($ch, CURLOPT_TIMEOUT, 120); //timeout in seconds

     if(is_array($opts) && count($opts)) curl_setopt_array($ch, $opts);
     //cookie
     if($refresh_cookie) {
          curl_setopt($ch, CURLOPT_COOKIESESSION, true);
     }
    
     $resp = curl_exec($ch);
     curl_close($ch);
     return $resp;
}
function hcgs_get_ad_param($n, $type) {
	if($type=='network') {
		$network = array(
			'g' => 'Google search',
			's' => 'search partner',
			'd' => 'Display Network',
			'c'=> 'Content'
		);
		return isset($network[$n])? $network[$n]: '';
	}
	if($type=='device') {
		$device = array(
			'c' => 'laptop computer/desktop',
			'm' => 'mobile',
			't'=>'tablet'
		);
		return isset($device[$n])? $device[$n]: '';
	}
	if($type=='matchtype') {
		$matchtype = array(
			'b' => 'broad match',
			'p' => 'phrase match',
			'e' => 'exact match',
			'c'=> 'Content network ads'
		);
		return isset($matchtype[$n])? $matchtype[$n]: '';
	}
	if($type=='adposition') {
		$arr=str_split($n);//1t2
		if(count($arr)>=3) {
			$pos ='page '.$arr[0].', ';
			if($arr[1]=='t') $pos.= 'top, ';
			else $pos.= $arr[1].', ';
			$pos.='pos '. $arr[2];
			return $pos;
		}
		
		return '';
	}
	return $n;
}

function hcgs_debug_backtrace_summary( $ignore_class = null, $skip_frames = 0, $pretty = true ) {
    if ( version_compare( PHP_VERSION, '5.2.5', '>=' ) )
        $trace = debug_backtrace( false );
    else
        $trace = debug_backtrace();
 
    $caller = array();
    $check_class = ! is_null( $ignore_class );
    $skip_frames++; // skip this function
 
    foreach ( $trace as $call ) {
        if ( $skip_frames > 0 ) {
            $skip_frames--;
        } elseif ( isset( $call['class'] ) ) {
            if ( $check_class && $ignore_class == $call['class'] )
                continue; // Filter out calls
 
            $caller[] = "{$call['class']}{$call['type']}{$call['function']}";
        } else {
            if ( in_array( $call['function'], array( 'do_action', 'apply_filters' ) ) ) {
                $caller[] = "{$call['function']}('{$call['args'][0]}')";
            } elseif ( in_array( $call['function'], array( 'include', 'include_once', 'require', 'require_once' ) ) ) {
                $caller[] = $call['function'] . "('" . str_replace( array( WP_CONTENT_DIR, ABSPATH ) , '', $call['args'][0] ) . "')";
            } else {
                $caller[] = $call['function'];
            }
        }
    }
    if ( $pretty )
        return join( ', ', array_reverse( $caller ) );
    else
        return $caller;
}

if( !function_exists('apache_request_headers') ) {
    function apache_request_headers() {
        $arh = array();
        $rx_http = '/\AHTTP_/';

        foreach($_SERVER as $key => $val) {
            if( preg_match($rx_http, $key) ) {
                $arh_key = preg_replace($rx_http, '', $key);
                $rx_matches = array();
           // do some nasty string manipulations to restore the original letter case
           // this should work in most cases
                $rx_matches = explode('_', $arh_key);

                if( count($rx_matches) > 0 and strlen($arh_key) > 2 ) {
                    foreach($rx_matches as $ak_key => $ak_val) {
                        $rx_matches[$ak_key] = ucfirst($ak_val);
                    }

                    $arh_key = implode('-', $rx_matches);
                }

                $arh[$arh_key] = $val;
            }
        }

        return( $arh );
    }
}
