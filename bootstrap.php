<?php
define('HCGS_MIN_PHP_VERSION', '5.6.0');
//define('DOING_AJAX', true);	//comment it for debug error

include_once (__DIR__.'/libs/config.php');

if(hcgs_isSSL()) {
	define('HCGS_MANAGER', 'https://clickgumshoe.com/');	//https://hoangweb-ads-manager.herokuapp.com/
}
else {
	if(HCGS_TEST_MODE) define('HCGS_MANAGER', 'http://localhost:82');	//test
	else define('HCGS_MANAGER', 'https://clickgumshoe.com/');	//http://hoangweb-ads-manager.herokuapp.com/
}
do_action('init');

if (isset( $_REQUEST['action']) && (HCGS_TEST_MODE || hcgs_is_ajax())) {
    //die('-1');

    header( "Content-Type: application/json" );
    send_nosniff_header();

    //Disable caching
    header('Cache-Control: no-cache');
    header('Pragma: no-cache');

    $action = /*esc_attr*/(trim($_REQUEST['action']));	//remove `action` to `_action`
    if(function_exists('cgs_load')) cgs_load();

    //A bit of security
    $allowed_actions = array(
        'hcgs_lock_submit',
        'hcgs_save_userdata',
        'hcgs_lock_debug',
        'hcgs_lock_reset_db',
        'hcgs_lock_clearsesison',
        'hcgs_lock_page_times',
        'hcgs_lock_rmmap'
    );

    $prefix = 'wp_ajax_';	//HW_
    //execution
    if(in_array($action, $allowed_actions)) {
        if(!function_exists('is_user_logged_in') || is_user_logged_in()) {
            do_action($prefix. $action);
        }
        else {
            do_action($prefix.'nopriv_'.$action);
        }
    } else {
        die('-1');
    }
    die();
}