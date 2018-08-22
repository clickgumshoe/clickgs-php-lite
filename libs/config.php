<?php
define( "HCGS_DEBUGGING", 0 ); // or false in production enviroment
define("HCGS_TEST_MODE", 0);

include_once __DIR__.'/vendor/autoload.php';
if(!function_exists('add_action')) require_once __DIR__.'/classes/php-hooks.php';
include_once (__DIR__.'/classes/css.php');
include_once (__DIR__.'/classes/ws.php');
include_once (__DIR__.'/classes/Medoo.php');
include_once (__DIR__.'/classes/cache.php');
include_once (__DIR__.'/classes/shutdown_exception.php');

include_once (__DIR__.'/utils.php');
include_once (__DIR__.'/functions.php');