<?php
/**
 *@class HCGS_ExceptionHandler
*/
class HCGS_ExceptionHandler {
	function catch_error( $error=null, $title='Error in adwords server') {
		if(!$error) $error = error_get_last();
		if (/*!$error ||*/ (is_array($error) && !in_array($error['type'], array (E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR)))) {
			return "invoke `catch_error` function but not found error.\n";
		}
		else if($error){
			if(is_array($error)) {
				$code = $error['type'] ;
				$message = $error['message'];
				$file = $error['file'];
				$line = $error['line'];
						
				$msg = $message . ' in <b>' . $file . '</b> on line <b>' . $line . '</b>';
			}
			else $msg = $error;
			//backtrace
			$backtrace = hcgs_debug_backtrace_summary(debug_backtrace());
			echo '^',$msg,' - ',$backtrace,"\n";
			
			//fire hook
			do_action('error_log_event', $msg, $backtrace);
			
			return $msg;
		}

	}
	function as_shutdown()
	{
		$error = $this->catch_error(null, 'Adwords server crashed');

		//echo 'crashed! [', $error,"]\n";
		// send_notification(array('title'=>'Adwords server crashed','message'=> 'Adwords server crashed! It will restart now.','sound'=>'falling'));
	}
	/**
	 * called for caught exceptions
	 * @param  Exception $e
	 * @return null
	 */
	function as_exception_handler($e){
		$msg = 'Error('.$e->getCode().') '. $e->getMessage().' in '. $e->getFile().':'. $e->getLine();
		$this->catch_error($msg, 'Adwords server crashed');
	}
	/**
	 * called for php errors
	 *
	 * @param int $errno
	 * @param string $errstr
	 * @param string $errfile
	 * @param string $errline
	 * @return null
	 */
	function as_error_handler($errno, $errstr, $errfile, $errline){
		$msg = 'Error('.$errno.') '.$errstr.' in '. $errfile.':'. $errline;
		$this->catch_error( $msg, 'Adwords server crashed');
	}

	function __construct() {
		register_shutdown_function(array($this, 'as_shutdown'));
		//set_error_handler(array($this, 'as_error_handler'));	//not working with workerman
		set_exception_handler(array($this, 'as_exception_handler'));
	}
}
new HCGS_ExceptionHandler;