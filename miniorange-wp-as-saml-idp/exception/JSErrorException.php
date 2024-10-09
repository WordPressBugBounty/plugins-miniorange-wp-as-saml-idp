<?php
/**
 * This file contains the `JSErrorException` class that defines
 * an exception when there was ErrorMessage set during JS validation.
 *
 * @package miniorange-wp-as-saml-idp\exception
 */

namespace IDP\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Exception denotes that there was ErrorMessage set during JS validation.
 */
class JSErrorException extends \Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $message The error message set during JS validation.
	 */
	public function __construct( $message ) {
		$message = $message;
		$code    = 103;
		parent::__construct( $message, $code, null );
	}

	/**
	 * Returns the string representation of the exception,
	 * with exception code and the error message.
	 *
	 * @return string
	 */
	public function __toString() {
		return __CLASS__ . ": [{$this->code}]: {$this->message}\n";
	}
}
