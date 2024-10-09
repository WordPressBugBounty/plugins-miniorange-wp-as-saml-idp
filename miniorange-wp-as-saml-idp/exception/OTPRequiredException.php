<?php
/**
 * This file contains the `OTPRequiredException` class that defines
 * an exception when the the user has not entered OTP for validation.
 *
 * @package miniorange-wp-as-saml-idp\exception
 */

namespace IDP\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPMessages;

/**
 * Exception denotes that the user has not entered
 * OTP for validation.
 */
class OTPRequiredException extends \Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 */
	public function __construct() {
		$message = MoIDPMessages::show_message( 'REQUIRED_OTP' );
		$code    = 113;
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
