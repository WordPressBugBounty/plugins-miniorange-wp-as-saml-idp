<?php
/**
 * This file contains the `InvalidNumberOfNameIDsException` class that defines
 * an exception when the request or response has more than 1 NameID.
 *
 * @package miniorange-wp-as-saml-idp\exception
 */

namespace IDP\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPMessages;

/**
 * Exception denotes that the request or response has more
 * than 1 NameID.
 */
class InvalidNumberOfNameIDsException extends \Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 */
	public function __construct() {
		$message = MoIDPMessages::show_message( 'INVALID_NO_OF_NAMEIDS' );
		$code    = 124;
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
