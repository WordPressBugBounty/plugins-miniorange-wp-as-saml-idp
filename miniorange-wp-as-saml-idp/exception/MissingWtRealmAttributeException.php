<?php
/**
 * This file contains the `MissingWtRealmAttributeException` class that defines
 * an exception when that the WS-FED request from the SP is missing the `wtrealm`
 * parameter.
 *
 * @package miniorange-wp-as-saml-idp\exception
 */

namespace IDP\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPMessages;

/**
 * Exception denotes that that the WS-FED request from the
 * SP is missing the `wtrealm` parameter.
 */
class MissingWtRealmAttributeException extends \Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 */
	public function __construct() {
		$message = MoIDPMessages::show_message( 'MISSING_WTREALM_ATTR' );
		$code    = 128;
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
