<?php
/**
 * This file contains the `IssuerValueAlreadyInUseException` class that defines
 * an exception when the Issuer value entered by the admin for a Service
 * Provider is already in use.
 *
 * @package miniorange-wp-as-saml-idp\exception
 */

namespace IDP\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPMessages;

/**
 * Exception denotes that the Issuer value entered by
 * the admin for a Service Provider is already in use.
 */
class IssuerValueAlreadyInUseException extends \Exception {

	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param object $sp Service Provider config object.
	 */
	public function __construct( $sp ) {
		$message = MoIDPMessages::show_message( 'ISSUER_EXISTS', array( 'name' => $sp->mo_idp_sp_name ) );
		$code    = 106;
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
