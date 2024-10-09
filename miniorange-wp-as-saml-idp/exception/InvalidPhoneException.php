<?php
/**
 * This file contains the `InvalidPhoneException` class that defines
 * an exception when the user did not provide a valid phone number at
 * the time of user registration.
 *
 * @package miniorange-wp-as-saml-idp\exception
 */

namespace IDP\Exception;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPMessages;

/**
 * Exception denotes that the user did not provide a
 * valid phone number at the time of user registration.
 */
class InvalidPhoneException extends \Exception {


	/**
	 * Constructor function, which defines the `$code` and `$message` for
	 * the exception, and makes a call to the parent (`Exception`) constructor.
	 *
	 * @param string $phone Phone number user provided at the time of registration.
	 */
	public function __construct( $phone ) {
		$message = MoIDPMessages::show_message( 'ERROR_PHONE_FORMAT', array( 'phone' => $phone ) );
		$code    = 112;
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
