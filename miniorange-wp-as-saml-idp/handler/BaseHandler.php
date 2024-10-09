<?php
/**
 * This file contains the `BaseHandler` class that defines common methods
 * to check whether the incoming request is valid, and whether all the
 * required fields are present.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\RequiredFieldsException;
use IDP\Exception\SupportQueryRequiredFieldsException;
use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class defines common methods to check whether the
 * incoming requests are valid, and whether all required
 * fields are present. It is extended by other handler
 * classes to handle respective operations.
 */
class BaseHandler {

	/**
	 * Unique string to validate the authenticity of the
	 * HTTP requests, to prevent unauthorized operations.
	 *
	 * @var string $nonce
	 */
	public $nonce;

	/**
	 * Checks if the plugin has been installed and activated
	 * properly.
	 *
	 * @return boolean
	 */
	public function check_if_valid_plugin() {
		return true;
	}

	/**
	 * Checks whether the incoming request is valid or not,
	 * based on the capabilities of the current user, and
	 * the nonce field received. It will perform `wp_die()`
	 * if the validation fails.
	 *
	 * @return boolean
	 */
	public function is_valid_request() {
		if ( ! current_user_can( 'manage_options' ) || ! check_admin_referer( $this->nonce ) ) {
			wp_die( esc_html( MoIDPMessages::show_message( 'INVALID_OP' ) ) );
		}
		return true;
	}

	/**
	 * Checks if any variable in the array passed to this function
	 * has a null or empty value. This function is used to check for
	 * required fields.
	 *
	 * @param array $var_array Associative array, which lists all the variables to check, and the array to check in.
	 * @throws RequiredFieldsException Exception when certain fields are either missing or empty in a given form / array.
	 */
	public function check_if_required_fields_empty( $var_array ) {
		foreach ( $var_array as $key => $value ) {
			if (
				( is_array( $value ) && empty( $value[ $key ] ) )
				|| MoIDPUtility::is_blank( $value )
			) {
				throw new RequiredFieldsException();
			}
		}
	}

	/**
	 * Check if any required field for the support query form
	 * has a null or empty value. Uses the `check_if_required_fields_empty()`
	 * function.
	 *
	 * @param array $var_array Associative array, which lists all the variables to check, and the array to check in.
	 * @throws SupportQueryRequiredFieldsException Exception when the fields in the Support Query form are empty.
	 */
	public function check_if_support_query_fields_empty( $var_array ) {
		try {
			$this->check_if_required_fields_empty( $var_array );
		} catch ( RequiredFieldsException $e ) {
			throw new SupportQueryRequiredFieldsException();
		}
	}
}
