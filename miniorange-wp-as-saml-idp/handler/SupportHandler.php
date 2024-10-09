<?php
/**
 * This file contains the `SupportHandler` class that is responsible
 * for processing the support query request by making an API call to
 * the miniOrange servers.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\SupportQueryRequiredFieldsException;
use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `BaseHandler` class and contains methods
 * to process the support query requests.
 */
final class SupportHandler extends BaseHandler {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->nonce = 'mo_idp_support_handler';
	}

	/**
	 * Function to process the support query request. It checks whether the
	 * request is valid, and whether all the required fields are present.
	 * It will then make an API call to miniOrange server (`/contact-us` endpoint)
	 * to process the support query request.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws SupportQueryRequiredFieldsException Exception when the fields in the Support Query form are empty.
	 */
	public function mo_idp_support_query( $sanitized_post ) {
		$this->is_valid_request();
		$this->check_if_support_query_fields_empty(
			array(
				'mo_idp_contact_us_email' => $sanitized_post,
				'mo_idp_contact_us_query' => $sanitized_post,
			)
		);

		$email = sanitize_email( $sanitized_post['mo_idp_contact_us_email'] );
		$phone = sanitize_text_field( $sanitized_post['mo_idp_contact_us_phone'] );
		$query = sanitize_textarea_field( $sanitized_post['mo_idp_contact_us_query'] );

		if ( ! empty( $sanitized_post['mo_idp_upgrade_plan_name'] ) ) {
			$plan_name  = sanitize_text_field( $sanitized_post['mo_idp_upgrade_plan_name'] );
			$plan_users = sanitize_text_field( $sanitized_post['mo_idp_upgrade_plan_users'] );
			$query      = 'Plan Name : ' . $plan_name . ', Users : ' . $plan_users . ', ' . $query;
		}

		$submitted = MoIdpUtility::submit_contact_us( $email, $phone, $query );

		if ( false === $submitted ) {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'ERROR_QUERY' ), 'ERROR' );
		} else {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'QUERY_SENT' ), 'SUCCESS' );
		}
	}
}
