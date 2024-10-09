<?php
/**
 * This file contains the `DemoRequestHandler` class that is responsible
 * for processing the demo request operation by making an API call to the
 * miniOrange servers.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\SupportQueryRequiredFieldsException;
use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPcURL;

/**
 * This class extends the `BaseHandler` class and contains methods
 * to process the demo request operation.
 */
class DemoRequestHandler extends BaseHandler {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->nonce = 'mo_idp_demo_request';
	}

	/**
	 * Function to process the demo request operation. It checks whether the
	 * request is valid and whether all the required fields are present.
	 * It will then make an API call to miniOrange server (`/notify` endpoint)
	 * to process the demo request.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws SupportQueryRequiredFieldsException Exception when the required fields in the Demo Request form are missing / empty.
	 */
	public function mo_idp_demo_request_function( $sanitized_post ) {
		$this->is_valid_request();
		$this->check_if_support_query_fields_empty(
			array(
				'mo_idp_demo_email'       => $sanitized_post,
				'mo_idp_demo_description' => $sanitized_post,
			)
		);
		$email = sanitize_email( ( $sanitized_post['mo_idp_demo_email'] ) );
		$query = sanitize_textarea_field( $sanitized_post['mo_idp_demo_description'] );

		$submitted = $this->send_email( $this->render_email( $query, $email ) );

		if ( false === $submitted ) {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'ERROR_QUERY' ), 'ERROR' );
		} else {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'QUERY_SENT' ), 'SUCCESS' );
		}
	}

	/**
	 * Function builds the content for the email to be submitted.
	 * It reads the local email template, and replaces the fields
	 * as per the input from the user.
	 *
	 * @param string $message Requirements or description added by user in the Demo Request form.
	 * @param string $email Email of the user.
	 * @return string
	 */
	private function render_email( $message, $email ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading the email template from local file.
		$demo_request_template = file_get_contents( MSI_DIR . 'includes/html/emailtemplate.min.html' );
		$server_name           = ! empty( $_SERVER['SERVER_NAME'] ) ? esc_url_raw( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : home_url();

		$demo_request_template = str_replace( '{{SERVER}}', $server_name, $demo_request_template );
		$demo_request_template = str_replace( '{{EMAIL}}', $email, $demo_request_template );
		$demo_request_template = str_replace( '{{PLUGIN}}', MoIDPConstants::AREA_OF_INTEREST, $demo_request_template );
		$demo_request_template = str_replace( '{{VERSION}}', MSI_VERSION, $demo_request_template );
		$demo_request_template = str_replace( '{{TYPE}}', '[Request a Demo]', $demo_request_template );
		$demo_request_template = str_replace( '{{QUERY}}', 'Requirements : ' . $message, $demo_request_template );
		$demo_request_template = str_replace( '{{RATING}}', '', $demo_request_template );

		return $demo_request_template;
	}

	/**
	 * Function responsible for making an API call to the `/notify`
	 * endpoint to process the demo request operation. It uses the
	 * `notify()` function to make the API call.
	 * It will return `false` if the API call fails.
	 *
	 * @param string $content Email body to be submitted in the API request.
	 * @return boolean
	 */
	private function send_email( $content ) {
		$customer_key = get_site_option( 'mo_idp_admin_customer_key' );
		$api_key      = get_site_option( 'mo_idp_admin_api_key' );
		return MoIDPcURL::notify(
			! $customer_key ? MoIDPConstants::DEFAULT_CUSTOMER_KEY : $customer_key,
			! $api_key ? MoIDPConstants::DEFAULT_API_KEY : $api_key,
			MoIDPConstants::WPIDPSUPPORT_EMAIL,
			$content,
			'Request a Demo : ' . MoIDPConstants::AREA_OF_INTEREST
		);
	}
}
