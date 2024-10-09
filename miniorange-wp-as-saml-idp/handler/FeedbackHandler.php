<?php
/**
 * This file contains the `FeedbackHandler` class that is responsible
 * for processing the deactivation feedback operation by making an API
 * call to the miniOrange servers.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPcURL;

/**
 * This class extends the `BaseHandler` class and contains methods
 * to process the deactivation feedback operation.
 */
final class FeedbackHandler extends BaseHandler {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->nonce = 'mo_idp_feedback';
	}

	/**
	 * Function to process the deactivation feedback operation. It initially checks
	 * whether the request is valid, and then proceeds to make an API call to miniOrange
	 * server (`/notify` endpoint) to process the deactivation feedback.
	 * The function also checks whether the user had opted to preserve the
	 * SSO configuration, and accordingly updates an option in the database.
	 * It finally deactivates the plugin.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @return void
	 */
	public function mo_send_feedback( $sanitized_post ) {
		$this->is_valid_request();
		$submit_type  = $sanitized_post['miniorange_feedback_submit'];
		$feedback     = sanitize_textarea_field( $sanitized_post['idp_query_feedback'] );
		$rating_value = sanitize_text_field( $sanitized_post['idp_rate'] );
		$email_value  = sanitize_email( $sanitized_post['idp_email'] );

		$keep_settings_intact = isset( $sanitized_post['idp_keep_settings_intact'] );
		$is_reply_required    = isset( $sanitized_post['idp_dnd'] );

		if ( $keep_settings_intact ) {
			update_site_option( 'idp_keep_settings_intact', true );
		} else {
			update_site_option( 'idp_keep_settings_intact', false );
		}
		if ( 'Skip & Deactivate' !== $submit_type ) {
			$this->send_email( $this->render_email( $feedback, $rating_value, $email_value, $is_reply_required ) ); // render and send deactivation feedback email.
		}

		deactivate_plugins( array( MSI_PLUGIN_NAME ) );

		if ( headers_sent() ) {
			echo "<meta http-equiv='refresh' content='" . esc_attr( '0;url=plugins.php?deactivate=true&plugin_status=all&paged=1&s=' ) . "' />";
		} else {
			wp_safe_redirect( self_admin_url( 'plugins.php?deactivate=true&plugin_status=all&paged=1&s=' ) );
		}
	}

	/**
	 * Function builds the content for the email to be submitted.
	 * It reads the local email template, and replaces the fields
	 * as per the input from the user.
	 *
	 * @param string  $message Feedback message added by user.
	 * @param string  $rating Ratings submitted between 1 and 5.
	 * @param string  $email Email of the user.
	 * @param boolean $is_reply_required Flag indicating whether the user wants to be contacted by miniOrange support.
	 * @return string
	 */
	private function render_email( $message, $rating, $email, $is_reply_required = true ) {
		// phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents -- Reading the email template from local file.
		$feedback_template = file_get_contents( MSI_DIR . 'includes/html/emailtemplate.min.html' );
		$server_name       = ! empty( $_SERVER['SERVER_NAME'] ) ? esc_url_raw( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : home_url();

		$feedback_template = str_replace( '{{SERVER}}', $server_name, $feedback_template );
		$feedback_template = str_replace( '{{EMAIL}}', $email, $feedback_template );
		$feedback_template = str_replace( '{{PLUGIN}}', MoIDPConstants::AREA_OF_INTEREST, $feedback_template );
		$feedback_template = str_replace( '{{VERSION}}', MSI_VERSION, $feedback_template );
		$feedback_template = str_replace( '{{TYPE}}', '[Plugin Deactivated]', $feedback_template );
		$feedback_template = str_replace( '{{QUERY}}', 'Feedback : ' . $message, $feedback_template );
		if ( ! $is_reply_required ) {
			$feedback_template = str_replace( '{{RATING}}', 'Rating : ' . $rating . ' [Do Not Reply]', $feedback_template );
		} else {
			$feedback_template = str_replace( '{{RATING}}', 'Rating : ' . $rating, $feedback_template );
		}
		return $feedback_template;
	}


	/**
	 * Function responsible for making an API call to the `/notify`
	 * endpoint to process the deactivation feedback operation.
	 * It uses the `notify()` function to make the API call.
	 * It will return `false` if the API call fails.
	 *
	 * @param string $content Email body to be submitted in the API request.
	 */
	private function send_email( $content ) {
		$customer_key = get_site_option( 'mo_idp_admin_customer_key' );
		$api_key      = get_site_option( 'mo_idp_admin_api_key' );
		MoIDPcURL::notify(
			! $customer_key ? MoIDPConstants::DEFAULT_CUSTOMER_KEY : $customer_key,
			! $api_key ? MoIDPConstants::DEFAULT_API_KEY : $api_key,
			MoIDPConstants::WPIDPSUPPORT_EMAIL,
			$content,
			'WordPress IDP Plugin Deactivated'
		);
	}
}
