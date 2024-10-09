<?php
/**
 * This file contains the `MoIDPcURL` utility class that is responsible
 * for carrying out all REST API calls to miniOrange servers.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;

/**
 * This class handles cURL calls to miniOrange servers.
 */
class MoIDPcURL {

	/**
	 * This function makes a cURL call to the `/customer/add`
	 * endpoint to create a new customer account.
	 *
	 * @param string $email Email of the user.
	 * @param string $password Password of the user.
	 * @return string
	 */
	public static function create_customer( $email, $password ) {
		$url          = MoIDPConstants::HOSTNAME . '/moas/rest/customer/add';
		$customer_key = MoIDPConstants::DEFAULT_CUSTOMER_KEY;
		$api_key      = MoIDPConstants::DEFAULT_API_KEY;
		$fields       = array(
			'areaOfInterest' => MoIDPConstants::AREA_OF_INTEREST,
			'email'          => $email,
			'password'       => $password,
		);
		$json         = wp_json_encode( $fields );
		$auth_header  = self::create_auth_header( $customer_key, $api_key );
		$response     = self::call_api( $url, $json, $auth_header );
		return $response;
	}

	/**
	 * This function makes a cURL call to the `/customer/key`
	 * endpoint to retrieve the customer object that contains
	 * `id`, `apiKey` and `token`.
	 *
	 * @param string $email Email of the user.
	 * @param string $password Password of the user.
	 * @return string
	 */
	public static function get_customer_key( $email, $password ) {
		$url          = MoIDPConstants::HOSTNAME . '/moas/rest/customer/key';
		$customer_key = MoIDPConstants::DEFAULT_CUSTOMER_KEY;
		$api_key      = MoIDPConstants::DEFAULT_API_KEY;
		$fields       = array(
			'email'    => $email,
			'password' => $password,
		);
		$json         = wp_json_encode( $fields );
		$auth_header  = self::create_auth_header( $customer_key, $api_key );
		$response     = self::call_api( $url, $json, $auth_header );
		return $response;
	}

	/**
	 * This function makes a cURL call to the `/customer/contact-us`
	 * endpoint to submit a query from the support form.
	 *
	 * @param string $q_email Email of the user.
	 * @param string $q_phone Phone number of the user.
	 * @param string $query Support query message body.
	 * @return boolean
	 */
	public static function submit_contact_us( $q_email, $q_phone, $query ) {
		$current_user = wp_get_current_user();
		$url          = MoIDPConstants::HOSTNAME . '/moas/rest/customer/contact-us';
		$query        = '[WP IDP Free Plugin - ' . MSI_VERSION . ']: ' . $query;
		$customer_key = ! MoIDPUtility::is_blank( get_site_option( 'mo_idp_admin_customer_key' ) )
						? get_site_option( 'mo_idp_admin_customer_key' ) : MoIDPConstants::DEFAULT_CUSTOMER_KEY;
		$api_key      = ! MoIDPUtility::is_blank( get_site_option( 'mo_idp_admin_customer_key' ) )
						? get_site_option( 'mo_idp_admin_customer_key' ) : MoIDPConstants::DEFAULT_API_KEY;
		$server_name  = ! empty( $_SERVER['SERVER_NAME'] ) ? esc_url_raw( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : home_url();
		$fields       = array(
			'firstName' => $current_user->user_firstname,
			'lastName'  => $current_user->user_lastname,
			'company'   => $server_name,
			'email'     => $q_email,
			'ccEmail'   => 'wpidpsupport@xecurify.com',
			'phone'     => $q_phone,
			'query'     => $query,
		);
		$json         = wp_json_encode( $fields );
		$auth_header  = self::create_auth_header( $customer_key, $api_key );
		self::call_api( $url, $json, $auth_header );
		return true;
	}

	/**
	 * This function makes a cURL call to the `/notify/send`
	 * endpoint to submit notifications from the plugin e.g.
	 * deactivation notification, demo request notification.
	 *
	 * @param string $customer_key Refers to the customer ID.
	 * @param string $api_key Refers to the API key.
	 * @param string $to_email Refers to the recipient of the email.
	 * @param string $content Refers to the body of the email.
	 * @param string $subject Refers to the subject of the email.
	 * @return string
	 */
	public static function notify( $customer_key, $api_key, $to_email, $content, $subject ) {
		$url = MoIDPConstants::HOSTNAME . '/moas/api/notify/send';

		$fields      = array(
			'customerKey' => $customer_key,
			'sendEmail'   => true,
			'email'       => array(
				'customerKey' => $customer_key,
				'fromEmail'   => MoIDPConstants::FEEDBACK_FROM_EMAIL,
				'bccEmail'    => MoIDPConstants::FEEDBACK_FROM_EMAIL,
				'fromName'    => 'miniOrange',
				'toEmail'     => MoIDPConstants::WPIDPSUPPORT_EMAIL,
				'toName'      => MoIDPConstants::WPIDPSUPPORT_EMAIL,
				'subject'     => $subject,
				'content'     => $content,
			),
		);
		$json        = wp_json_encode( $fields );
		$auth_header = self::create_auth_header( $customer_key, $api_key );
		return self::call_api( $url, $json, $auth_header );
	}

	/**
	 * This function makes a cURL call to the `/auth/challenge`
	 * endpoint to generate an OTP token and send it to the
	 * user's email or phone.
	 *
	 * @param string $auth_type Refers to the type of OTP (over Email / Phone) to send.
	 * @param string $phone Refers to the user's phone number.
	 * @param string $email Refers to the user's email.
	 * @return string
	 */
	public static function send_otp_token( $auth_type, $phone, $email ) {
		$url          = MoIDPConstants::HOSTNAME . '/moas/api/auth/challenge';
		$customer_key = MoIDPConstants::DEFAULT_CUSTOMER_KEY;
		$api_key      = MoIDPConstants::DEFAULT_API_KEY;

		$fields      = array(
			'customerKey'     => $customer_key,
			'email'           => $email,
			'phone'           => $phone,
			'authType'        => $auth_type,
			'transactionName' => MoIDPConstants::AREA_OF_INTEREST,
		);
		$json        = wp_json_encode( $fields );
		$auth_header = self::create_auth_header( $customer_key, $api_key );
		$response    = self::call_api( $url, $json, $auth_header );
		return $response;
	}

	/**
	 * This function makes a cURL call to the `/auth/validate`
	 * endpoint to validate the OTP token entered by the user.
	 *
	 * @param string $transaction_id Refers to the transaction ID.
	 * @param string $otp_token Refers to the OTP entered by the user.
	 * @return string
	 */
	public static function validate_otp_token( $transaction_id, $otp_token ) {
		$url          = MoIDPConstants::HOSTNAME . '/moas/api/auth/validate';
		$customer_key = MoIDPConstants::DEFAULT_CUSTOMER_KEY;
		$api_key      = MoIDPConstants::DEFAULT_API_KEY;
		$fields       = array(
			'txId'  => $transaction_id,
			'token' => $otp_token,
		);
		$json         = wp_json_encode( $fields );
		$auth_header  = self::create_auth_header( $customer_key, $api_key );
		$response     = self::call_api( $url, $json, $auth_header );
		return $response;
	}

	/**
	 * This function makes a cURL call to the `/customer/check-if-exists`
	 * endpoint to check if a customer account exists with the entered
	 * email address.
	 *
	 * @param string $email Refers to the email of the user.
	 * @return string
	 */
	public static function check_customer( $email ) {
		$url          = MoIDPConstants::HOSTNAME . '/moas/rest/customer/check-if-exists';
		$customer_key = MoIDPConstants::DEFAULT_CUSTOMER_KEY;
		$api_key      = MoIDPConstants::DEFAULT_API_KEY;
		$fields       = array(
			'email' => $email,
		);
		$json         = wp_json_encode( $fields );
		$auth_header  = self::create_auth_header( $customer_key, $api_key );
		$response     = self::call_api( $url, $json, $auth_header );
		return $response;
	}

	/**
	 * This function makes a cURL call to the `/customer/password-reset`
	 * endpoint to send a password reset email to the customer's registered
	 * email address.
	 *
	 * @param string $email Refers to the customer's registered email address.
	 * @param string $customer_key Refers to the customer ID.
	 * @param string $api_key Refers to the API key.
	 * @return string
	 */
	public static function forgot_password( $email, $customer_key, $api_key ) {
		$url         = MoIDPConstants::HOSTNAME . '/moas/rest/customer/password-reset';
		$fields      = array(
			'email' => $email,
		);
		$json        = wp_json_encode( $fields );
		$auth_header = self::create_auth_header( $customer_key, $api_key );
		$response    = self::call_api( $url, $json, $auth_header );
		return $response;
	}

	/**
	 * This function is responsible for creating the authorization
	 * header for the cURL calls.
	 *
	 * @param string $customer_key Refers to the customer ID.
	 * @param string $api_key Refers to the API key.
	 * @return string
	 */
	private static function create_auth_header( $customer_key, $api_key ) {
		$current_timestamp_in_millis = round( microtime( true ) * 1000 );
		$current_timestamp_in_millis = number_format( $current_timestamp_in_millis, 0, '', '' );

		$string_to_hash = $customer_key . $current_timestamp_in_millis . $api_key;
		$auth_header    = hash( 'sha512', $string_to_hash );

		$header = array(
			'Content-Type'  => 'application/json',
			'Customer-Key'  => $customer_key,
			'Timestamp'     => $current_timestamp_in_millis,
			'Authorization' => $auth_header,
		);
		return $header;
	}

	/**
	 *  Uses WordPress HTTP API to make cURL calls to miniOrange server
	 *  <br/>Arguments that you can pass
	 * <ol>
	 *  <li>'timeout'     => 5,</li>
	 *  <li>'redirection' => 5,</li>
	 *  <li>'httpversion' => '1.0',</li>
	 *  <li>'user-agent'  => 'WordPress/' . $wp_version . '; ' . home_url(),</li>
	 *  <li>'blocking'    => true,</li>
	 *  <li>'headers'     => array(),</li>
	 *  <li>'cookies'     => array(),</li>
	 *  <li>'body'        => null,</li>
	 *  <li>'compress'    => false,</li>
	 *  <li>'decompress'  => true,</li>
	 *  <li>'sslverify'   => true,</li>
	 *  <li>'stream'      => false,</li>
	 *  <li>'filename'    => null</li>
	 * </ol>
	 *
	 * @param string $url           URL to post to.
	 * @param string $json_string   json encoded post data.
	 * @param array  $headers       headers to be passed in the call.
	 * @return string
	 */
	private static function call_api( $url, $json_string, $headers = array( 'Content-Type' => 'application/json' ) ) {
		$args = array(
			'method'      => 'POST',
			'body'        => $json_string,
			'timeout'     => '10000',
			'redirection' => '10',
			'httpversion' => '1.0',
			'blocking'    => true,
			'headers'     => $headers,
			'sslverify'   => MSI_TEST ? false : true,
		);

		$response = wp_remote_post( $url, $args );

		if ( is_wp_error( $response ) ) {
			wp_die( wp_kses( "Something went wrong: <br/> {$response->get_error_message()}", array( 'br' => array() ) ) );
		}
		return wp_remote_retrieve_body( $response );
	}
}
