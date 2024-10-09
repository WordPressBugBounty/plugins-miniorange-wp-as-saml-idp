<?php
/**
 * This file contains the `RegistrationHandler` class that is responsible
 * for processing user registration.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidPhoneException;
use IDP\Exception\OTPRequiredException;
use IDP\Exception\OTPSendingFailedException;
use IDP\Exception\OTPValidationFailedException;
use IDP\Exception\PasswordMismatchException;
use IDP\Exception\PasswordResetFailedException;
use IDP\Exception\PasswordStrengthException;
use IDP\Exception\RegistrationRequiredFieldsException;
use IDP\Exception\RequiredFieldsException;
use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `RegistrationUtility` class and
 * handles all the user registration related functionality.
 */
final class RegistrationHandler extends RegistrationUtility {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->nonce = 'reg_handler';
	}

	/**
	 * This function processes and handles the registration
	 * form submitted by the user. It uses the `check_customer()`
	 * function to check whether a customer already exists using
	 * the email entered by the user. If it already exists, it
	 * uses the `get_current_customer()` function to fetch the
	 * details of the existing customer. Otherwise, it creates a
	 * new account using the `create_user_without_verification()`
	 * function.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws PasswordMismatchException Exception when the password and confirm password fields do not match.
	 * @throws PasswordStrengthException Exception when user password length is less than 6.
	 * @throws RegistrationRequiredFieldsException Exception when the user email and password are missing during user registration.
	 */
	public function idp_register_customer( array $sanitized_post ) {
		$this->is_valid_request();

		// validate and sanitize.
		$email            = sanitize_email( $sanitized_post['email'] );
		$password         = sanitize_text_field( $sanitized_post['password'] );
		$confirm_password = sanitize_text_field( $sanitized_post['confirmPassword'] );

		$this->check_if_reg_req_fields_empty( array( $email, $password, $confirm_password ) );
		$this->check_pwd_strength( $password, $confirm_password );
		$this->pwd_and_cnfrm_pwd_match( $password, $confirm_password );

		update_site_option( 'mo_idp_admin_email', $email );
		update_site_option( 'mo_idp_admin_password', $password );

		$content = json_decode( MoIDPUtility::check_customer(), true );

		switch ( $content['status'] ) {
			case 'CUSTOMER_NOT_FOUND':
				$this->create_user_without_verification( $email, $password );
				break;
			default:
				$this->get_current_customer( $email, $password );
				break;
		}
	}

	/**
	 * This function handles sending OTP to a
	 * user's phone number to validate himself.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws InvalidPhoneException Exception when the phone number entered by the user does not match the pattern in const PATTERN_PHONE.
	 * @throws OTPSendingFailedException Exception when the API call to send the OTP fails.
	 *
	 * @deprecated since 1.10.9
	 */
	public function mo_idp_phone_verification( array $sanitized_post ) {
		$this->is_valid_request();

		$phone = sanitize_text_field( $sanitized_post['phone_number'] );
		$phone = str_replace( ' ', '', $phone );

		$this->is_valid_phone_number( $phone );
		update_site_option( 'mo_customer_validation_admin_phone', $phone );
		$this->send_otp_token( '', $phone, 'SMS' );
	}

	/**
	 * This function saves the customer details in the
	 * database after registration is complete.
	 *
	 * @param string $id Refers to the customer key or ID.
	 * @param string $api_key Refers to the api token of the customer.
	 * @param string $token Refers to the token of the customer.
	 * @param string $app_secret Refers to the app secret of the customer.
	 * @return void
	 */
	public function save_success_customer_config( $id, $api_key, $token, $app_secret ) {
		update_site_option( 'mo_idp_admin_customer_key', $id );
		update_site_option( 'mo_idp_admin_api_key', $api_key );
		update_site_option( 'mo_idp_customer_token', $token );
		delete_site_option( 'mo_idp_verify_customer' );
		delete_site_option( 'mo_idp_new_registration' );
		delete_site_option( 'mo_idp_admin_password' );
		delete_site_option( 'mo_idp_registration_status' );
	}

	/**
	 * This function handles going back to the registration
	 * form / page. It deletes and updates all the relevant
	 * database entries to facilitate registration again.
	 *
	 * @return void
	 */
	public function mo_idp_go_back() {
		$this->is_valid_request();

		delete_site_option( 'mo_idp_transactionId' );
		delete_site_option( 'mo_idp_admin_password' );
		delete_site_option( 'mo_idp_registration_status' );
		delete_site_option( 'mo_idp_admin_phone' );
		delete_site_option( 'mo_idp_new_registration' );
		delete_site_option( 'mo_idp_admin_customer_key' );
		delete_site_option( 'mo_idp_admin_api_key' );
		delete_site_option( 'mo_idp_admin_email' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function.
		if ( ( ! empty( $_POST['option'] ) ? sanitize_text_field( wp_unslash( $_POST['option'] ) ) : '' ) === 'remove_idp_account' ) {
			delete_site_option( 'sml_idp_lk' );
			delete_site_option( 't_site_status' );
			delete_site_option( 'site_idp_ckl' );
		}
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function.
		update_site_option( 'mo_idp_verify_customer', sanitize_text_field( wp_unslash( $_POST['option'] ) ) === 'remove_idp_account' );
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function.
		update_site_option( 'mo_idp_new_registration', sanitize_text_field( wp_unslash( $_POST['option'] ) ) === 'mo_idp_go_back' );
		wp_safe_redirect( mo_idp_get_registration_url() );
	}

	/**
	 * This function sends a reset password API call
	 * to the server to reset the password of the admin.
	 *
	 * @throws PasswordResetFailedException Exception when the password reset was unsuccessful.
	 */
	public function mo_idp_forgot_password() {
		$this->is_valid_request();

		$email   = get_site_option( 'mo_idp_admin_email' );
		$content = json_decode( MoIDPUtility::forgot_password( $email ), true );
		$this->check_if_password_reset_successfully( $content, 'status' );
		do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'PASS_RESET' ), 'SUCCESS' );
	}

	/**
	 * This function handles validating an existing user.
	 * It uses the `get_current_customer()` to process the
	 * login form.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws RequiredFieldsException Exception when the user email and password are missing during user registration.
	 */
	public function mo_idp_verify_customer( array $sanitized_post ) {
		$this->is_valid_request();

		$email    = sanitize_email( $sanitized_post['email'] );
		$password = sanitize_text_field( $sanitized_post['password'] );
		$this->check_if_required_fields_empty( array( $email, $password ) );
		$this->get_current_customer( $email, $password );
	}

	/**
	 * This function handles sending OTPs to a person's email
	 * or phone number for verification. It uses the
	 * `send_otp_token()` function to send the OTP.
	 *
	 * @param string $email Refers to the email entered by the user.
	 * @param string $phone Refers to the phone number entered by the user.
	 * @param string $auth_type Refers to the type of OTP (over Email / Phone) to send.
	 * @throws OTPSendingFailedException Exception when the API call to send the OTP fails.
	 *
	 * @deprecated since 1.10.9
	 */
	public function send_otp_token( $email, $phone, $auth_type ) {
		$this->is_valid_request();

		$content = json_decode( MoIDPUtility::send_otp_token( $auth_type, $email, $phone ), true );
		$this->check_if_otp_sent_successfully( $content, 'status' );

		update_site_option( 'mo_idp_transactionId', $content['txId'] );
		update_site_option( 'mo_idp_registration_status', 'MO_OTP_DELIVERED_SUCCESS' );
		if ( 'EMAIL' === $auth_type ) {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'EMAIL_OTP_SENT', array( 'email' => $email ) ), 'SUCCESS' );
		} else {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'PHONE_OTP_SENT', array( 'phone' => $phone ) ), 'SUCCESS' );
		}
	}

	/**
	 * This function handles getting existing customer based on the
	 * user's email and password. It uses the `get_customer_key()`
	 * function to fetch the customer details.
	 *
	 * @param string $email Refers to the email entered by the user.
	 * @param string $password Refers to the password entered by the user.
	 * @return void
	 */
	public function get_current_customer( $email, $password ) {
		$content      = MoIdpUtility::get_customer_key( $email, $password );
		$customer_key = json_decode( $content, true );

		if ( JSON_ERROR_NONE === json_last_error() ) {
			update_site_option( 'mo_idp_admin_email', $email );
			$this->save_success_customer_config( $customer_key['id'], $customer_key['apiKey'], $customer_key['token'], $customer_key['appSecret'] );
		} else {
			update_site_option( 'mo_idp_verify_customer', true );
			delete_site_option( 'mo_idp_new_registration' );
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'ACCOUNT_EXISTS' ), 'ERROR' );
		}
	}

	/**
	 * This function handles validating OTP entered by the user.
	 * If the OTP validation passes, it proceeds to create a new
	 * customer account.
	 * It uses the `validate_otp_token()` function to validate the
	 * OTP, and `create_customer()` to register a new account for
	 * the user.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 *
	 * @throws OTPRequiredException Exception when a user does not enter the OTP.
	 * @throws OTPValidationFailedException Exception when the API call to validate the OTP fails.
	 *
	 * @deprecated since 1.10.9
	 */
	public function idp_validate_otp( array $sanitized_post ) {
		$this->is_valid_request();

		$otp_token = sanitize_text_field( $sanitized_post['otp_token'] );
		$this->check_if_otp_entered( array( 'otp_token' => $sanitized_post ) );

		$content = json_decode( MoIDPUtility::validate_otp_token( get_site_option( 'mo_idp_transactionId' ), $otp_token ), true );
		$this->check_if_otp_validation_passed( $content, 'status' );
		$customer_key = json_decode( MoIDPUtility::create_customer(), true );
		if ( strcasecmp( $customer_key['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS' ) === 0 ) {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'ACCOUNT_EXISTS' ), 'SUCCESS' );
		} elseif ( strcasecmp( $customer_key['status'], 'SUCCESS' ) === 0 ) {
			$this->save_success_customer_config( $customer_key['id'], $customer_key['apiKey'], $customer_key['token'], $customer_key['appSecret'] );
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'NEW_REG_SUCCES' ), 'SUCCESS' );
		}
	}

	/**
	 * This function handles user registration bypassing the
	 * OTP validation. It uses the `create_customer()` function
	 * to register a new account for the user. If an account
	 * already exists, it uses the `get_current_customer()`
	 * function to fetch the details of the existing account.
	 *
	 * @param string $email Refers to the email entered by the user.
	 * @param string $password Refers to the password entered by the user.
	 */
	public function create_user_without_verification( $email, $password ) {
		$customer_key = json_decode( MoIDPUtility::create_customer(), true );
		if ( strcasecmp( $customer_key['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS' ) === 0 ) {
			$this->get_current_customer( $email, $password );
		} elseif ( strcasecmp( $customer_key['status'], 'SUCCESS' ) === 0 ) {
			$this->save_success_customer_config( $customer_key['id'], $customer_key['apiKey'], $customer_key['token'], $customer_key['appSecret'] );
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'NEW_REG_SUCCES' ), 'SUCCESS' );
		}
	}
}
