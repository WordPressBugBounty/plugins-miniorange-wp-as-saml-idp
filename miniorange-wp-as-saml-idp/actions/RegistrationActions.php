<?php
/**
 * This file contains the `RegistrationActions` class that defines
 * methods to handle user registration functionality.
 *
 * @package miniorange-wp-as-saml-idp\actions
 */

namespace IDP\Actions;

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
use IDP\Handler\RegistrationHandler;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `BasePostAction` class
 * and handles all the registration functions.
 */
class RegistrationActions extends BasePostAction {

	use Instance;

	/**
	 * Instance of `RegistrationHandler` class
	 * to call its required methods.
	 *
	 * @var RegistrationHandler $handler
	 */
	private $handler;

	/**
	 * Constructor function, which instantiates the `RegistrationHandler`
	 * and makes a call to the parent (`BasePostAction`) constructor.
	 */
	public function __construct() {
		$this->handler = RegistrationHandler::get_instance();
		parent::__construct();
	}

	/**
	 * Refers to form options related to
	 * registration functionality.
	 *
	 * @var array $funcs
	 */
	private $funcs = array(
		'mo_idp_register_customer',
		'mo_idp_validate_otp',
		'mo_idp_phone_verification',
		'mo_idp_connect_verify_customer',
		'mo_idp_forgot_password',
		'mo_idp_go_back',
		'mo_idp_resend_otp',
		'remove_idp_account',
	);

	/**
	 * Handles the registration form post data. Checks for
	 * any kind of Exception that may occur during
	 * processing of form post data.
	 *
	 * @return void
	 */
	public function handle_post_data() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function in their respective Handler classes.
		if ( current_user_can( 'manage_options' ) && isset( $_POST['option'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function in their respective Handler classes.
			$option = trim( sanitize_text_field( wp_unslash( $_POST['option'] ) ) );
			try {
				$this->route_post_data( $option );
			} catch ( RegistrationRequiredFieldsException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( PasswordStrengthException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( PasswordMismatchException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( InvalidPhoneException $e ) {
				update_site_option( 'mo_idp_registration_status', 'MO_OTP_DELIVERED_FAILURE' );
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( OTPRequiredException $e ) {
				update_site_option( 'mo_idp_registration_status', 'MO_OTP_VALIDATION_FAILURE' );
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( OTPValidationFailedException $e ) {
				update_site_option( 'mo_idp_registration_status', 'MO_OTP_VALIDATION_FAILURE' );
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( OTPSendingFailedException $e ) {
				update_site_option( 'mo_idp_registration_status', 'MO_OTP_DELIVERED_FAILURE' );
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( PasswordResetFailedException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( RequiredFieldsException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( \Exception $e ) {
				if ( MSI_DEBUG ) {
					MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
				}
				wp_die( esc_html( $e->getMessage() ) );
			}
		}
	}

	/**
	 * Route the registration form post data. Check for any kind of
	 * Exception that may occur during processing of form post
	 * data.
	 *
	 * @param string $option Reference for option value in the form post.
	 * @throws InvalidPhoneException Exception when the phone number entered by the user does not match the pattern in const PATTERN_PHONE.
	 * @throws OTPRequiredException Exception when a user does not enter the OTP.
	 * @throws OTPSendingFailedException Exception when the API call to send the OTP fails.
	 * @throws OTPValidationFailedException Exception when the API call to validate the OTP fails.
	 * @throws PasswordMismatchException Exception when the password and confirm password fields do not match.
	 * @throws PasswordResetFailedException Exception when the password reset was unsuccessful.
	 * @throws PasswordStrengthException Exception when user password length is less than 6.
	 * @throws RegistrationRequiredFieldsException Exception when the user email and password are missing during user registration.
	 * @throws RequiredFieldsException Exception when certain fields are either missing or empty in a given form / array.
	 */
	public function route_post_data( $option ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function in their respective Handler classes.
		$sanitized_post = MoIDPUtility::sanitize_associative_array( $_POST );
		switch ( $option ) {
			case $this->funcs[0]:
				$this->handler->idp_register_customer( $sanitized_post );
				break;
			case $this->funcs[1]:
				$this->handler->idp_validate_otp( $sanitized_post );
				break;
			case $this->funcs[2]:
				$this->handler->mo_idp_phone_verification( $sanitized_post );
				break;
			case $this->funcs[3]:
				$this->handler->mo_idp_verify_customer( $sanitized_post );
				break;
			case $this->funcs[4]:
				$this->handler->mo_idp_forgot_password();
				break;
			case $this->funcs[5]:
			case $this->funcs[7]:
				$this->handler->mo_idp_go_back();
				break;
			case $this->funcs[6]:
				$this->handler->send_otp_token(
					get_site_option( 'mo_idp_admin_email' ),
					'',
					'EMAIL'
				);
				break;
		}
	}
}
