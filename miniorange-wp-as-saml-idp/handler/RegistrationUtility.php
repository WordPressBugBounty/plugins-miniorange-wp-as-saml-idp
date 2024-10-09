<?php
/**
 * This file contains the `RegistrationUtility` class that provides
 * helper functions used to handle user registration.
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
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `BaseHandler` class and
 * provides helper functions used to handle user
 * registration.
 */
class RegistrationUtility extends BaseHandler {

	/**
	 * Check if the admin has entered password and confirm password
	 * of appropriate length. The length of the password needs to
	 * be greater than 6.
	 *
	 * @param string $confirm_password Confirm password string entered by the user.
	 * @param string $password Password string entered by the user.
	 * @throws PasswordStrengthException Exception when user password length is less than 6.
	 */
	public function check_pwd_strength( $confirm_password, $password ) {
		if ( strlen( $password ) < 6 || strlen( $confirm_password ) < 6 ) {
			throw new PasswordStrengthException();
		}
	}

	/**
	 * Check if the password string and the confirm password string
	 * entered by the admin are a match.
	 *
	 * @param string $confirm_password Confirm password string entered by the user.
	 * @param string $password Password string entered by the user.
	 * @throws PasswordMismatchException Exception when the password and confirm password fields do not match.
	 */
	public function pwd_and_cnfrm_pwd_match( $confirm_password, $password ) {
		if ( $password !== $confirm_password ) {
			throw new PasswordMismatchException();
		}
	}

	/**
	 * Check if any required field for the registration form has a
	 * null or empty value. Uses the `check_if_required_fields_empty()`
	 * function.
	 *
	 * @param array $field_array Refers to a list of all the required fields to check in the registration form.
	 * @throws RegistrationRequiredFieldsException Exception when the user email and password are missing during user registration.
	 */
	public function check_if_reg_req_fields_empty( $field_array ) {
		try {
			$this->check_if_required_fields_empty( $field_array );
		} catch ( RequiredFieldsException $e ) {
			throw new RegistrationRequiredFieldsException();
		}
	}

	/**
	 * Check if the phone number matched the correct format.
	 *
	 * @param string $phone Phone number entered by the user.
	 * @throws InvalidPhoneException Exception when the phone number entered by the user does not match the pattern in const PATTERN_PHONE.
	 */
	public function is_valid_phone_number( $phone ) {
		if ( ! MoIDPUtility::validate_phone_number( $phone ) ) {
			throw new InvalidPhoneException( esc_html( $phone ) );
		}
	}

	/**
	 * Check if the required field (OTP) has a null or empty value.
	 * Uses the `check_if_required_fields_empty()` function.
	 *
	 * @param array $var_array Associative array, which lists all the variables to check, and the array to check in.
	 * @throws OTPRequiredException Exception when a user does not enter the OTP.
	 */
	public function check_if_otp_entered( $var_array ) {
		try {
			$this->check_if_required_fields_empty( $var_array );
		} catch ( RequiredFieldsException $e ) {
			throw new OTPRequiredException();
		}
	}

	/**
	 * Check if the OTP validation passed or failed, by checking the
	 * response received from the server.
	 *
	 * @param array  $resp_array Response received from the server.
	 * @param string $key The key to check in the API Response.
	 * @throws OTPValidationFailedException Exception when the API call to validate the OTP fails.
	 */
	public function check_if_otp_validation_passed( $resp_array, $key ) {
		if ( empty( $resp_array[ $key ] ) || strcasecmp( $resp_array[ $key ], 'SUCCESS' ) !== 0 ) {
			throw new OTPValidationFailedException();
		}
	}

	/**
	 * Check if the OTP was sent to the user successfully, by checking the
	 * response received from the server.
	 *
	 * @param array  $resp_array Response received from the server.
	 * @param string $key The key to check in the API Response.
	 * @throws OTPSendingFailedException Exception when the API call to send the OTP fails.
	 */
	public function check_if_otp_sent_successfully( $resp_array, $key ) {
		if ( empty( $resp_array[ $key ] ) || strcasecmp( $resp_array[ $key ], 'SUCCESS' ) !== 0 ) {
			throw new OTPSendingFailedException();
		}
	}

	/**
	 * Check if the password was reset successfully, by checking the
	 * response received from the server.
	 *
	 * @param array  $resp_array Response received from the server.
	 * @param string $key The key to check in the API Response.
	 * @throws PasswordResetFailedException Exception when the password reset was unsuccessful.
	 */
	public function check_if_password_reset_successfully( $resp_array, $key ) {
		if ( empty( $resp_array[ $key ] ) || strcasecmp( $resp_array[ $key ], 'SUCCESS' ) !== 0 ) {
			throw new PasswordResetFailedException();
		}
	}
}
