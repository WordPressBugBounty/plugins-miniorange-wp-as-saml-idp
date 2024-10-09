<?php
/**
 * This file contains the `MoIDPUtility` utility class that
 * provides helper functions used throughout the plugin.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\SAML2\MetadataGenerator;
use IDP\Helper\Constants\MoIDPMessages;

/**
 * This class provides helper functions used throughout
 * the plugin.
 */
class MoIDPUtility {

	/**
	 * This function checks if a value is set or
	 * empty. Returns true if value is empty.
	 *
	 * @param string $value References the variable passed.
	 * @return boolean
	 */
	public static function is_blank( $value ) {
		if ( ! isset( $value ) || empty( $value ) ) {
			return true;
		}
		return false;
	}

	/**
	 * This function checks if cURL has been installed
	 * or enabled on the site.
	 *
	 * @return 0|1
	 */
	public static function is_curl_installed() {
		if ( in_array( 'curl', get_loaded_extensions(), true ) ) {
			return 1;
		} else {
			return 0;
		}
	}

	/**
	 * This function checks if there is a current
	 * session. Starts a new session if there's no
	 * existing session.
	 *
	 * @return void
	 */
	public static function start_session() {
		if ( ! session_id() || session_id() === '' || ! isset( $_SESSION ) ) {
			session_start();
		}
	}

	/**
	 * This function checks if the phone number is
	 * in the correct format or not.
	 *
	 * @param string $phone Refers to the phone number entered.
	 * @return boolean
	 */
	public static function validate_phone_number( $phone ) {
		if ( ! preg_match( MoIDPConstants::PATTERN_PHONE, $phone, $matches ) ) {
			return false;
		} else {
			return true;
		}
	}

	/**
	 * This function creates a cookie for the
	 * SP that the user is currently logged into.
	 *
	 * @param string $issuer Refers to the Issuer/Entity ID of the SP.
	 * @return void
	 */
	public static function add_sp_cookie( $issuer ) {
		$sanitized_cookie   = self::sanitize_associative_array( $_COOKIE );
		$arr_cookie_options = array(
			'expires'  => time() + 21600,
			'path'     => '/',
			'secure'   => true,
			'samesite' => 'None',
		);
		if ( isset( $sanitized_cookie['mo_sp_count'] ) ) {
			for ( $i = 1;$i <= $sanitized_cookie['mo_sp_count'];$i++ ) {
				if ( $sanitized_cookie[ 'mo_sp_' . $i . '_issuer' ] === $issuer ) {
					return;
				}
			}
		}
		$sp_count = isset( $sanitized_cookie['mo_sp_count'] ) ? $sanitized_cookie['mo_sp_count'] + 1 : 1;
		setcookie( 'mo_sp_count', $sp_count, $arr_cookie_options );
		setcookie( 'mo_sp_' . $sp_count . '_issuer', $issuer, $arr_cookie_options );
	}

	/**
	 * This function is used to check if a customer has
	 * completed his registration and if his keys have been
	 * set properly in the database.
	 *
	 * @return 0|1
	 */
	public static function micr() {
		$email        = get_site_option( 'mo_idp_admin_email' );
		$customer_key = get_site_option( 'mo_idp_admin_customer_key' );
		return ! $email || ! $customer_key || ! is_numeric( trim( $customer_key ) ) ? 0 : 1;
	}

	/**
	 * This function is used to get the SP
	 * count from the database. This function
	 * is just used for abstraction purposes.
	 *
	 * @global \IDP\Helper\Database\MoDbQueries $moidp_db_queries
	 * @return string|null
	 */
	public static function gssc() {
		global $moidp_db_queries;
		return $moidp_db_queries->get_sp_count();
	}

	/**
	 * This function is used to initialize all values and
	 * call the create_customer cURL function.
	 *
	 * @return string
	 */
	public static function create_customer() {
		$email    = get_site_option( 'mo_idp_admin_email' );
		$password = get_site_option( 'mo_idp_admin_password' );
		$content  = MoIDPcURL::create_customer( $email, $password );
		return $content;
	}

	/**
	 * This function is used to initialize all values and
	 * call the get_customer_key cURL function.
	 *
	 * @param string $email Refers to the email entered.
	 * @param string $password Refers to the password entered.
	 * @return string
	 */
	public static function get_customer_key( $email, $password ) {
		$content = MoIDPcURL::get_customer_key( $email, $password );
		return $content;
	}

	/**
	 * This function is used to initialize all values and
	 * call the check_customer cURL function.
	 *
	 * @return string
	 */
	public static function check_customer() {
		$email   = get_site_option( 'mo_idp_admin_email' );
		$content = MoIDPcURL::check_customer( $email );
		return $content;
	}

	/**
	 * This function is used to process the parameters and
	 * call the send_otp_token cURL function.
	 *
	 * @param string $auth_type Refers to the type of OTP (over Email / Phone) to send.
	 * @param string $email Refers to the email otp has to be sent to.
	 * @param string $phone Refers to the phone otp has to be sent to.
	 * @return string
	 */
	public static function send_otp_token( $auth_type, $email = '', $phone = '' ) {
		$content = MoIDPcURL::send_otp_token( $auth_type, $phone, $email );
		return $content;
	}

	/**
	 * This function is used to process the parameters and
	 * call the validate_otp_token cURL function.
	 *
	 * @param string $transaction_id Refers to txId stored in session.
	 * @param string $otp_token Refers to the otp entered by the user.
	 * @return string
	 */
	public static function validate_otp_token( $transaction_id, $otp_token ) {
		$content = MoIDPcURL::validate_otp_token( $transaction_id, $otp_token );
		return $content;
	}

	/**
	 * This function is used to submit the Contact us query
	 * by calling the submit_contact_us cURL function.
	 *
	 * @param string $email Refers to the email of the user.
	 * @param string $phone Refers to the phone of the user.
	 * @param string $query Refers to the query to be sent.
	 * @return boolean
	 */
	public static function submit_contact_us( $email, $phone, $query ) {
		MoIDPcURL::submit_contact_us( $email, $phone, $query );
		return true;
	}

	/**
	 * This function is used to call the forgot_password cURL
	 * function.
	 *
	 * @param string $email Refers to the email of the user.
	 * @return string
	 */
	public static function forgot_password( $email ) {
		$email        = get_site_option( 'mo_idp_admin_email' );
		$customer_key = get_site_option( 'mo_idp_admin_customer_key' );
		$api_key      = get_site_option( 'mo_idp_admin_api_key' );
		$content      = MoIDPcURL::forgot_password( $email, $customer_key, $api_key );
		return $content;
	}

	/**
	 * Function just unsets the cookie variables.
	 *
	 * @param array $vars Refers to the Cookie variables to unset.
	 * @return void
	 */
	public static function unset_cookie_variables( $vars ) {
		foreach ( $vars as $var ) {
			unset( $_COOKIE[ $var ] );
			setcookie( $var, '', time() - 3600 );
		}
	}

	/**
	 * This function forms and returns the idp-signing.crt directory path.
	 *
	 * @return string
	 */
	public static function get_public_cert_path() {
		return MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing.crt';
	}

	/**
	 * This function forms and returns the idp-signing.key directory path.
	 *
	 * @return string
	 */
	public static function get_private_key_path() {
		return MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing.key';
	}

	//phpcs:disable WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents, WordPress.WP.AlternativeFunctions.file_system_read_fclose, WordPress.WP.AlternativeFunctions.file_system_read_fopen, WordPress.WP.AlternativeFunctions.file_system_read_fwrite, WordPress.WP.AlternativeFunctions.file_system_read_file_put_contents -- Reading and writing data to local files.

	/**
	 * This function reads and returns the idp-signing.crt.
	 *
	 * @return string|false
	 */
	public static function get_public_cert() {
		return file_get_contents( MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing.crt' );
	}

	/**
	 * This function reads and returns the idp-signing-new.crt.
	 *
	 * @return string|false
	 */
	public static function get_new_public_cert() {
		return file_get_contents( MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing-new.crt' );
	}

	/**
	 * Returns the new key from idp-signing-new.key file
	 *
	 * @return string
	 */
	public static function get_new_private_key() {
		return file_get_contents( MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing-new.key' );
	}

	/**
	 * This function reads and returns the idp-signing.key.
	 *
	 * @return string|false
	 */
	public static function get_private_key() {
		return file_get_contents( MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing.key' );
	}

	/**
	 * This function returns the Public Cert URL.
	 *
	 * @return string
	 */
	public static function get_public_cert_url() {
		return MSI_URL . 'includes/resources/idp-signing.crt';
	}

	/**
	 * This function returns the New Public Cert URL.
	 *
	 * @return string
	 */
	public static function get_new_public_cert_url() {
		return MSI_URL . 'includes/resources/idp-signing-new.crt';
	}

	/**
	 * This function logs a line in the PHP error log file
	 * for debugging purposes. Should only be used when MSI_DEBUG
	 * is TRUE.
	 *
	 * @param string $message Refers to the message to be logged in the log file.
	 * @return void
	 */
	public static function mo_debug( $message ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log -- Debugging function requires use of `error_log()`.
		error_log( '[MO-MSI-LOG][' . gmdate( 'm-d-Y', time() ) . ']: ' . $message );
	}

	/**
	 * This function generates the IDP metadata XML file for the site.
	 *
	 * @return void
	 */
	public static function create_metadata_file() {
		global $wp_filesystem;
		if ( ! WP_Filesystem() ) {
			return;
		}

		$blogs       = is_multisite() ? get_sites() : null;
		$login_url   = is_null( $blogs ) ? site_url( '/' ) : get_site_url( $blogs[0]->blog_id, '/' );
		$logout_url  = is_null( $blogs ) ? site_url( '/' ) : get_site_url( $blogs[0]->blog_id, '/' );
		$entity_id   = get_site_option( 'mo_idp_entity_id' ) ? get_site_option( 'mo_idp_entity_id' ) : MSI_URL;
		$certificate = self::get_public_cert();
		$new_cert    = null;

		if ( ! get_site_option( 'mo_idp_new_certs' ) ) {
			$new_cert = self::get_new_public_cert();
		}

		$generator = new MetadataGenerator( $entity_id, true, $certificate, $new_cert, $login_url, $login_url, $logout_url, $logout_url );
		$metadata  = $generator->generate_metadata();
		if ( MSI_DEBUG ) {
			self::mo_debug( 'Metadata Generated: ' . $metadata );
		}

		$wp_filesystem->put_contents( MSI_DIR . 'metadata.xml', $metadata, FS_CHMOD_FILE );
	}

	/**
	 * This function renders the IDP metadata XML file for the site.
	 *
	 * @return void
	 */
	public static function show_metadata() {
		$blogs       = is_multisite() ? get_sites() : null;
		$login_url   = is_null( $blogs ) ? site_url( '/' ) : get_site_url( $blogs[0]->blog_id, '/' );
		$logout_url  = is_null( $blogs ) ? site_url( '/' ) : get_site_url( $blogs[0]->blog_id, '/' );
		$entity_id   = get_site_option( 'mo_idp_entity_id' ) ? get_site_option( 'mo_idp_entity_id' ) : MSI_URL;
		$certificate = self::get_public_cert();
		$new_cert    = null;

		if ( ! get_site_option( 'mo_idp_new_certs' ) ) {
			$new_cert = self::get_new_public_cert();
		}

		$generator = new MetadataGenerator( $entity_id, true, $certificate, $new_cert, $login_url, $login_url, $logout_url, $logout_url );
		$metadata  = $generator->generate_metadata();

		if ( ob_get_contents() ) {
			ob_clean();
		}

		header( 'Content-Type: text/xml' );
		// phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Escaping metadata results in broken structure, all variables escaped before echo.
		echo $metadata;
		exit;
	}

	/**
	 * This function generates a random alphanumeric string based
	 * on the length passed.
	 *
	 * @param int $length The length of the string.
	 * @return string
	 */
	public static function generate_random_alphanumeric_value( $length ) {
		$chars     = 'abcdef0123456789';
		$chars_len = strlen( $chars );
		$unique_id = '';
		for ( $i = 0; $i < $length; $i++ ) {
			$unique_id .= substr( $chars, wp_rand( 0, 15 ), 1 );
		}
		return 'a' . $unique_id;
	}

	/**
	 * This function is created to check whether a person is having
	 * admin access or not.
	 *
	 * @return 0|1
	 */
	public static function is_admin() {
		$user = wp_get_current_user();
		if ( in_array( 'administrator', (array) $user->roles, true ) ) {
			return 1;
		} else {
			return 0;
		}
	}

	/**
	 * This function is created to update the certificates. The validity of the certificates
	 * is set to 365 days, and this function will replace the existing certificates with the
	 * new certificates. This will also update the plugin metadata XML file once the certificates
	 * are updated.
	 *
	 * @return void
	 */
	public static function use_new_certs() {
		global $moidp_db_queries, $wp_filesystem;
		if ( ! WP_Filesystem() ) {
			return;
		}

		$moidp_signing_cert_file_path = self::get_public_cert_path();
		$moidp_signing_key_file_path  = self::get_private_key_path();
		
		if ( ! $wp_filesystem->is_writable( $moidp_signing_cert_file_path ) || ! $wp_filesystem->is_writable( $moidp_signing_key_file_path ) ) {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'READ_ONLY_PERMISSIONS' ), 'ERROR' );
			return;
		}

		$wp_filesystem->put_contents( $moidp_signing_cert_file_path, self::get_new_public_cert(), FS_CHMOD_FILE );
		$wp_filesystem->put_contents( $moidp_signing_key_file_path, self::get_new_private_key(), FS_CHMOD_FILE );

		update_site_option( 'mo_idp_new_certs', true );

		$metadata_dir = MSI_DIR . 'metadata.xml';
		if ( file_exists( $metadata_dir ) && filesize( $metadata_dir ) > 0 ) {
			wp_delete_file( $metadata_dir );
			self::create_metadata_file();
		}

		$moidp_db_queries->create_public_key_table();
		self::save_new_cert_to_db_for_sp();
	}

	/**
	 * Saves the new certificate to db for the service provider.
	 *
	 * @param int|bool $sp_id Id of the service provider to save the cert for, if passed
	 *                          as false then we save certificate for the 1st SP in db.
	 * @return int|false
	 */
	public static function save_new_cert_to_db_for_sp( $sp_id = false ) {
		global $moidp_db_queries;
		$public_key  = self::get_new_public_cert();
		$private_key = self::get_new_private_key();
		return $moidp_db_queries->insert_cert_for_sp( $public_key, $private_key, $sp_id );
	}

	/**
	 * This function compares the expiry of the old and the new certificate files in the plugin.
	 * If the new certificate expiry is longer than the current certificate, it will return True, else False.
	 *
	 * @return boolean
	 */
	public static function check_cert_expiry() {
		$current_cert = MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing.crt';
		$new_cert     = MSI_DIR . 'includes' . DIRECTORY_SEPARATOR . 'resources' . DIRECTORY_SEPARATOR . 'idp-signing-new.crt';

		$current_cert_expiry = ( openssl_x509_parse( file_get_contents( $current_cert ) )['validTo_time_t'] ) - time();
		$new_cert_expiry     = ( openssl_x509_parse( file_get_contents( $new_cert ) )['validTo_time_t'] ) - time();

		if ( $new_cert_expiry > $current_cert_expiry ) {
			return true;
		} else {
			return false;
		}
	}

	/*
	| ------------------------------------------------------------------------------------------
	| FREE PLUGIN SPECIFIC FUNCTIONS
	| ------------------------------------------------------------------------------------------
	 */

	/**
	 * This function checks if the user has
	 * completed the activation step.
	 *
	 * @return boolean
	 */
	public static function iclv() {
		return true;
	}

	/**
	 * Wrapper function for `wp_remote_get()`.
	 *
	 * @param string $url Refers to the URL to retrieve.
	 * @param array  $args Optional. Request arguments.
	 * @return array|null
	 */
	public static function mo_saml_wp_remote_get( $url, $args = array() ) {
		$response = wp_remote_get( $url, $args );

		if ( ! is_wp_error( $response ) ) {
				return $response;
		} else {
				return null;
		}
	}

	/**
	 * Used to sanitize an associative array.
	 *
	 * @param array $raw_array Unsantized associative array.
	 * @return array
	 */
	public static function sanitize_associative_array( $raw_array ) {
		$sanitized_array = array();
		foreach ( $raw_array as $key => $value ) {
			if ( is_array( $value ) ) {
				$temp_value = array();
				foreach ( $value as $inner_key => $inner_value ) {
					$temp_value[ $inner_key ] = sanitize_text_field( $inner_value );
				}
				$sanitized_array[ $key ] = $temp_value;
			} else {
				$sanitized_array[ $key ] = sanitize_text_field( $value );
			}
		}
		$sanitized_array = apply_filters( 'mo_idp_sanitized_array', $sanitized_array, $raw_array );
		return $sanitized_array;
	}

	/**
	 * Checks whether the file was uploaded via HTTP POST
	 * and returns the contents.
	 *
	 * @param string $file_name Name of the file to read.
	 * @return file $file | null
	 */
	public static function handle_file_upload( $file_name ) {
		if ( is_uploaded_file( $file_name ) ) {
			$file = file_get_contents( $file_name );
		} else {
			$file = null;
		}

		return $file;
	}
}

// phpcs:enable
