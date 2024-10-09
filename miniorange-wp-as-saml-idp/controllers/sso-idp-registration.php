<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the user-registration
 * view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;
use IDP\Handler\RegistrationHandler;

$hostname = MoIDPConstants::HOSTNAME;

/**
 * Instance of `RegistrationHandler` class
 * to access its required members.
 *
 *  @var RegistrationHandler $handler
 */
$handler  = RegistrationHandler::get_instance();
$url      = $hostname . '/moas/login?redirectUrl=' . $hostname . '/moas/viewlicensekeys';
$email    = get_site_option( 'mo_idp_admin_email' );
$dir      = MSI_DIR . 'views/registration/';
$regnonce = $handler->nonce;

if ( get_site_option( 'mo_idp_verify_customer' ) ) {
	include $dir . 'verify-customer.php';
} elseif (
		trim( get_site_option( 'mo_idp_admin_email' ) ) !== ''
		&& trim( get_site_option( 'mo_idp_admin_api_key' ) ) === ''
		&& get_site_option( 'mo_idp_new_registration' ) !== 'true'
	) {
	include $dir . 'verify-customer.php';
} elseif (
		get_site_option( 'mo_idp_registration_status' ) === 'MO_OTP_DELIVERED_SUCCESS'
		|| get_site_option( 'mo_idp_registration_status' ) === 'MO_OTP_VALIDATION_FAILURE'
		|| get_site_option( 'mo_idp_registration_status' ) === 'MO_OTP_DELIVERED_FAILURE'
	) {
	include $dir . 'verify-otp.php';
} elseif ( ! $registered ) {
	delete_site_option( 'password_mismatch' );
	update_site_option( 'mo_idp_new_registration', true );
	$current_logged_in_user = wp_get_current_user();
	include $dir . 'new-registration.php';
} else {
	include MSI_DIR . 'controllers/sso-idp-settings.php';
}
