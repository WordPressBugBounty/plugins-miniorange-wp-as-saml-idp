<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the idp-support
 * view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\SupportHandler;
use IDP\Helper\Utilities\MoIDPUtility;

$current_logged_in_user = wp_get_current_user();
$email                  = get_site_option( 'mo_idp_admin_email' );
$email                  = ! empty( $email ) ? $email : $current_logged_in_user->user_email;
$phone                  = get_site_option( 'mo_idp_admin_phone' );
$phone                  = $phone ? $phone : '';

$support_nonce = SupportHandler::get_instance()->nonce;

// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification since we are getting the plan_name from the parameter.
$sanitized_request = MoIDPUtility::sanitize_associative_array( $_REQUEST );

if ( ! empty( $sanitized_request['plan_name'] ) ) {
	if ( 'lite_monthly' === $sanitized_request['plan_name'] ) {
		$plan      = 'mo_lite_monthly';
		$plan_desc = 'LITE PLAN - Monthly';
		$users     = '5000+';
	} elseif ( 'lite_yearly' === $sanitized_request['plan_name'] ) {
		$plan      = 'mo_lite_yearly';
		$plan_desc = 'LITE PLAN - Yearly';
		$users     = '5000+';
	} elseif ( 'wp_yearly' === $sanitized_request['plan_name'] ) {
		$plan      = 'mo_wp_yearly';
		$plan_desc = 'PREMIUM PLAN - Yearly';
		if ( '5K' === $sanitized_request['plan_users'] ) {
			$users = '5000+';
		} else {
			$users = 'Unlimited';
		}
	} elseif ( 'all_inclusive' === $sanitized_request['plan_name'] ) {
		$plan      = 'mo_all_inclusive';
		$plan_desc = 'All Inclusive Plan';
		$users     = '';
	}
}

if ( isset( $plan ) || isset( $users ) ) {
	$request_quote = 'Any Special Requirements: ';
} else {
	$request_quote = '';
}

	require MSI_DIR . 'views/idp-support.php';
