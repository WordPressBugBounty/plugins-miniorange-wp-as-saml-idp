<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the navbar
 * view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Utilities\MoIDPUtility;

$request_uri = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url( 'admin.php' );
$license_url = MoIDPConstants::IDP_LANDING_PAGE_URL;

$profile_url      = add_query_arg( array( 'page' => $profile_tab_details->menu_slug ), $request_uri );
$register_url     = add_query_arg( array( 'page' => $profile_tab_details->menu_slug ), $request_uri );
$idp_settings     = add_query_arg( array( 'page' => $sp_settings_tab_details->menu_slug ), $request_uri );
$sp_settings      = add_query_arg( array( 'page' => $metadata_tab_details->menu_slug ), $request_uri );
$login_settings   = add_query_arg( array( 'page' => $settings_tab_details->menu_slug ), $request_uri );
$attr_settings    = add_query_arg( array( 'page' => $attr_map_tab_details->menu_slug ), $request_uri );
$demo_request_url = add_query_arg( array( 'page' => $demo_request_tab_details->menu_slug ), $request_uri );
$idp_addons_url   = add_query_arg( array( 'page' => $idp_addons_tab_details->menu_slug ), $request_uri );
$dashboard_url    = add_query_arg( array( 'page' => $idp_dashboard_tab_details->menu_slug ), $request_uri );
$support_url      = add_query_arg( array( 'page' => $support_section->menu_slug ), $request_uri );
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification since we are navigating through tabs.
$active_tab = ! empty( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : '';

$use_new_cert = MoIDPUtility::check_cert_expiry();
if ( true === $use_new_cert ) {
	update_site_option( 'mo_idp_new_certs', false );
}

require MSI_DIR . 'views/navbar.php';
