<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the demo-request
 * view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\DemoRequestHandler;

$current_logged_in_user = wp_get_current_user();
$mo_idp_demo_email      = get_site_option( 'mo_idp_admin_email' );
$mo_idp_demo_email      = ! empty( $mo_idp_demo_email ) ? $mo_idp_demo_email : $current_logged_in_user->user_email;
$demononce              = DemoRequestHandler::get_instance()->nonce;

require MSI_DIR . 'views/demo-request.php';
