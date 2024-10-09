<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the user-profile
 * view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\RegistrationHandler;

$email       = get_site_option( 'mo_idp_admin_email' );
$customer_id = get_site_option( 'mo_idp_admin_customer_key' );
$regnonce    = RegistrationHandler::get_instance()->nonce;

require MSI_DIR . 'views/user-profile.php';
