<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the contact-button
 * view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\SupportHandler;
use IDP\Helper\Constants\MoIDPConstants;

global $_wp_admin_css_colors;

$admin_color = get_user_option( 'admin_color' );
$colors      = $_wp_admin_css_colors[ $admin_color ]->colors;

$current_logged_in_user = wp_get_current_user();
$email                  = get_site_option( 'mo_idp_admin_email' );
$email                  = ! empty( $email ) ? $email : $current_logged_in_user->user_email;
$phone                  = get_site_option( 'mo_idp_admin_phone' );
$phone                  = $phone ? $phone : '';
$support                = MoIDPConstants::WPIDPSUPPORT_EMAIL;

$support_nonce = SupportHandler::get_instance()->nonce;

require MSI_DIR . 'views/contact-button.php';
