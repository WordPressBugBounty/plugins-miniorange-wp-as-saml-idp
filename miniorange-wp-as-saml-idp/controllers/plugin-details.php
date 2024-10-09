<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the plugin-details
 * (dashboard) view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$integrations_details = array(
	'MemberPress'      => MSI_URL . 'includes/images/memberpress.jpg',
	'WooCommerce'      => MSI_URL . 'includes/images/woocommerce.png',
	'BuddyPress'       => MSI_URL . 'includes/images/buddypress.png',
	'LearnDash'        => MSI_URL . 'includes/images/learndash.png',
	'Ultimate Member'  => MSI_URL . 'includes/images/ultimatemember.png',
	'Teachable'        => MSI_URL . 'includes/images/teachable.png',
	'Paid Memberships' => MSI_URL . 'includes/images/paid_mem_pro.png',
	'Optimonster'      => MSI_URL . 'includes/images/optimonster.png',
	'WP Members'       => MSI_URL . 'includes/images/wp-members.png',
);

require MSI_DIR . 'views/plugin-details.php';
