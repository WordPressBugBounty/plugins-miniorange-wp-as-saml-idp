<?php
/**
 * This file is the main controller, which defines all the
 * required variables to be used across different views
 * throughout the plugin. It is also responsible for routing
 * to the particular controller based on the `$_GET` request.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Utilities\MoIDPUtility;
use IDP\Helper\Utilities\TabDetails;
use IDP\Helper\Utilities\Tabs;

$registered = MoIDPUtility::micr();
$verified   = MoIDPUtility::iclv();
$controller = MSI_DIR . 'controllers/';

/**
 * Instance of `TabDetails` class
 * to access its required members.
 *
 * @var TabDetails $idp_tabs
 */
$idp_tabs    = TabDetails::get_instance();
$tab_details = $idp_tabs->tab_details;
$parent_slug = $idp_tabs->parent_slug;

/**
 * ProfileTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the User Profile tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $profile_tab_details
 */
$profile_tab_details = $tab_details[ Tabs::PROFILE ];

/**
 * SettingsTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the SSO Options tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $settings_tab_details
 */
$settings_tab_details = $tab_details[ Tabs::SIGN_IN_SETTINGS ];

/**
 * MetadataTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the IDP Metadata tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $metadata_tab_details
 */
$metadata_tab_details = $tab_details[ Tabs::METADATA ];

/**
 * SPSettingsTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the Service Providers tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $sp_settings_tab_details
 */
$sp_settings_tab_details = $tab_details[ Tabs::IDP_CONFIG ];

/**
 * AttrMapTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the Attribute / Role
 * Mapping tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $attr_map_tab_details
 */
$attr_map_tab_details = $tab_details[ Tabs::ATTR_SETTINGS ];

/**
 * SupportSection is an an object of
 * the `PluginPageDetails` class detailing
 * information about the Support Page.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $support_section
 */
$support_section = $tab_details[ Tabs::SUPPORT ];

/**
 * DemoRequestTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the Request a Demo tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $demo_request_tab_details
 */
$demo_request_tab_details = $tab_details[ Tabs::DEMO_REQUEST ];

/**
 * IDPAddonsTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the User Profile tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $idp_addons_tab_details
 */
$idp_addons_tab_details = $tab_details[ Tabs::ADDONS ];

/**
 * IDPDashboardTabDetails is an an object of
 * the `PluginPageDetails` class detailing
 * information about the Dashboard tab.
 *
 * @var \IDP\Helper\Utilities\PluginPageDetails $idp_dashboard_tab_details
 */
$idp_dashboard_tab_details = $tab_details[ Tabs::DASHBOARD ];


require MSI_DIR . 'views/common-elements.php';
require MSI_DIR . 'controllers/sso-idp-navbar.php';

// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification since we are navigating through tabs.
if ( isset( $_GET['page'] ) ) {
	$account = $registered ? 'sso-idp-profile.php' : 'sso-idp-registration.php';
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification since we are navigating through tabs.
	switch ( sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) {
		case $metadata_tab_details->menu_slug:
			include $controller . 'sso-idp-data.php';
			break;
		case $sp_settings_tab_details->menu_slug:
			include $controller . 'sso-idp-settings.php';
			break;
		case $profile_tab_details->menu_slug:
			include $controller . $account;
			break;
		case $settings_tab_details->menu_slug:
			include $controller . 'sso-signin-settings.php';
			break;
		case $attr_map_tab_details->menu_slug:
			include $controller . 'sso-attr-settings.php';
			break;
		case $support_section->menu_slug:
			include $controller . 'sso-idp-support.php';
			break;
		case $parent_slug:
			include $controller . 'plugin-details.php';
			break;
		case $demo_request_tab_details->menu_slug:
			include $controller . 'sso-idp-request-demo.php';
			break;
		case $idp_addons_tab_details->menu_slug:
			include $controller . 'sso-idp-addons.php';
			break;
		case $idp_dashboard_tab_details->menu_slug:
			include $controller . 'plugin-details.php';
			break;
	}
	include $controller . 'contact-button.php';
}
