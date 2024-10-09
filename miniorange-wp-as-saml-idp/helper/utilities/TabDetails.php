<?php
/**
 * This file contains the `TabDetails` class that is used
 * to describe the plugin tabs.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Traits\Instance;

/**
 * This class describes the plugin tabs.
 */
final class TabDetails {

	use Instance;

	/**
	 * Array of `PluginPageDetails` Object detailing
	 * all the page menu options.
	 *
	 * @var array[PluginPageDetails] $tab_details
	 */
	public $tab_details;

	/**
	 * The parent menu slug.
	 *
	 * @var string $parent_slug
	 */
	public $parent_slug;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$registered        = MoIDPUtility::micr();
		$this->parent_slug = 'idp_settings';
		$this->tab_details = array(
			Tabs::IDP_CONFIG       => new PluginPageDetails(
				'SAML IDP - Configure IDP',
				'idp_configure_idp',
				'Service Providers',
				'Service Providers',
				"This Tab is the section where you Configure your Service Provider's details needed for SSO."
			),
			Tabs::METADATA         => new PluginPageDetails(
				'SAML IDP - Metadata',
				'idp_metadata',
				'IDP Metadata',
				'IDP Metadata',
				"This Tab is where you will find information to put in your Service Provider's configuration page."
			),
			Tabs::DEMO_REQUEST     => new PluginPageDetails(
				'SAML IDP - Request a Demo',
				'idp_request_demo',
				'Request a Demo',
				'Request a Demo',
				'This Tab is where you can request a demo of the WordPress SAML IDP Premium plugin.'
			),
			Tabs::ATTR_SETTINGS    => new PluginPageDetails(
				'SAML IDP - Attribute Settings',
				'idp_attr_settings',
				'Attribute / Role Mapping',
				'Attribute / Role Mapping',
				'This Tab is where you configure the User Attributes and Role that you want to send out to your Service Provider.'
			),
			Tabs::SIGN_IN_SETTINGS => new PluginPageDetails(
				'SAML IDP - SignIn Settings',
				'idp_signin_settings',
				'SSO Options',
				'SSO Options',
				'This Tab is where you will find ShortCode and IdP Initiated Links for SSO.'
			),
			Tabs::ADDONS           => new PluginPageDetails(
				'SAML IDP - Add Ons',
				'idp_addons',
				'Add-Ons',
				'Add-Ons',
				'This page provides you with the SAML IDP compatible addons'
			),
			Tabs::PROFILE          => new PluginPageDetails(
				'SAML IDP - Account',
				'idp_profile',
				! $registered ? 'Account Setup' : 'User Profile',
				! $registered ? 'Account Setup' : 'Profile',
				"This Tab contains your Profile information. If you haven't registered then you can do so from here."
			),
			Tabs::SUPPORT          => new PluginPageDetails(
				'SAML IDP - Support',
				'idp_support',
				'Support',
				'Support',
				'You can use the form here to get in touch with us for any kind of support.'
			),
			Tabs::DASHBOARD        => new PluginPageDetails(
				'SAML IDP - DashBoard',
				$this->parent_slug,
				'Dashboard',
				'Dashboard',
				'You can use the form here to get in touch with us for any kind of support.'
			),
		);
	}
}
