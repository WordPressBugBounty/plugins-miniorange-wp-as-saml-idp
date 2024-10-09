<?php
/**
 * This file contains the `Tabs` class that defines constants
 * to reference the plugin tabs.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class defines constants to reference the
 * plugin tabs.
 */
final class Tabs {

	const PROFILE          = 'profile';
	const IDP_CONFIG       = 'idp_config';
	const METADATA         = 'metadata';
	const SIGN_IN_SETTINGS = 'sign_in_settings';
	const ATTR_SETTINGS    = 'attr_settings';
	const SUPPORT          = 'support';
	const DEMO_REQUEST     = 'demo_request';
	const ADDONS           = 'idp_addons';
	const DASHBOARD        = 'dashboard';
}
