<?php
/**
 * This file defines constants and makes a call to the
 * autoloader to include the plugin files and other library
 * files used throughout the plugin.
 *
 * @package miniorange-wp-as-saml-idp
 */

use IDP\Helper\Utilities\TabDetails;
use IDP\Helper\Utilities\Tabs;
use IDP\SplClassLoader;

define( 'MSI_VERSION', '1.15.6' );
define( 'MSI_DB_VERSION', '1.5' );
define( 'MSI_DIR', plugin_dir_path( __FILE__ ) );
define( 'MSI_URL', plugin_dir_url( __FILE__ ) );
define( 'MSI_CSS_URL', MSI_URL . 'includes/css/mo_idp_style.min.css' );
define( 'MSI_JS_URL', MSI_URL . 'includes/js/settings.min.js' );
define( 'MSI_ICON', MSI_URL . 'includes/images/miniorange_icon.png' );
define( 'MSI_LOGO_URL', MSI_URL . 'includes/images/logo.png' );
define( 'MSI_LOADER', MSI_URL . 'includes/images/loader.gif' );
define( 'MSI_TEST', false );
define( 'MSI_DEBUG', false );
define( 'MSI_LK_DEBUG', false );
define( 'MSI_LOCK', MSI_URL . 'includes/images/lock.png' );

mo_idp_include_lib_files();

/**
 * This function includes the library files
 * required in the plugin.
 *
 * @return void
 */
function mo_idp_include_lib_files() {
	if ( ! class_exists( 'RobRichards\XMLSecLibs\XMLSecurityKey' ) ) {
		include 'helper/common/XMLSecurityKey.php';
	}
	if ( ! class_exists( 'RobRichards\XMLSecLibs\XMLSecEnc' ) ) {
		include 'helper/common/XMLSecEnc.php';
	}
	if ( ! class_exists( 'RobRichards\XMLSecLibs\XMLSecurityDSig' ) ) {
		include 'helper/common/XMLSecurityDSig.php';
	}
	if ( ! class_exists( 'RobRichards\XMLSecLibs\Utils\XPath' ) ) {
		include 'helper/common/Utils/XPath.php';
	}
}

/**
 * This function returns the link to the
 * Account Setup tab.
 *
 * @return string
 */
function mo_idp_get_registration_url() {
	$request_uri = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url( 'admin.php' );
	return add_query_arg(
		array( 'page' => TabDetails::get_instance()->tab_details[ Tabs::PROFILE ]->menu_slug ),
		esc_url_raw( $request_uri )
	);
}

require 'SplClassLoader.php';

/**
 * Instance of `SplClassLoader` class
 * to call its required methods.
 *
 * @var SplClassLoader $mo_idp_class_loader
 */
$mo_idp_class_loader = new SplClassLoader( 'IDP', realpath( __DIR__ . DIRECTORY_SEPARATOR . '..' ) );
$mo_idp_class_loader->register();
