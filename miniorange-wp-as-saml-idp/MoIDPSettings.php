<?php
/**
 * Plugin Name: Login using WordPress Users
 * Plugin URI: https://plugins.miniorange.com/wordpress-saml-idp
 * Description: Convert your WordPress into an IDP.
 * Version: 1.15.7
 * Author: miniOrange
 * Author URI: https://plugins.miniorange.com/
 * License: MIT/Expat
 * License URI: https://docs.miniorange.com/mit-license
 *
 * @package miniorange-wp-as-saml-idp
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}
define( 'MSI_PLUGIN_NAME', plugin_basename( __FILE__ ) );
$dir_name = substr( MSI_PLUGIN_NAME, 0, strpos( MSI_PLUGIN_NAME, '/' ) );
define( 'MSI_NAME', $dir_name );
require 'MoIDPAutoload.php';
\IDP\MoIDP::get_instance();
