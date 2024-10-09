<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the idp-settings
 * (Service Providers) view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\SPSettingsHandler;

/**
 * Global variable to access the `MoDbQueries`
 * object and call its required methods for
 * different database operations.
 *
 * @global \IDP\Helper\Database\MoDbQueries $moidp_db_queries
 */
global $moidp_db_queries;

$sp_list = $moidp_db_queries->get_sp_list();
// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification since we are navigating through protocols.
$idp_action = isset( $_GET['action'] ) ? sanitize_text_field( wp_unslash( $_GET['action'] ) ) : '';

$protocol_inuse = 'add_wsfed_app' === $idp_action ? 'WSFED' : ( 'add_jwt_app' === $idp_action ? 'JWT' : 'SAML' );

$request_uri = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '';
$goback_url  = remove_query_arg( array( 'action', 'id' ), $request_uri );
$post_url    = remove_query_arg( array( 'action', 'id' ), $request_uri );

$sp_page_url  = add_query_arg( array( 'page' => $sp_settings_tab_details->menu_slug ), $request_uri );
$delete_url   = add_query_arg( array( 'action' => 'delete_sp_settings' ), $request_uri ) . '&id=';
$settings_url = add_query_arg( array( 'action' => 'show_idp_settings' ), $request_uri ) . '&id=';

$sp_exists = true;
$disabled  = '';

$idp_sp_settings_nonce = SPSettingsHandler::get_instance()->nonce;

if ( isset( $idp_action ) && 'delete_sp_settings' === $idp_action ) {
	// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification since we are getting the id from the parameter.
	$sp_id = ! empty( $_GET['id'] ) ? sanitize_text_field( wp_unslash( $_GET['id'] ) ) : '';
	$sp    = $moidp_db_queries->get_sp_data( $sp_id );
	include MSI_DIR . 'views/idp-delete.php';
} elseif ( ! empty( $sp_list ) ) {
	$sp          = $sp_list[0];
	$header      = 'Edit ' . ( ! empty( $sp ) ? $sp->mo_idp_sp_name : 'IDP' ) . ' Settings';
	$sp_exists   = false;
	$relay_state = $sp->mo_idp_default_relayState; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Refers to mo_idp_default_relay_state.
	$test_window = site_url() . '/?option=test_idp_config' .
								'&acs=' . $sp->mo_idp_acs_url .
								'&issuer=' . $sp->mo_idp_sp_issuer .
								'&defaultRelayState=' . $sp->mo_idp_default_relayState; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Refers to mo_idp_default_relay_state.

	if ( 'JWT' === $sp->mo_idp_protocol_type ) {
		include MSI_DIR . 'views/idp-jwt-settings.php';
	} elseif ( 'WSFED' === $sp->mo_idp_protocol_type ) {
		include MSI_DIR . 'views/idp-wsfed-settings.php';
	} else {
		include MSI_DIR . 'views/idp-settings.php';
	}
} else {
	$sp          = empty( $sp_list ) ? '' : $sp_list[0];
	$header      = 'SAML' === $protocol_inuse ? 'Selected Service Provider : SAML' :
					( 'JWT' === $protocol_inuse ? 'Selected Service Provider : JWT ' : 'Selected Service Provider : WS-FED ' );
	$test_window = '';
	$relay_state = ! empty( $sp ) ? $sp->mo_idp_default_relayState : ''; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Refers to mo_idp_default_relay_state.
	if ( 'JWT' === $protocol_inuse ) {
		include MSI_DIR . 'views/idp-jwt-settings.php';
	} elseif ( 'WSFED' === $protocol_inuse ) {
		include MSI_DIR . 'views/idp-wsfed-settings.php';
	} else {
		include MSI_DIR . 'views/idp-settings.php';
	}
}
