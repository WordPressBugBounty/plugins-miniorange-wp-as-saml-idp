<?php
/**
 * This file runs automatically when the user deletes
 * the plugin in order to clear out any plugin options
 * and/or settings specific to the plugin.
 *
 * @package miniorange-wp-as-saml-idp
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit();
}

if ( ! get_site_option( 'idp_keep_settings_intact' ) ) {
	global $wpdb;

	delete_site_option( 'mo_idp_transactionId' );
	delete_site_option( 'mo_idp_admin_password' );
	delete_site_option( 'mo_idp_registration_status' );
	delete_site_option( 'mo_idp_admin_phone' );
	delete_site_option( 'mo_idp_new_registration' );
	delete_site_option( 'mo_idp_admin_customer_key' );
	delete_site_option( 'mo_idp_admin_api_key' );
	delete_site_option( 'mo_idp_customer_token' );
	delete_site_option( 'mo_idp_verify_customer' );
	delete_site_option( 'mo_idp_message' );
	delete_site_option( 'mo_idp_admin_email' );
	delete_site_option( 'mo_saml_idp_plugin_version' );
	delete_site_option( 'sml_idp_lk' );
	delete_site_option( 't_site_status' );
	delete_site_option( 'site_idp_ckl' );
	delete_site_option( 'mo_idp_usr_lmt' );
	delete_site_option( 'mo_idp_entity_id' );

	// plugin settings.

	$attr_table       = is_multisite() ? 'mo_sp_attributes' : $wpdb->prefix . 'mo_sp_attributes';
	$data_table       = is_multisite() ? 'mo_sp_data' : $wpdb->prefix . 'mo_sp_data';
	$public_key_table = is_multisite() ? 'moos_oauth_public_keys' : $wpdb->prefix . 'moos_oauth_public_keys';

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Removing plugin configuration at the time of uninstall prepare not required as the table name is picked from a local string.
	$wpdb->query( "DROP TABLE IF EXISTS $attr_table" );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Removing plugin configuration at the time of uninstall prepare not required as the table name is picked from a local string.
	$wpdb->query( "DROP TABLE IF EXISTS $data_table" );

	// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- Removing plugin configuration at the time of uninstall prepare not required as the table name is picked from a local string.
	$wpdb->query( "DROP TABLE IF EXISTS $public_key_table" );
}
