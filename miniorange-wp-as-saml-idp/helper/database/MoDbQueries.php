<?php
/**
 * This file contains the `MoDbQueries` class that is
 * responsible for carrying out all database operations.
 *
 * @package miniorange-wp-as-saml-idp\helper\database
 */

namespace IDP\Helper\Database;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Traits\Instance;

require_once ABSPATH . 'wp-admin/includes/upgrade.php';

/**
 * This class handles all the database operations.
 */
final class MoDbQueries {

	use Instance;

	/**
	 * Name of the table where Service
	 * Provider configuration is stored.
	 *
	 * @var string $sp_data_table_name
	 */
	private $sp_data_table_name;

	/**
	 * Name of the DB table where attribute
	 * mapping configuration is stored.
	 *
	 * @var string $sp_attr_table_name
	 */
	private $sp_attr_table_name;

	/**
	 * Name of the DB table where x509
	 * certificates are stored for SP.
	 *
	 * @var string $public_key_table
	 */
	private $public_key_table;

	/**
	 * Name of the default WordPress usermeta
	 * table.
	 *
	 *  @var string $user_meta_table
	 */
	private $user_meta_table;

	/**
	 * Value of the db collate
	 *
	 * @var string collate
	 */
	private $collate = '';

	/**
	 * Private constructor to prevent direct object creation.
	 */
	private function __construct() {
		global $wpdb;
		$this->sp_data_table_name = is_multisite() ? 'mo_sp_data' : $wpdb->prefix . 'mo_sp_data';
		$this->sp_attr_table_name = is_multisite() ? 'mo_sp_attributes' : $wpdb->prefix . 'mo_sp_attributes';
		$this->public_key_table   = is_multisite() ? 'moos_oauth_public_keys' : $wpdb->prefix . 'moos_oauth_public_keys';
		$this->user_meta_table    = $wpdb->prefix . 'usermeta';

		if ( $wpdb->has_cap( 'collation' ) ) {
			if ( ! empty( $wpdb->charset ) ) {
				$this->collate .= "DEFAULT CHARACTER SET $wpdb->charset";
			}
			if ( ! empty( $wpdb->collate ) ) {
				$this->collate .= " COLLATE $wpdb->collate";
			}
		}
	}

	/**
	 * Function generates the SP and Attributes Tables.
	 *
	 * @return void
	 */
	private function generate_tables() {

		$table1 = 'CREATE TABLE ' . $this->sp_data_table_name . " (
                    id bigint(20) NOT NULL auto_increment,
                    mo_idp_sp_name text NOT NULL,
                    mo_idp_sp_issuer longtext NOT NULL,
                    mo_idp_acs_url longtext NOT NULL,
                    mo_idp_cert longtext NULL,
                    mo_idp_cert_encrypt longtext NULL,
                    mo_idp_nameid_format longtext NOT NULL,
                    mo_idp_nameid_attr varchar(55) DEFAULT 'emailAddress' NOT NULL,
                    mo_idp_response_signed smallint NULL,
                    mo_idp_assertion_signed smallint NULL,
                    mo_idp_encrypted_assertion smallint NULL,
                    mo_idp_enable_group_mapping smallint NULL,
                    mo_idp_default_relayState longtext NULL,
                    mo_idp_logout_url longtext NULL,
                    mo_idp_logout_binding_type varchar(15) DEFAULT 'HttpRedirect' NOT NULL,
                    mo_idp_protocol_type longtext NOT NULL,
                    PRIMARY KEY  (id)
                )$this->collate;";

		$table2 = 'CREATE TABLE ' . $this->sp_attr_table_name . " (
                    id bigint(20) NOT NULL auto_increment,
                    mo_sp_id bigint(20),
                    mo_sp_attr_name longtext NOT NULL,
                    mo_sp_attr_value longtext NOT NULL,
                    mo_attr_type smallint DEFAULT 0 NOT NULL,
                    PRIMARY KEY  (id),
                    FOREIGN KEY  (mo_sp_id) REFERENCES $this->sp_data_table_name (id)
                )$this->collate;";

		dbDelta( $table1 );
		dbDelta( $table2 );
		$public_cert_table_created = $this->create_public_key_table();
	}

	/**
	 * Creates the public key table
	 *
	 * @return array Strings containing the results of the various update queries.
	 */
	public function create_public_key_table() {
		$public_key_table = 'CREATE TABLE IF NOT EXISTS ' . $this->public_key_table . " (
			client_id VARCHAR(80),
			public_key VARCHAR(8000),
			private_key VARCHAR(8000),
			encryption_algorithm VARCHAR(80) DEFAULT 'RS256'
			)$this->collate;";

		return dbDelta( $public_key_table );
	}

	/**
	 * Checks the DB version and decides if the tables need
	 * to be created or updated.
	 *
	 * @return void
	 */
	public function check_tables_and_run_queries() {
		$old_version = get_site_option( 'mo_saml_idp_plugin_version' );
		if ( ! $old_version ) {
			update_site_option( 'mo_saml_idp_plugin_version', MSI_DB_VERSION );
			$this->generate_tables();
			if ( ob_get_contents() ) {
				ob_clean();
			}
		} else {
			if ( $old_version < MSI_DB_VERSION ) {
				update_site_option( 'mo_saml_idp_plugin_version', MSI_DB_VERSION );
			}
			$this->check_version_and_update( $old_version );
		}
	}

	/**
	 * Checks the current DB version and runs the
	 * appropriate update queries for updating the
	 * table.
	 *
	 * @param string $old_version Refers to the existing DB version.
	 * @return void
	 */
	private function check_version_and_update( $old_version ) {
		switch ( $old_version ) {
			case '1.0':
				$this->mo_update_cert();
				// Fall-through intended.
			case '1.0.2':
				$this->mo_update_relay();
				// Fall-through intended.
			case '1.0.4':
				$this->mo_update_logout();
				// Fall-through intended.
			case '1.2':
				$this->mo_update_custom_attr();
				// Fall-through intended.
			case '1.3':
				$this->mo_update_protocol_type();
				// Fall-through intended.
			case '1.4':
				$public_cert_table_created = $this->create_public_key_table();
		}
	}

	// phpcs:disable Squiz.Commenting.InlineComment.InvalidEndChar, Squiz.PHP.CommentedOutCode.Found, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.DirectDatabaseQuery.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQL.NotPrepared -- Operations required for proper functioning of the plugin.

	/**
	 * Runs the update query to update the protocol type i.e. SAML or WS-Fed
	 * and adding a column for user selected protocol type in the database.
	 *
	 * @return void
	 */
	private function mo_update_protocol_type() {
		global $wpdb;
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . ' ADD COLUMN mo_idp_protocol_type longtext NOT NULL' );
		$wpdb->query( 'UPDATE ' . $this->sp_data_table_name . " SET mo_idp_protocol_type = 'SAML'" );
	}

	/**
	 * Runs the update query to update the SP table and
	 * add logout url and logout binding type columns.
	 *
	 * @return void
	 */
	private function mo_update_logout() {
		global $wpdb;
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . ' ADD COLUMN mo_idp_logout_url longtext NULL' );
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . " ADD COLUMN mo_idp_logout_binding_type varchar(15) DEFAULT 'HttpRedirect' NOT NULL" );
	}

	/**
	 * Runs the update query to update the SP table and
	 * add SP cert and encrypted_assertion allowed column.
	 *
	 * @return void
	 */
	private function mo_update_cert() {
		global $wpdb;
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . ' ADD COLUMN mo_idp_cert_encrypt longtext NULL' );
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . ' ADD COLUMN mo_idp_encrypted_assertion smallint NULL' );
	}

	/**
	 * Runs the update query to update the SP table and
	 * add the default relay state column.
	 *
	 * @return void
	 */
	private function mo_update_relay() {
		global $wpdb;
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . ' ADD COLUMN mo_idp_default_relayState longtext NULL' );
	}

	/**
	 * Runs the update query to update the Attribute table
	 * and add the attr_type column to facilitate custom attribute.
	 *
	 * @return void
	 */
	private function mo_update_custom_attr() {
		global $wpdb;
		$wpdb->query( 'ALTER TABLE ' . $this->sp_attr_table_name . ' ADD COLUMN mo_attr_type smallint DEFAULT 0 NOT NULL' );
		$wpdb->update( $this->sp_attr_table_name, array( 'mo_attr_type' => '1' ), array( 'mo_sp_attr_name' => 'groupMapName' ) );
	}

	/**
	 * Gets the list of all SPs from the SP table.
	 *
	 * @return array|object|null
	 */
	public function get_sp_list() {
		global $wpdb;
		return $wpdb->get_results( 'SELECT * FROM ' . $this->sp_data_table_name );
	}

	/**
	 * Gets all the SP data for the ID passed from the
	 * database.
	 *
	 * @param string $id References the ID of the SP in the database.
	 * @return array|object|null|void
	 */
	public function get_sp_data( $id ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . $this->sp_data_table_name . ' WHERE id=%s', $id ) );
	}

	/**
	 * Gets the count of all the SPs in the SP Table.
	 *
	 * @return string|null
	 */
	public function get_sp_count() {
		global $wpdb;
		$sql = 'SELECT COUNT(*) FROM ' . $this->sp_data_table_name;
		return $wpdb->get_var( $sql );
	}

	/**
	 * Gets all the Attribute mapping done for the
	 * SP from the Attribute table.
	 *
	 * @param string $id References the ID of the SP in the database.
	 * @return array|object|null
	 */
	public function get_all_sp_attributes( $id ) {
		global $wpdb;
		return $wpdb->get_results( $wpdb->prepare( 'SELECT * FROM ' . $this->sp_attr_table_name . ' WHERE mo_sp_id = %s', $id ) );
	}

	/**
	 * Get the SP details from the SP Table based on the
	 * issuer value.
	 *
	 * @param string $issuer References the SP issuer value.
	 * @return array|object|null|void
	 */
	public function get_sp_from_issuer( $issuer ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . $this->sp_data_table_name . ' WHERE mo_idp_sp_issuer = %s', $issuer ) );
	}

	/**
	 * Get the SP details from the SP Table based on the
	 * name value.
	 *
	 * @param string $name References the name of the SP in the database.
	 * @return array|object|null|void
	 */
	public function get_sp_from_name( $name ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . $this->sp_data_table_name . ' WHERE mo_idp_sp_name = %s',  $name ) );
	}

	/**
	 * Get the SP details from the SP Table based on the
	 * acs value.
	 *
	 * @param string $acs References the SP acs value.
	 * @return array|object|null|void
	 */
	public function get_sp_from_acs( $acs ) {
		global $wpdb;
		return $wpdb->get_row( $wpdb->prepare( 'SELECT * FROM ' . $this->sp_data_table_name . ' WHERE mo_idp_acs_url = %s', $acs ) );
	}

	/**
	 * Insert a new SP in the SP table.
	 *
	 * @param array $data References the SP configuration to be saved.
	 * @return int|false
	 */
	public function insert_sp_data( $data ) {
		global $wpdb;
		return $wpdb->insert( $this->sp_data_table_name, $data );
	}

	/**
	 * Get the certificate details by SP ID
	 *
	 * @param int $sp_id SP ID to fetch certificate for.
	 * @return mixed
	 */
	public function get_cert_by_sp_id( $sp_id ) {
		global $wpdb;
		return $wpdb->get_row( "SELECT * FROM $this->public_key_table WHERE client_id = '$sp_id'" );
	}

	/**
	 * Stores certificate for SP in the cert table.
	 * Updates record if it already exists.
	 *
	 * @param string   $public_key Public key of the certificate to be saved to db.
	 * @param string   $private_key Private key of the certificate to be saved to db.
	 * @param int|bool $sp_id Id of the service provider to save the cert for, if passed
	 *                          as false then we save certificate for the 1st SP in db.
	 *
	 * @return int|false
	 */
	public function insert_cert_for_sp( $public_key, $private_key, $sp_id = false ) {
		global $wpdb;

		if ( false === $sp_id ) {
			$sp_data = $this->get_sp_list();
			if ( empty( $sp_data[0] ) ) {
				return;
			}
			$sp_id = $sp_data[0]->id;
		}
		$cert_for_sp_id = $this->get_cert_by_sp_id( $sp_id );

		$data                = array();
		$data['client_id']   = $sp_id;
		$data['public_key']  = $public_key;
		$data['private_key'] = $private_key;

		if ( empty( $cert_for_sp_id ) ) {
			return $wpdb->insert( $this->public_key_table, $data );
		} else {
			return $wpdb->update( $this->public_key_table, $data, array( 'client_id' => $sp_id ) );
		}
	}

	/**
	 * Deletes all existing SP configurations, and resets
	 * the auto-increment counter to 0.
	 *
	 * @return void
	 */
	public function update_metadata_data() {
		global $wpdb;
		$wpdb->query( 'DELETE FROM ' . $this->sp_data_table_name );
		$wpdb->query( 'ALTER TABLE ' . $this->sp_data_table_name . ' AUTO_INCREMENT=0' );
		$wpdb->query( 'DELETE FROM ' . $this->public_key_table );
	}

	/**
	 * Updates the SP values in the SP table.
	 *
	 * @param array $data References the column value pair.
	 * @param array $where References the where clause.
	 * @return void
	 */
	public function update_sp_data( $data, $where ) {
		global $wpdb;
		$wpdb->update( $this->sp_data_table_name, $data, $where );
	}

	/**
	 * Delete the SP data from both SP and Attribute tables.
	 *
	 * @param array $sp_where References the where clause for SP Table.
	 * @param array $sp_attr_where References the where clause for Attribute Table.
	 * @return void
	 */
	public function delete_sp( $sp_where, $sp_attr_where ) {
		global $wpdb;

		$this->delete_sp_attributes( $sp_attr_where );
		$cert_deleted = $this->delete_public_certificate_from_table( $sp_where['id'] );
		$wpdb->delete( $this->sp_data_table_name, $sp_where, $where_format = null );
	}

	/**
	 * Delete a certificate from the certificate table.
	 *
	 * @param int $sp_id SP ID to delete certificate for.
	 * @return int|false The number of rows updated, or false on error.
	 */
	public function delete_public_certificate_from_table( $sp_id ) {
		global $wpdb;
		$where_format['client_id'] = $sp_id;
		return $wpdb->delete( $this->public_key_table, $where_format );
	}

	/**
	 * Deletes the SP attribute data from the Attribute table.
	 *
	 * @param array $attr_where References the where clause for Attribute Table.
	 * @return void
	 */
	public function delete_sp_attributes( $attr_where ) {
		global $wpdb;
		$wpdb->delete( $this->sp_attr_table_name, $attr_where, $where_format = null );
	}

	/**
	 * Get the distinct unique meta keys from the user_meta table
	 * to be shown in the attributes dropdown.
	 *
	 * @return array|object|null
	 */
	public function get_distinct_meta_attributes() {
		global $wpdb;
		return $wpdb->get_results( 'SELECT DISTINCT meta_key FROM ' . $this->user_meta_table );
	}
}

// phpcs:enable
