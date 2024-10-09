<?php
/**
 * This file contains the `SPSettingsHandler` class that is responsible
 * for processing and saving the Service Provider configuration in the
 * database.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidEncryptionCertException;
use IDP\Exception\IssuerValueAlreadyInUseException;
use IDP\Exception\NoServiceProviderConfiguredException;
use IDP\Exception\RequiredFieldsException;
use IDP\Exception\SPNameAlreadyInUseException;
use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\Database\MoDbQueries;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;
use IDP\Helper\Utilities\SAMLUtilities;
use IDP\Helper\SAML2\MetadataReader;
use IDP\Exception\MetadataFileException;
use IDP\Exception\RequiredSpNameException;

/**
 * This class extends the `SPSettingsUtility` class and
 * handles all the SP Data related settings.
 * Handles all the form submissions by the admin
 * under the Service Providers Tab.
 */
final class SPSettingsHandler extends SPSettingsUtility {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->nonce = 'mo_idp_sp_settings';
	}

	/**
	 * Function to fetch the SP Metadata from URL / read the SP
	 * Metadata from file and store the Service Provider configuration
	 * in the database.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws MetadataFileException Exception when uploaded metadata file is empty / invalid.
	 * @throws RequiredSpNameException Exception when the Service Provider name is not provided during the configuration.
	 */
	public function mo_idp_metadata_new_sp( $sanitized_post ) {
		$this->is_valid_request();
		$file = '';

		if ( ! empty( $sanitized_post['idp_sp_name'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification done using is_valid_request call already.
			if ( isset( $_FILES['metadata_file'] ) || isset( $sanitized_post['metadata_url'] ) ) {
				// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification done using is_valid_request call already.
				if ( ! empty( $_FILES['metadata_file']['tmp_name'] ) ) {
					// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.MissingUnslash,WordPress.Security.NonceVerification.Missing -- Cannot unslash file path. Nonce verification already done.
					$file = MoIDPUtility::handle_file_upload( sanitize_text_field( $_FILES['metadata_file']['tmp_name'] ) );
				} else {
					if ( ! MoIDPUtility::is_curl_installed() ) {
						do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'CURL_ERROR' ), 'ERROR' );
					}

					$url      = filter_var( $sanitized_post['metadata_url'], FILTER_SANITIZE_URL );
					$response = MoIDPUtility::mo_saml_wp_remote_get( $url, array( 'sslverify' => false ) );

					if ( ! is_null( $response ) ) {
						$file = $response['body'];
					} else {
						throw new MetadataFileException();
					}
				}

				if ( ! is_null( $file ) ) {
					$this->upload_metadata( $file, $sanitized_post );
				}
			} else {
				throw new MetadataFileException();
			}
		} else {
			throw new RequiredSpNameException();
		}
	}

	/**
	 * Function to parse the SP Metadata, process and
	 * store the Service Provider configuration in the
	 * database.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param string $file SP Metadata XML string.
	 * @param array  $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws IssuerValueAlreadyInUseException Exception when there already exists a configured Service Provider with the similar Issuer value.
	 * @throws SPNameAlreadyInUseException Exception when the Service Provider name is similar to the existing Service Provider that is configured.
	 */
	public function upload_metadata( $file, $sanitized_post ) {
		global $moidp_db_queries;

		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_set_error_handler -- Needed to handle any errors that might rise from DOMDocument::loadXml() 
		$old_error_handler = set_error_handler( array( $this, 'handle_xml_error' ) );
		$document          = new \DOMDocument();
		$document->loadXML( $file );
		restore_error_handler();

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument attributes.
		$first_child = $document->firstChild;

		if ( ! empty( $first_child ) ) {

			$metadata          = new MetadataReader( $document );
			$service_providers = $metadata->get_service_providers();

			if ( ! preg_match( '/^\w*$/', $sanitized_post['idp_sp_name'] ) ) {
				do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'SP_NAME_INVALID' ), 'ERROR' );
				return;
			}
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification done using is_valid_request call already.
			if ( empty( $service_providers ) && ! empty( $_FILES['metadata_file']['tmp_name'] ) ) {
				do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'METADATA_FILE_INVALID' ), 'ERROR' );
				return;
			}
			if ( empty( $service_providers ) && ! empty( $sanitized_post['metadata_url'] ) ) {
				do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'METADATA_URL_INVALID' ), 'ERROR' );
				return;
			}

			foreach ( $service_providers as $key => $sp ) {
				$entity_id      = $sp->get_entity_id();
				$acs_url        = $sp->get_acs_url();
				$name_id_format = $sp->get_name_id_format();
				$signed         = $sp->get_signed_assertion();
			}

			$where                   = array();
			$data                    = array();
			$sp_name                 = sanitize_text_field( $sanitized_post['idp_sp_name'] );
			$where['mo_idp_sp_name'] = $sp_name;
			$data['mo_idp_sp_name']  = $sp_name;

			$this->check_name_already_in_use( $sp_name );
			$this->check_issuer_already_in_use( $entity_id, null, $sp_name );

			$data['mo_idp_protocol_type'] = sanitize_text_field( $sanitized_post['mo_idp_protocol_type'] );
			$data['mo_idp_sp_issuer']     = $entity_id;
			$data['mo_idp_acs_url']       = $acs_url;
			$data['mo_idp_nameid_format'] = $name_id_format;

			$data['mo_idp_logout_url']          = null;
			$data['mo_idp_cert']                = null;
			$data['mo_idp_cert_encrypt']        = null;
			$data['mo_idp_default_relayState']  = null;
			$data['mo_idp_logout_binding_type'] = 'HttpRedirect';

			$data['mo_idp_response_signed']     = null;
			$data['mo_idp_assertion_signed']    = ( 'true' === $signed ) ? 1 : null;
			$data['mo_idp_encrypted_assertion'] = null;

			$count = $moidp_db_queries->get_sp_count();
			if ( $count >= 1 ) {
				$moidp_db_queries->update_metadata_data();
			}

			$insert     = $moidp_db_queries->insert_sp_data( $data );
			$cert_saved = MoIDPUtility::save_new_cert_to_db_for_sp();

			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'SETTINGS_SAVED' ), 'SUCCESS' );
		} else {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification done using is_valid_request call already.
			if ( ! empty( $_FILES['metadata_file']['tmp_name'] ) ) {
				do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'METADATA_FILE_INVALID' ), 'ERROR' );
			}
			if ( ! empty( $sanitized_post['metadata_url'] ) ) {
				do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'METADATA_URL_INVALID' ), 'ERROR' );
			}
		}
	}

	/**
	 * Function to insert a new SP into the database.
	 * This function saves the data provided in the
	 * Service Provider config, into the database.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws IssuerValueAlreadyInUseException Exception when there already exists a configured Service Provider with the similar Issuer value.
	 * @throws RequiredFieldsException Exception when certain fields are either missing or empty in a given form / array.
	 * @throws SPNameAlreadyInUseException Exception when the Service Provider name is similar to the existing Service Provider that is configured.
	 * @throws InvalidEncryptionCertException Exception when invalid certificate is provided.
	 */
	public function mo_idp_save_new_sp( $sanitized_post ) {
		global $moidp_db_queries;

		$this->check_if_valid_plugin();
		$this->is_valid_request();
		$this->check_if_required_fields_empty(
			array(
				'idp_sp_name'       => $sanitized_post,
				'idp_sp_issuer'     => $sanitized_post,
				'idp_acs_url'       => $sanitized_post,
				'idp_nameid_format' => $sanitized_post,
			)
		);

		$where                    = array();
		$data                     = array();
		$sp_name                  = sanitize_text_field( $sanitized_post['idp_sp_name'] );
		$where['mo_idp_sp_name']  = $sp_name;
		$data['mo_idp_sp_name']   = $sp_name;
		$issuer                   = sanitize_text_field( $sanitized_post['idp_sp_issuer'] );
		$data['mo_idp_sp_issuer'] = $issuer;

		$this->check_issuer_already_in_use( $issuer, null, $sp_name );
		$this->check_name_already_in_use( $sp_name );

		$data = $this->collect_data( $sanitized_post, $data );

		$insert     = $moidp_db_queries->insert_sp_data( $data );
		$cert_saved = MoIDPUtility::save_new_cert_to_db_for_sp();

		do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'SETTINGS_SAVED' ), 'SUCCESS' );
	}

	/**
	 * Function to update the SP in the database.
	 * This function updates the data provided in the
	 * Service Provider config, in the database for the SP.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws IssuerValueAlreadyInUseException Exception when there already exists a configured Service Provider with the similar Issuer value.
	 * @throws NoServiceProviderConfiguredException Exception when the ID of the Service Provider is blank.
	 * @throws RequiredFieldsException Exception when certain fields are either missing or empty in a given form / array.
	 * @throws SPNameAlreadyInUseException Exception when the Service Provider name is similar to the existing Service Provider that is configured.
	 * @throws InvalidEncryptionCertException Exception when invalid certificate is provided.
	 */
	public function mo_idp_edit_sp( $sanitized_post ) {
		global $moidp_db_queries;

		$this->check_if_valid_plugin();
		$this->is_valid_request();
		$this->check_if_required_fields_empty(
			array(
				'idp_sp_name'       => $sanitized_post,
				'idp_sp_issuer'     => $sanitized_post,
				'idp_acs_url'       => $sanitized_post,
				'idp_nameid_format' => $sanitized_post,
			)
		);
		$this->check_if_valid_service_provider( $sanitized_post, true, 'service_provider' );

		$data                     = array();
		$where                    = array();
		$id                       = $sanitized_post['service_provider'];
		$where['id']              = $id;
		$sp_name                  = sanitize_text_field( $sanitized_post['idp_sp_name'] );
		$data['mo_idp_sp_name']   = $sp_name;
		$issuer                   = sanitize_text_field( $sanitized_post['idp_sp_issuer'] );
		$data['mo_idp_sp_issuer'] = $issuer;

		$this->check_if_valid_service_provider( $moidp_db_queries->get_sp_data( $id ) );
		$this->check_issuer_already_in_use( $issuer, $id, null );
		$this->check_name_already_in_use( $sp_name, $id );

		$data = $this->collect_data( $sanitized_post, $data );

		$moidp_db_queries->update_sp_data( $data, $where );
		$cert_saved = MoIDPUtility::save_new_cert_to_db_for_sp( $id );
		do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'SETTINGS_SAVED' ), 'SUCCESS' );
	}

	/**
	 * Function to delete SP data ( all configurations )
	 * from the SP Data and SP Attribute table in the
	 * database.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 */
	public function mo_idp_delete_sp_settings( $sanitized_post ) {
		global $moidp_db_queries;

		MoIDPUtility::start_session();
		$this->check_if_valid_plugin();
		$this->is_valid_request();

		$sp_where                  = array();
		$sp_attr_where             = array();
		$id                        = $sanitized_post['sp_id'];
		$sp_where['id']            = $id;
		$sp_attr_where['mo_sp_id'] = $id;

		$moidp_db_queries->delete_sp( $sp_where, $sp_attr_where );

		if ( isset( $_SESSION['SP'] ) ) {
			unset( $_SESSION['SP'] );
		}

		do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'SP_DELETED' ), 'SUCCESS' );
	}

	/**
	 * Function to update the NameID attribute for
	 * the given Service Provider in the database.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws NoServiceProviderConfiguredException Exception when the ID of the Service Provider is blank.
	 */
	public function mo_idp_change_name_id( $sanitized_post ) {
		global $moidp_db_queries;

		$this->check_if_valid_plugin();
		$this->is_valid_request();
		$this->check_if_valid_service_provider( $sanitized_post, true, 'service_provider' );

		$data                       = array();
		$where                      = array();
		$sp_id                      = $sanitized_post['service_provider'];
		$where['id']                = $sanitized_post['service_provider'];
		$data['mo_idp_nameid_attr'] = $sanitized_post['idp_nameid_attr'];
		$moidp_db_queries->update_sp_data( $data, $where );
		do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'SETTINGS_SAVED' ), 'SUCCESS' );
	}

	/**
	 * This function is used to just change the SP id in the
	 * session so that all the appropriate settings of the SP
	 * can be shown to the user.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @throws NoServiceProviderConfiguredException Exception when the ID of the Service Provider is blank.
	 */
	public function mo_sp_change_settings( $sanitized_post ) {
		$this->check_if_valid_plugin();
		$this->is_valid_request();
		$this->check_if_valid_service_provider( $sanitized_post, true, 'service_provider' );
	}

	/**
	 * Function is used to collect and process the post data saved
	 * by the admin from under the Service Providers tab.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 * @param array $data Array to store the SP config.
	 * @return array
	 * @throws InvalidEncryptionCertException Exception when invalid certificate is provided.
	 */
	private function collect_data( $sanitized_post, $data ) {
		$data['mo_idp_acs_url']       = esc_url_raw( $sanitized_post['idp_acs_url'] );
		$data['mo_idp_nameid_format'] = sanitize_text_field( $sanitized_post['idp_nameid_format'] );
		$data['mo_idp_protocol_type'] = sanitize_text_field( $sanitized_post['mo_idp_protocol_type'] );

		$data['mo_idp_logout_url']          = null;
		$data['mo_idp_cert']                = ! empty( $sanitized_post['mo_idp_cert'] ) ? SAMLUtilities::sanitize_certificate( trim( $sanitized_post['mo_idp_cert'] ) ) : null;
		$data['mo_idp_cert_encrypt']        = null;
		$data['mo_idp_default_relayState']  = ! empty( $sanitized_post['idp_default_relayState'] ) ? $sanitized_post['idp_default_relayState'] : null;
		$data['mo_idp_logout_binding_type'] = ! empty( $sanitized_post['mo_idp_logout_binding_type'] ) ? $sanitized_post['mo_idp_logout_binding_type'] : 'HttpRedirect';

		$data['mo_idp_response_signed']     = null;
		$data['mo_idp_assertion_signed']    = isset( $sanitized_post['idp_assertion_signed'] ) ? $sanitized_post['idp_assertion_signed'] : null;
		$data['mo_idp_encrypted_assertion'] = null;

		$this->check_if_valid_encryption_cert_provided( $data['mo_idp_encrypted_assertion'], $data['mo_idp_cert_encrypt'] );

		return $data;
	}

	/**
	 * `DOMDocument::loadXml()` reports an error instead of throwing an exception
	 * when the XML is not well-formed. This function allows us to catch an
	 * exception instead of generating an error.
	 *
	 * @param int    $errno Refers to the level of the error raised.
	 * @param string $errstr Refers to the error message.
	 * @param string $errfile Refers to the filename that the error was raised in.
	 * @param int    $errline Refers to the line number where the error was raised.
	 * @return boolean|void
	 */
	private function handle_xml_error( $errno, $errstr, $errfile, $errline ) {
		if ( E_WARNING === $errno && ( substr_count( $errstr, 'DOMDocument::loadXML()' ) > 0 ) ) {
			return;
		} else {
			return false;
		}
	}
}
