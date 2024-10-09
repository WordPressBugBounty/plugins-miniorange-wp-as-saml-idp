<?php
/**
 * This file contains the `IDPSettingsHandler` class that is responsible
 * for updating IDP specific configuration such as updating the IDP
 * Entity ID.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `BaseHandler` class and contains methods
 * to update IDP specific configuration such as updating the IDP
 * Entity ID.
 */
final class IDPSettingsHandler extends BaseHandler {

	use Instance;

	/**
	 * Private constructor to prevent direct object creation.
	 */
	private function __construct() {
		$this->nonce = 'mo_idp_update_idp_settings';
	}

	/**
	 * Function to update the IDP Entity ID. It initially checks
	 * if the plugin is activated correctly, and whether the request
	 * is valid. It then updates an option in the database with the
	 * new IDP Entity ID, and regenerates the IDP Metadata XML with
	 * the new Entity ID.
	 *
	 * @param array $sanitized_post Sanitized PHP Superglobals `$_POST`.
	 */
	public function mo_change_idp_entity_id( $sanitized_post ) {
		$this->check_if_valid_plugin();
		$this->is_valid_request();
		if ( ! empty( $sanitized_post['mo_saml_idp_entity_id'] ) ) {
			update_site_option( 'mo_idp_entity_id', $sanitized_post['mo_saml_idp_entity_id'] );
			MoIDPUtility::create_metadata_file(); // regenerate the metadata file.
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'IDP_ENTITY_ID_CHANGED' ), 'SUCCESS' );
		} else {
			do_action( 'mo_idp_show_message', MoIDPMessages::show_message( 'IDP_ENTITY_ID_NULL' ), 'ERROR' );
		}
	}
}
