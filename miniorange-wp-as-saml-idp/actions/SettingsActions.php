<?php
/**
 * This file contains the `SettingsActions` class that defines
 * methods to handle form submissions by the admin.
 *
 * @package miniorange-wp-as-saml-idp\actions
 */

namespace IDP\Actions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidEncryptionCertException;
use IDP\Exception\IssuerValueAlreadyInUseException;
use IDP\Exception\MetadataFileException;
use IDP\Exception\NoServiceProviderConfiguredException;
use IDP\Exception\RequiredFieldsException;
use IDP\Exception\RequiredSpNameException;
use IDP\Exception\SPNameAlreadyInUseException;
use IDP\Exception\SupportQueryRequiredFieldsException;
use IDP\Handler\DemoRequestHandler;
use IDP\Handler\FeedbackHandler;
use IDP\Handler\IDPSettingsHandler;
use IDP\Handler\SPSettingsHandler;
use IDP\Handler\SupportHandler;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class is the central class to handle all the plugin settings.
 * It handles all the form submissions by the admin. This class routes
 * the flow to appropriate class to handle the form post data based on
 * the option variable in the form post.
 */
class SettingsActions extends BasePostAction {

	use Instance;

	/**
	 * Instance of `SPSettingsHandler` class
	 * to call its required methods.
	 *
	 * @var SPSettingsHandler $handler
	 */
	private $handler;

	/**
	 * Instance of `SupportHandler` class
	 * to call its required methods.
	 *
	 * @var SupportHandler $support_handler
	 */
	private $support_handler;

	/**
	 * Instance of `IDPSettingsHandler` class
	 * to call its required methods.
	 *
	 * @var IDPSettingsHandler $idp_settings_handler
	 */
	private $idp_settings_handler;

	/**
	 * Instance of `FeedbackHandler` class
	 * to call its required methods.
	 *
	 * @var FeedbackHandler $feedback_handler
	 */
	private $feedback_handler;

	/**
	 * Instance of `DemoRequestHandler` class
	 * to call its required methods.
	 *
	 * @var DemoRequestHandler $demo_request_handler
	 */
	private $demo_request_handler;

	/**
	 * Constructor function, which instantiates the required handlers
	 * and makes a call to the parent (`BasePostAction`) constructor.
	 */
	public function __construct() {
		$this->handler              = SPSettingsHandler::get_instance();
		$this->support_handler      = SupportHandler::get_instance();
		$this->idp_settings_handler = IDPSettingsHandler::get_instance();
		$this->feedback_handler     = FeedbackHandler::get_instance();
		$this->demo_request_handler = DemoRequestHandler::get_instance();
		$this->nonce                = 'idp_settings';
		parent::__construct();
	}

	/**
	 * Defines all the option values of the plugin settings
	 * forms which is used to distinguish our forms.
	 *
	 * @var array $funcs
	 */
	private $funcs = array(
		'mo_add_idp',
		'mo_edit_idp',
		'mo_show_sp_settings',
		'mo_idp_delete_sp_settings',
		'mo_idp_entity_id',
		'change_name_id',
		'mo_idp_contact_us_query_option',
		'mo_idp_feedback_option',
		'mo_idp_use_new_cert',
		'saml_idp_upload_metadata',
		'mo_idp_request_demo',
	);

	/**
	 * Handle the form post data. Check for any kind of
	 * Exception that may occur during processing of form post
	 * data and set the current SP ID in session.
	 *
	 * @return void
	 */
	public function handle_post_data() {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function in their respective Handler classes.
		if ( current_user_can( 'manage_options' ) && isset( $_POST['option'] ) ) {
			// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function in their respective Handler classes.
			$option = trim( sanitize_text_field( wp_unslash( $_POST['option'] ) ) );
			try {
				$this->route_post_data( $option );
			} catch ( NoServiceProviderConfiguredException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( RequiredFieldsException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( SPNameAlreadyInUseException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( IssuerValueAlreadyInUseException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( InvalidEncryptionCertException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( MetadataFileException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( RequiredSpNameException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( SupportQueryRequiredFieldsException $e ) {
				do_action( 'mo_idp_show_message', $e->getMessage(), 'ERROR' );
			} catch ( \Exception $e ) {
				if ( MSI_DEBUG ) {
					MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
				}
				wp_die( esc_html( $e->getMessage() ) );
			}
		}
	}

	/**
	 * Route the form post data. Check for any kind of
	 * Exception that may occur during processing of form post
	 * data.
	 *
	 * @param string $option Reference for option value in the form post.
	 * @throws InvalidEncryptionCertException Exception when invalid certificate is provided.
	 * @throws IssuerValueAlreadyInUseException Exception when there already exists a configured Service Provider with the similar Issuer value.
	 * @throws MetadataFileException Exception when uploaded metadata file is empty / invalid.
	 * @throws NoServiceProviderConfiguredException Exception when the ID of the Service Provider is blank.
	 * @throws RequiredFieldsException Exception when certain fields are either missing or empty in a given form / array.
	 * @throws RequiredSpNameException Exception when the Service Provider name is not provided during the configuration.
	 * @throws SPNameAlreadyInUseException Exception when the Service Provider name is similar to the existing Service Provider that is configured.
	 * @throws SupportQueryRequiredFieldsException Exception when the fields in the Support Query form are empty.
	 */
	public function route_post_data( $option ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Missing -- Nonce verification handled in the wrapper function in their respective Handler classes.
		$sanitized_post = MoIDPUtility::sanitize_associative_array( $_POST );
		switch ( $option ) {
			case $this->funcs[0]:
				$this->handler->mo_idp_save_new_sp( $sanitized_post );
				break;
			case $this->funcs[1]:
				$this->handler->mo_idp_edit_sp( $sanitized_post );
				break;
			case $this->funcs[2]:
				$this->handler->mo_sp_change_settings( $sanitized_post );
				break;
			case $this->funcs[3]:
				$this->handler->mo_idp_delete_sp_settings( $sanitized_post );
				break;
			case $this->funcs[4]:
				$this->idp_settings_handler->mo_change_idp_entity_id( $sanitized_post );
				break;
			case $this->funcs[5]:
				$this->handler->mo_idp_change_name_id( $sanitized_post );
				break;
			case $this->funcs[6]:
				$this->support_handler->mo_idp_support_query( $sanitized_post );
				break;
			case $this->funcs[7]:
				$this->feedback_handler->mo_send_feedback( $sanitized_post );
				break;
			case $this->funcs[8]:
				MoIDPUtility::use_new_certs();
				break;
			case $this->funcs[9]:
				$this->handler->mo_idp_metadata_new_sp( $sanitized_post );
				break;
			case $this->funcs[10]:
				$this->demo_request_handler->mo_idp_demo_request_function( $sanitized_post );
				break;
		}
	}
}
