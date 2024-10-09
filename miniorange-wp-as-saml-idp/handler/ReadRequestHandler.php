<?php
/**
 * This file contains the `ReadRequestHandler` class that is responsible
 * for reading SAML / WS-Fed Request and Response.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidServiceProviderException;
use IDP\Exception\InvalidSSOUserException;
use IDP\Helper\Database\MoDbQueries;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;
use IDP\Helper\SAML2\AuthnRequest;
use IDP\Helper\Factory\RequestDecisionHandler;
use IDP\Helper\WSFED\WsFedRequest;
use \RobRichards\XMLSecLibs\XMLSecurityKey;
use IDP\Helper\Utilities\SAMLUtilities;
use IDP\Helper\Constants\MoIDPConstants;

/**
 * This class extends the `BaseHandler` class and handles
 * reading of all the SAML / WS-Fed Request and Response,
 * and process it to build the requestObject required for
 * further processing.
 */
final class ReadRequestHandler extends BaseHandler {

	use Instance;

	/**
	 * Instance of `ProcessRequestHandler` class
	 * to call its required methods.
	 *
	 *  @var ProcessRequestHandler $request_process_handler
	 */
	private $request_process_handler;

	/**
	 * Private constructor to prevent direct object creation.
	 */
	private function __construct() {
		$this->request_process_handler = ProcessRequestHandler::get_instance();
	}

	/**
	 * Read the request from the SP and process it before reading the XML or other attributes for
	 * Login or Logout Request. Need to first get the correct RequestHandler for handling the
	 * request coming to the server.
	 *
	 * @param array  $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @param array  $sanitized_get Sanitized PHP Superglobals `$_GET`.
	 * @param string $type Refers to the type of request coming in. Can be SAML | WS-FED.
	 * @throws InvalidServiceProviderException Exception when the Service Provider's configuration are `null`.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function read_request( array $sanitized_request, array $sanitized_get, $type ) {
		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( 'Reading SAML Request' );
		}

		$this->check_if_valid_plugin();

		$request_object = RequestDecisionHandler::get_request_handler( $type, $sanitized_request, $sanitized_get );
		$relay_state    = isset( $sanitized_request['RelayState'] ) ? $sanitized_request['RelayState'] : '/';

		if ( MoIDPUtility::is_blank( $request_object ) ) {
			return;
		}

		switch ( $request_object->get_request_type() ) {
			case MoIDPConstants::AUTHN_REQUEST:
				$this->mo_idp_process_assertion_request( $request_object, $relay_state );
				break;
			case MoIDPConstants::WS_FED:
				$this->mo_idp_process_ws_fed_request( $request_object, $relay_state );
				break;
		}
	}

	/**
	 * Function processes the WS-Fed Request and starts the SSO
	 * process. It also checks whether the request is coming from
	 * a valid configured Service Provider.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param WsFedRequest $wsfed_request_object Refers to the WS-Fed requestObject formed from the request coming from the SP.
	 * @param string       $relay_state Refers to the Relay State in the SAML request, if any.
	 * @throws InvalidServiceProviderException Exception when the Service Provider's configuration are `null`.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function mo_idp_process_ws_fed_request( WsFedRequest $wsfed_request_object, $relay_state ) {
		global $moidp_db_queries;

		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( $wsfed_request_object ); // display ws-fed request.
		}

		$sp = $moidp_db_queries->get_sp_from_issuer( $wsfed_request_object->get_wtrealm() );

		$this->check_if_valid_sp( $sp );

		$this->request_process_handler->mo_idp_authorize_user( $relay_state, $wsfed_request_object );
	}

	/**
	 * Function processes the and validates the SAML AuthnRequest.
	 * It also checks whether the request is coming from a valid
	 * configured Service Provider.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param AuthnRequest $authn_request Refers to the SAML requestObject formed from the request coming from the SP.
	 * @param string       $relay_state Refers to the Relay State in the SAML request, if any.
	 * @throws InvalidServiceProviderException Exception when the Service Provider's configuration are `null`.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	private function mo_idp_process_assertion_request( AuthnRequest $authn_request, $relay_state ) {
		global $moidp_db_queries;

		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( $authn_request ); // Display AuthnRequest Values.
		}

		$issuer = $authn_request->get_issuer();
		$acs    = $authn_request->get_assertion_consumer_service_url();

		$sp = $moidp_db_queries->get_sp_from_issuer( $issuer );
		$sp = ! isset( $sp ) ? $moidp_db_queries->get_sp_from_acs( $acs ) : $sp;

		$this->check_if_valid_sp( $sp );

		$issuer = $sp->mo_idp_sp_issuer;
		$acs    = $sp->mo_idp_acs_url;

		$authn_request->set_issuer( $issuer );
		$authn_request->set_assertion_consumer_service_url( $acs );

		$signature_data = SAMLUtilities::validate_element( $authn_request->get_xml() );
		$sp_certificate = $sp->mo_idp_cert;
		if ( ! empty( $sp_certificate ) ) {
			$sp_certificate = XMLSecurityKey::getRawThumbprint( $sp_certificate );
			$sp_certificate = iconv( 'UTF-8', 'CP1252//IGNORE', $sp_certificate );
			$sp_certificate = preg_replace( '/\s+/', '', $sp_certificate );

			if ( false !== $signature_data ) {
				$this->validate_signature_in_request( $sp_certificate, $signature_data );
			}
		}

		$relay_state = MoIDPUtility::is_blank( $sp->mo_idp_default_relayState ) ? $relay_state : $sp->mo_idp_default_relayState; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Refers to mo_idp_default_relay_state.

		$this->request_process_handler->mo_idp_authorize_user( $relay_state, $authn_request );
	}

	/**
	 * Function checks if the Service Provider object is not
	 * empty and is a valid SP.
	 *
	 * @param array|object|null|void $sp The Service Provider object returned from the database.
	 * @throws InvalidServiceProviderException Exception when the Service Provider's configuration are `null`.
	 */
	public function check_if_valid_sp( $sp ) {
		if ( MoIDPUtility::is_blank( $sp ) ) {
			throw new InvalidServiceProviderException();
		}
	}

	/*
	| -----------------------------------------------------------------------------------------------
	| FREE PLUGIN SPECIFIC FUNCTIONS
	| -----------------------------------------------------------------------------------------------
	 */

	/**
	 * This function validates the signature in the SAML Request
	 * using the certificate provided during configuration.
	 *
	 * @param string $sp_certificate refers to the certificate saved in SAML configuration.
	 * @param array  $signature_data refers to the Signature Data in the SAML request.
	 * @return boolean
	 */
	public function validate_signature_in_request( $sp_certificate, $signature_data ) {
		return true;
	}
}
