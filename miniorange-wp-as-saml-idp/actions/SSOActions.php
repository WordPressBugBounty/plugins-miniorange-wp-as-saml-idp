<?php
/**
 * This file contains the `SSOActions` class that defines
 * methods to handle SSO related flows.
 *
 * @package miniorange-wp-as-saml-idp\actions
 */

namespace IDP\Actions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidRequestInstantException;
use IDP\Exception\InvalidRequestVersionException;
use IDP\Exception\InvalidServiceProviderException;
use IDP\Exception\InvalidSignatureInRequestException;
use IDP\Exception\InvalidSSOUserException;
use IDP\Handler\ProcessRequestHandler;
use IDP\Handler\ReadRequestHandler;
use IDP\Handler\SendResponseHandler;
use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Constants\MoIDPMessages;
use IDP\Helper\SAML2\AuthnRequest;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class contains all the functions to facilitate SSO.
 */
class SSOActions {

	use Instance;

	/**
	 * Instance of `ReadRequestHandler` class
	 * to call its required methods.
	 *
	 * @var ReadRequestHandler $read_request_handler
	 */
	private $read_request_handler;

	/**
	 * Instance of `SendResponseHandler` class
	 * to call its required methods.
	 *
	 * @var SendResponseHandler $send_response_handler
	 */
	private $send_response_handler;

	/**
	 * Instance of `ProcessRequestHandler` class
	 * to call its required methods.
	 *
	 * @var ProcessRequestHandler $request_process_handler
	 */
	private $request_process_handler;

	/**
	 * Constructor function, which instantiates the required handlers
	 * and registers the callback functions on `init` and `wp_login`
	 * hooks required to handle the SSO flow.
	 */
	private function __construct() {
		$this->read_request_handler    = ReadRequestHandler::get_instance();
		$this->send_response_handler   = SendResponseHandler::get_instance();
		$this->request_process_handler = ProcessRequestHandler::get_instance();

		add_action( 'init', array( $this, 'handle_sso' ) );
		add_action( 'wp_login', array( $this, 'mo_idp_handle_post_login' ), 99 );
	}

	/**
	 * Refers to the values in the request parameter.
	 *
	 * @var array $request_params
	 */
	private $request_params = array(
		'SAMLRequest',
		'option',
		'wtrealm',      // checking wtrealm instead of clientRequestId as it is optional.
	);

	/**
	 * Handles all the SSO operations. Checks if there is
	 * any `SAMLRequest` or `option` request made to the site.
	 * Checks for any exceptions that may occur.
	 *
	 * @return void
	 */
	public function handle_sso() {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification as this is SSO flow.
		$sanitized_request = MoIDPUtility::sanitize_associative_array( $_REQUEST );
		$keys              = array_keys( $sanitized_request );
		$operation         = array_intersect( $keys, $this->request_params );
		if ( count( $operation ) <= 0 ) {
			return;
		}
		try {
			$this->route_data( array_values( $operation )[0] );
		} catch ( InvalidRequestInstantException $e ) {
			if ( MSI_DEBUG ) {
				MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
			}
			wp_die( esc_html( $e->getMessage() ) );
		} catch ( InvalidRequestVersionException $e ) {
			if ( MSI_DEBUG ) {
				MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
			}
			wp_die( esc_html( $e->getMessage() ) );
		} catch ( InvalidServiceProviderException $e ) {
			if ( MSI_DEBUG ) {
				MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
			}
			wp_die( esc_html( $e->getMessage() ) );
		} catch ( InvalidSignatureInRequestException $e ) {
			if ( MSI_DEBUG ) {
				MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
			}
			wp_die( esc_html( $e->getMessage() ) );
		} catch ( InvalidSSOUserException $e ) {
			if ( MSI_DEBUG ) {
				MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
			}
			wp_die( esc_html( $e->getMessage() ) );
		} catch ( \Exception $e ) {
			if ( MSI_DEBUG ) {
				MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
			}
			wp_die( esc_html( $e->getMessage() ) );
		}
	}

	/**
	 * Route the request data to appropriate functions for processing.
	 * Check for any kind of Exception that may occur during processing
	 * of form post data.
	 *
	 * @param string $op Refers to values from the request parameters.
	 * @throws InvalidServiceProviderException Exception when the Service Provider's configuration are `null`.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function route_data( $op ) {
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification as this is SSO flow.
		$sanitized_get = MoIDPUtility::sanitize_associative_array( $_GET );
		// phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Skipping nonce verification as this is SSO flow.
		$sanitized_request = MoIDPUtility::sanitize_associative_array( $_REQUEST );
		switch ( $op ) {
			case $this->request_params[0]:
				$this->read_request_handler->read_request( $sanitized_request, $sanitized_get, MoIDPConstants::SAML );
				break;
			case $this->request_params[1]:
				$this->initiate_saml_response( $sanitized_request );
				break;
			case $this->request_params[2]:
				$this->read_request_handler->read_request( $sanitized_request, $sanitized_get, MoIDPConstants::WS_FED );
				break;
		}
	}

	/**
	 * Function to handle post login sending of
	 * SAML response. It checks if SP data was saved
	 * in `$_COOKIE` before authentication so that SAML response
	 * can be sent to it after successful authentication.
	 *
	 * @param string $login username of the user who logged in.
	 * @return void
	 */
	public function mo_idp_handle_post_login( $login ) {
		$sanitized_cookie = MoIDPUtility::sanitize_associative_array( $_COOKIE );
		if ( ! empty( $sanitized_cookie['response_params'] ) ) {
			try {

				if ( isset( $sanitized_cookie['moIdpsendSAMLResponse'] ) && 0 === strcmp( $sanitized_cookie['moIdpsendSAMLResponse'], 'true' ) ) {
					$this->send_response_handler->mo_idp_send_response(
						array(
							'requestType' => MoIDPConstants::AUTHN_REQUEST,
							'acs_url'     => $sanitized_cookie['acs_url'],
							'issuer'      => $sanitized_cookie['audience'],
							'relayState'  => $sanitized_cookie['relayState'],
							'requestID'   => $sanitized_cookie['requestID'],
						),
						$login
					);
				}

				if ( isset( $sanitized_cookie['moIdpsendWsFedResponse'] ) && 0 === strcmp( $sanitized_cookie['moIdpsendWsFedResponse'], 'true' ) ) {
					$this->send_response_handler->mo_idp_send_response(
						array(
							'requestType'     => MoIDPConstants::WS_FED,
							'clientRequestId' => $sanitized_cookie['clientRequestId'],
							'wtrealm'         => $sanitized_cookie['wtrealm'],
							'wa'              => $sanitized_cookie['wa'],
							'relayState'      => $sanitized_cookie['relayState'],
							'wctx'            => $sanitized_cookie['wctx'],
						),
						$login
					);
				}
			} catch ( InvalidSSOUserException $e ) {
				if ( MSI_DEBUG ) {
					MoIDPUtility::mo_debug( 'Exception Occurred during SSO ' . $e );
				}
				wp_die( esc_html( $e->getMessage() ) );
			}
		}
	}

	/**
	 * Checks the `option` key from the `$_REQUEST` array
	 * and initiates the process to either send the SAMLResponse
	 * or display the IDP Metadata.
	 *
	 * @param array $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	private function initiate_saml_response( $sanitized_request ) {
		if ( 'test_idp_config' === $sanitized_request['option'] ) {
			$this->send_saml_response_based_on_request_data( $sanitized_request );
		} elseif ( 'saml_user_login' === $sanitized_request['option'] ) {
			$this->send_saml_response_based_on_sp_name( $sanitized_request['sp'], $sanitized_request['relayState'] );
		} elseif ( 'mo_idp_metadata' === $sanitized_request['option'] ) {
			MoIDPUtility::show_metadata();
		}
	}

	/**
	 * Reads the SP related data from the `$_REQUEST` array and
	 * passes it to the next function for generating and
	 * sending SAML Response.
	 *
	 * @param array $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	private function send_saml_response_based_on_request_data( $sanitized_request ) {
		$default_relay_state = empty( $sanitized_request['defaultRelayState'] ) ? '/' : $sanitized_request['defaultRelayState'];
		$this->send_response_handler->mo_idp_send_response(
			array(
				'requestType' => MoIDPConstants::AUTHN_REQUEST,
				'acs_url'     => $sanitized_request['acs'],
				'issuer'      => $sanitized_request['issuer'],
				'relayState'  => $default_relay_state,
			)
		);
	}

	/**
	 * Function sends a SAML Response to the SP based on the
	 * SP Name in the request. Gets all the SP data from the
	 * database and sends it to the next function for generating
	 * and sending SAML Response.
	 *
	 * @global \IDP\Helper\Database\MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param string $sp_name Name of the SP in the request.
	 * @param string $relay_state Dynamic URL admin wants the user redirected to.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	private function send_saml_response_based_on_sp_name( $sp_name, $relay_state ) {
		global $moidp_db_queries;
		$sp = $moidp_db_queries->get_sp_from_name( $sp_name );
		if ( ! MoIDPUtility::is_blank( $sp ) ) {
			$default_relay_state = ! MoIDPUtility::is_blank( $relay_state ) ? $relay_state
								: ( MoIDPUtility::is_blank( $sp->mo_idp_default_relayState ) ? '/' : $sp->mo_idp_default_relayState ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Refers to mo_idp_default_relay_state.

			if ( ! is_user_logged_in() ) {
				$request_obj = new AuthnRequest();
				$request_obj = $request_obj->set_assertion_consumer_service_url( $sp->mo_idp_acs_url )
					->set_issuer( $sp->mo_idp_sp_issuer )
					->set_request_id( null );
				$this->request_process_handler->set_saml_session_cookies( $request_obj, $default_relay_state );
			}

			$this->send_response_handler->mo_idp_send_response(
				array(
					'requestType' => MoIDPConstants::AUTHN_REQUEST,
					'acs_url'     => $sp->mo_idp_acs_url,
					'issuer'      => $sp->mo_idp_sp_issuer,
					'relayState'  => $default_relay_state,
				)
			);
		}
	}
}
