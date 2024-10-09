<?php
/**
 * This file contains the `ProcessRequestHandler` class that is responsible
 * for processing SAML / WS-Fed Request and Response.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidSSOUserException;
use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\SAML2\AuthnRequest;
use IDP\Helper\Traits\Instance;
use IDP\Helper\WSFED\WsFedRequest;

/**
 * This class extends the `BaseHandler` class and handles all
 * the processing of SAML / WS-Fed Request and Response read.
 */
final class ProcessRequestHandler extends BaseHandler {

	use Instance;

	/**
	 * Instance of `SendResponseHandler` class
	 * to call its required methods.
	 *
	 * @var SendResponseHandler $send_response_handler
	 */
	private $send_response_handler;

	/**
	 * Private constructor to prevent direct object creation.
	 */
	private function __construct() {
		$this->send_response_handler = SendResponseHandler::get_instance();
	}

	/**
	 * Check the type of the Request being made, and start the SSO process based
	 * on the type of request made by the Service Provider.
	 *
	 * @param string                    $relay_state Refers to the Relay State in the SAML request, if any.
	 * @param AuthnRequest|WsFedRequest $request_object Refers to the requestObject formed from the request coming from the SP.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function mo_idp_authorize_user( $relay_state, $request_object ) {
		switch ( $request_object->get_request_type() ) {
			case MoIDPConstants::AUTHN_REQUEST:
				$this->start_process_for_saml_response( $relay_state, $request_object );
				break;
			case MoIDPConstants::WS_FED:
				$this->start_process_for_wsfed_response( $relay_state, $request_object );
				break;
		}
	}

	/**
	 * Check if a user is already logged in, and initiate the SSO process
	 * for sending SAML response. If the user is not logged in, redirect him
	 * to the login page while saving the SP data in session (cookie) for sending
	 * Response after successful authentication.
	 *
	 * @param string       $relay_state Refers to the Relay State in the SAML request, if any.
	 * @param AuthnRequest $request_object Refers to the requestObject formed from the request coming from the SP.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function start_process_for_saml_response( $relay_state, $request_object ) {
		if ( is_user_logged_in() ) {
			$this->send_response_handler->mo_idp_send_response(
				array(
					'requestType' => $request_object->get_request_type(),
					'acs_url'     => $request_object->get_assertion_consumer_service_url(),
					'issuer'      => $request_object->get_issuer(),
					'relayState'  => $relay_state,
					'requestID'   => $request_object->get_request_id(),
				)
			);
		} else {
			$this->set_saml_session_cookies( $request_object, $relay_state );
		}
	}

	/**
	 * Check if a user is already logged in, and initiate the SSO process
	 * for sending Ws-Fed response. If the user is not logged in, redirect him
	 * to the login page while saving the SP data in session (cookie) for sending
	 * Response after successful authentication.
	 *
	 * @param string       $relay_state Refers to the Relay State in the request, if any.
	 * @param WsFedRequest $request_object Refers to the requestObject formed from the request coming from the SP.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function start_process_for_wsfed_response( $relay_state, $request_object ) {
		if ( is_user_logged_in() ) {
			$this->send_response_handler->mo_idp_send_response(
				array(
					'requestType'     => $request_object->get_request_type(),
					'clientRequestId' => $request_object->get_client_request_id(),
					'wtrealm'         => $request_object->get_wtrealm(),
					'wa'              => $request_object->get_wa(),
					'relayState'      => $relay_state,
					'wctx'            => $request_object->get_wctx(),
				)
			);
		} else {
			$this->set_wsfed_session_cookies( $request_object, $relay_state );
		}
	}

	/**
	 * Function to save SP data in cookie for sending Response after
	 * successful authentication.
	 * Setting individual cookies, cause there have been cases where
	 * people get a redirect loop on the website if all these values are set
	 * under the same variable.
	 *
	 * @param WsFedRequest $request_object The requestObject formed from the WsFedRequest.
	 * @param string       $relay_state Refers to the Relay State in the SAML request, if any.
	 */
	public function set_wsfed_session_cookies( $request_object, $relay_state ) {
		if ( ob_get_contents() ) {
			ob_clean();
		}
		setcookie( 'response_params', 'isSet' );
		setcookie( 'moIdpsendWsFedResponse', 'true' );
		setcookie( 'wtrealm', $request_object->get_wtrealm() );
		setcookie( 'wa', $request_object->get_wa() );
		setcookie( 'wctx', $request_object->get_wctx() );
		setcookie( 'relayState', $relay_state );
		setcookie( 'clientRequestId', $request_object->get_client_request_id() );
		wp_safe_redirect( wp_login_url() );
		exit;
	}

	/**
	 * Function to save SP data in cookie for sending Response after
	 * successful authentication.
	 * Setting individual cookies, cause there have been cases where
	 * people get a redirect loop on the website if all these values are set
	 * under the same variable.
	 *
	 * @param AuthnRequest $request_object The requestObject formed from the AuthnRequest.
	 * @param string       $relay_state Refers to the Relay State in the SAML request, if any.
	 */
	public function set_saml_session_cookies( $request_object, $relay_state ) {
		if ( ob_get_contents() ) {
			ob_clean();
		}
		setcookie( 'response_params', 'isSet' );
		setcookie( 'moIdpsendSAMLResponse', 'true' );
		setcookie( 'acs_url', $request_object->get_assertion_consumer_service_url() );
		setcookie( 'audience', $request_object->get_issuer() );
		setcookie( 'relayState', $relay_state );
		setcookie( 'requestID', $request_object->get_request_id() );
		wp_safe_redirect( wp_login_url() );
		exit;
	}
}
