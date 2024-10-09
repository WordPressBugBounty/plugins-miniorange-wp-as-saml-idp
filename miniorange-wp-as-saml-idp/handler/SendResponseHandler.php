<?php
/**
 * This file contains the `SendResponseHandler` class that is responsible
 * for sending the SAML / WS-Fed Response to the Service Provider.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidSSOUserException;
use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Database\MoDbQueries;
use IDP\Helper\Factory\ResponseDecisionHandler;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `BaseHandler` class and handles the
 * sending of SAML / WS-Fed Responses to the Service Provider.
 */
final class SendResponseHandler extends BaseHandler {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {}

	/**
	 * Function processes and generates the SAML / WS-Fed Response
	 * to be sent to the Service Provider.
	 *
	 * @param array       $args An array of values pertaining to an SP.
	 * @param string|null $login Username of the user.
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function mo_idp_send_response( $args, $login = null ) {
		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( 'Generating Login Response' );
		}
		$this->check_if_valid_plugin();

		$current_user = wp_get_current_user();
		$current_user = ! MoIDPUtility::is_blank( $current_user->ID ) ? $current_user : get_user_by( 'login', $login );

		if ( strcasecmp( $args['requestType'], MoIDPConstants::AUTHN_REQUEST ) === 0 ) {
			$args = $this->get_saml_response_params( $args, $current_user );
		} elseif ( strcasecmp( $args['requestType'], MoIDPConstants::WS_FED ) === 0 ) {
			$args = $this->get_wsfed_response_params( $args, $current_user );
		}

		$response_obj = ResponseDecisionHandler::get_response_handler(
			$args[0],
			array( $args[1], $args[2], $args[3], $args[4], $args[5], $args[6], $login )
		);
		$response     = $response_obj->generate_response();

		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( 'Login Response generated: ' . $response );
		}

		if ( ob_get_contents() ) {
			ob_clean();
		}
		MoIDPUtility::unset_cookie_variables(
			array(
				'response_params',
				'moIdpsendSAMLResponse',
				'acs_url',
				'audience',
				'relayState',
				'requestID',
				'moIdpsendWsFedResponse',
				'wtrealm',
				'wa',
				'wctx',
				'clientRequestId',
			)
		);

		if ( strcasecmp( $args[0], MoIDPConstants::SAML_RESPONSE ) === 0 ) {
			$this->send_response( $response, $args[7], $args[1] );
		} elseif ( strcasecmp( $args[0], MoIDPConstants::WS_FED_RESPONSE ) === 0 ) {
			$this->send_ws_fed_response( $response, $args[5]->mo_idp_acs_url . '?clientRequestId=' . $args[8], $args[3], $args[2] );
		}
	}

	/**
	 * Processes the values coming in the request or set in the `$_COOKIE` and
	 * initializes values required to start the process for generating a
	 * SAML response.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param array               $args An array of values pertaining to an SP.
	 * @param false|null|\WP_User $current_user User object of currently logged-in user.
	 * @return array
	 */
	public function get_saml_response_params( $args, $current_user ) {
		global $moidp_db_queries;
		$acs_url     = $args['acs_url'];
		$audience    = $args['issuer'];
		$relay_state = isset( $args['relayState'] ) ? $args['relayState'] : null;
		$request_id  = isset( $args['requestID'] ) ? $args['requestID'] : null;

		MoIDPUtility::add_sp_cookie( $audience );

		$issuer  = get_site_option( 'mo_idp_entity_id' ) ? get_site_option( 'mo_idp_entity_id' ) : MSI_URL;
		$sp      = $moidp_db_queries->get_sp_from_acs( $acs_url );
		$id      = ! empty( $sp ) ? $sp->id : null;
		$sp_attr = $moidp_db_queries->get_all_sp_attributes( $id );

		return array( MoIDPConstants::SAML_RESPONSE, $acs_url, $issuer, $audience, $request_id, $sp_attr, $sp, $relay_state, null );
	}

	/**
	 * Processes the values coming in the request or set in the `$_COOKIE` and
	 * initializes values required to start the process for generating a
	 * WS-Fed response.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param array               $args An array of values pertaining to an SP.
	 * @param false|null|\WP_User $current_user User object of currently logged-in user.
	 * @return array
	 */
	public function get_wsfed_response_params( $args, $current_user ) {
		global $moidp_db_queries;

		$client_request_id = $args['clientRequestId'];
		$wtrealm           = $args['wtrealm'];
		$wa                = $args['wa'];
		$relay_state       = isset( $args['relayState'] ) ? $args['relayState'] : null;
		$wctx              = isset( $args['wctx'] ) ? $args['wctx'] : null;

		$issuer  = get_site_option( 'mo_idp_entity_id' ) ? get_site_option( 'mo_idp_entity_id' ) : MSI_URL;
		$sp      = $moidp_db_queries->get_sp_from_issuer( $wtrealm );
		$id      = ! empty( $sp ) ? $sp->id : null;
		$sp_attr = $moidp_db_queries->get_all_sp_attributes( $id );

		return array( MoIDPConstants::WS_FED_RESPONSE, $wtrealm, $wa, $wctx, $issuer, $sp, $sp_attr, $relay_state, $client_request_id );
	}

	/**
	 * Function sends out a SAML Response to the SP after successful authentication.
	 *
	 * @param string $saml_response SAMLResponse to be sent.
	 * @param string $relay_state RelayState to be sent.
	 * @param string $acs_url Destination to post the SAML Response.
	 * @return void
	 */
	private function send_response( $saml_response, $relay_state, $acs_url ) {
		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( 'Sending SAML Login Response' );
		}
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Base64 encoding required for the SAML protocol.
		$saml_response = base64_encode( $saml_response );
		echo '
		<html>
			<head>
				<meta http-equiv="cache-control" content="no-cache">
				<meta http-equiv="pragma" content="no-cache">
			</head>
			<body>
			<form id="responseform" action="' . esc_url( $acs_url ) . '" method="post">
				<input type="hidden" name="SAMLResponse" value="' . esc_html( $saml_response ) . '" />';
		if ( '/' !== $relay_state ) {
			echo '<input type="hidden" name="RelayState" value="' . esc_attr( $relay_state ) . '" />';
		}
		echo '</form>
			</body>
		<script>
			document.getElementById(\'responseform\').submit();	
		</script>
		</html>';
		exit;
	}

	/**
	 * Function sends out a WS-Fed Response to the SP after successful authentication.
	 *
	 * @param string $wsfed_response WS-Fed Response to be sent.
	 * @param string $acs_url Destination to post the WS-Fed Response.
	 * @param string $wctx wctx value to be sent.
	 * @param string $wa wa value to be sent.
	 * @return void
	 */
	private function send_ws_fed_response( $wsfed_response, $acs_url, $wctx, $wa ) {
		if ( MSI_DEBUG ) {
			MoIDPUtility::mo_debug( 'Sending WS-FED Login Response' );
		}
		echo '
		<html>
			<head>
				<meta http-equiv="cache-control" content="no-cache">
				<meta http-equiv="pragma" content="no-cache">
			</head>
			<body>
				<form id="responseform" action="' . esc_url( $acs_url ) . '" method="post">
					<input type="hidden" name="wa" value="' . esc_attr( $wa ) . '" />
			
					<input type="hidden" name="wresult" value="' . esc_html( $wsfed_response ) . '" />
					<input type="hidden" name="wctx" value="' . esc_attr( $wctx ) . '" />';
		echo '	</form>
			</body>
			<script>
				document.getElementById(\'responseform\').submit();	
			</script>
		</html>';
		exit;
	}
}
