<?php
/**
 * This file contains the `RequestDecisionHandler` class that returns
 * the appropriate Request Handler based on the type of the request
 * being made by the Service Provider.
 *
 * @package miniorange-wp-as-saml-idp\helper\factory
 */

namespace IDP\Helper\Factory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\SAML2\AuthnRequest;
use IDP\Helper\WSFED\WsFedRequest;

/**
 * This is the factory which returns the appropriate requestHandlerObject
 * based on the type of request being made.
 */
class RequestDecisionHandler {

	/**
	 * This function is called to fetch the appropriate Request
	 * Handler based on the type of the request being made by the
	 * Service Provider.
	 *
	 * @param string $type Refers to the type of request coming in. Can be SAML | WS-FED.
	 * @param array  $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @param array  $sanitized_get Sanitized PHP Superglobals `$_GET`.
	 * @param array  $args Arguments being passed to construct the requestHandler.
	 * @return AuthnRequest|WsFedRequest
	 */
	public static function get_request_handler( $type, $sanitized_request, $sanitized_get, $args = array() ) {
		switch ( $type ) {
			case MoIDPConstants::SAML:
				return self::get_saml_request_handler( $sanitized_request, $sanitized_get );
			case MoIDPConstants::WS_FED:
				return self::get_wsfed_request_handler( $sanitized_request, $sanitized_get );
			case MoIDPConstants::AUTHN_REQUEST:
				return new AuthnRequest( $args[0] );
		}
	}

	/**
	 * This function is called to get the SAML Request Handler.
	 * Process the request coming from the Service Provider, and
	 * create the AuthnRequest object.
	 *
	 * @param array $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @param array $sanitized_get Sanitized PHP Superglobals `$_GET`.
	 * @return AuthnRequest|void
	 */
	public static function get_saml_request_handler( $sanitized_request, $sanitized_get ) {
		$saml_request = $sanitized_request['SAMLRequest'];
		// phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Base64 decoding required for the SAML protocol.
		$saml_request = base64_decode( $saml_request );
		if ( ! empty( $sanitized_get['SAMLRequest'] ) ) {
			$saml_request = gzinflate( $saml_request );
		}

		$document = new \DOMDocument();
		$document->loadXML( $saml_request );
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMDocument attributes.
		$saml_request_xml = $document->firstChild;
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMNode attributes.
		if ( 'LogoutRequest' === $saml_request_xml->localName ) {
			return;
		} else {
			return new AuthnRequest( $saml_request_xml );
		}
	}

	/**
	 * This function is called to get the WsFed Request Handler.
	 * Process the request coming from the Service Provider, and
	 * create the WsFed Request object.
	 *
	 * @param array $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @param array $sanitized_get Sanitized PHP Superglobals `$_GET`.
	 * @return WsFedRequest
	 */
	public static function get_wsfed_request_handler( $sanitized_request, $sanitized_get ) {
		return new WsFedRequest( $sanitized_request );
	}
}
