<?php
/**
 * This file contains the `ResponseDecisionHandler` class that returns
 * the appropriate Response Handler based on the type of the request
 * being made by the Service Provider.
 *
 * @package miniorange-wp-as-saml-idp\helper\factory
 */

namespace IDP\Helper\Factory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\SAML2\GenerateResponse;
use IDP\Helper\WSFED\GenerateWsFedResponse;

/**
 * This class is called to decide what kind of Response Handler
 * needs to be created based on the type passed in it's parameter.
 */
class ResponseDecisionHandler {

	/**
	 * This function is called to create the appropriate Response
	 * class object to be returned based on the type parameter.
	 *
	 * @param string $type Refers to the Response Handler type.
	 * @param array  $args Refers to the array of values required to initialize the handler.
	 * @return GenerateResponse|GenerateWsFedResponse
	 */
	public static function get_response_handler( $type, $args ) {
		switch ( $type ) {
			case MoIDPConstants::SAML_RESPONSE:
				return new GenerateResponse(
					$args[0],
					$args[1],
					$args[2],
					$args[3],
					$args[4],
					$args[5],
					$args[6]
				);
			case MoIDPConstants::WS_FED_RESPONSE:
				return new GenerateWsFedResponse(
					$args[0],
					$args[1],
					$args[2],
					$args[3],
					$args[4],
					$args[5],
					$args[6]
				);
		}
	}
}
