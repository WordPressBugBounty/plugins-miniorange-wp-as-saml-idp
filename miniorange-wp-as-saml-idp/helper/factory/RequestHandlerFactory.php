<?php
/**
 * This file contains the `RequestHandlerFactory` interface that
 * is implemented by other Request Handler classes.
 *
 * @package miniorange-wp-as-saml-idp\helper\factory
 */

namespace IDP\Helper\Factory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface RequestHandlerFactory {

	/**
	 * This function is used to generate AuthnRequest|WsFedRequest.
	 * Not implemented currently as these requests are generated
	 * on the SP side and this is the IDP plugin.
	 *
	 * @return void
	 */
	public function generate_request();

	/**
	 * This function returns the type of the Request (AuthnRequest|WsFedRequest).
	 *
	 * @return void
	 */
	public function get_request_type();
}
