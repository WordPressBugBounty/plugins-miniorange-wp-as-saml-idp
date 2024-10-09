<?php
/**
 * This file contains the `ResponseHandlerFactory` interface that
 * is implemented by other Response Handler classes.
 *
 * @package miniorange-wp-as-saml-idp\helper\factory
 */

namespace IDP\Helper\Factory;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

interface ResponseHandlerFactory {

	/**
	 * This function is used to generate the Response.
	 *
	 * @return void
	 */
	public function generate_response();
}
