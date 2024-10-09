<?php
/**
 * This file contains the abstract `BasePostAction` class that is extended by
 * classes to handle form post data.
 *
 * @package miniorange-wp-as-saml-idp\actions
 */

namespace IDP\Actions;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Traits\Instance;

/**
 * This class is an abstract class extended by classes
 * which need to handle any sort of form post data.
 *
 * @abstract
 */
abstract class BasePostAction {

	use Instance;

	/**
	 * Unique string to validate the authenticity of the
	 * HTTP requests, to prevent unauthorized operations.
	 *
	 * @var string $nonce
	 */
	protected $nonce;

	/**
	 * Constructor function, registering the hook required for
	 * handling the form post data.
	 */
	public function __construct() {
		add_action( 'admin_init', array( $this, 'handle_post_data' ), 1 );
	}

	/**
	 * Abstract function, to be extended by classes that wish to
	 * handle and process the post data. This is the callback function on `admin_init`
	 * hook.
	 *
	 * @abstract
	 * @return void
	 */
	abstract public function handle_post_data();

	/**
	 * Abstract function, to be extended by classes that wish to
	 * route the flow to respective functions. This function is generally
	 * called from the `handle_post_data()` function.
	 *
	 * @abstract
	 * @param string $option Variable used to get the `option` name of the form submitted.
	 * @return void
	 */
	abstract public function route_post_data( $option );
}
