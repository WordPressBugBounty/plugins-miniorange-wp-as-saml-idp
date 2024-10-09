<?php
/**
 * This file contains the `Instance` trait that generates
 * and returns an instance of the class.
 *
 * @package miniorange-wp-as-saml-idp\helper\traits
 */

namespace IDP\Helper\Traits;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This trait is used to check whether an instance of
 * the class exists, or generates / returns the instance
 * of the class.
 */
trait Instance {

	/**
	 * Refers to the class object.
	 *
	 * @var object|null $instance
	 */
	private static $instance = null;

	/**
	 * Function checks whether an instance of the
	 * class exists, or generates / returns the
	 * instance of the class.
	 *
	 * @return self
	 */
	public static function get_instance() {
		if ( is_null( self::$instance ) ) {
			self::$instance = new self();
		}
		return self::$instance;
	}
}
