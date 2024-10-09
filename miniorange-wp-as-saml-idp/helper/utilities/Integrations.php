<?php
/**
 * This file contains the `Integrations` class that is used
 * to describe the plugin's third party integrations.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Traits\Instance;

/**
 * This class describes the plugin's third party
 * integrations.
 */
class Integrations {

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param string $src_image Refers to the location of the integration logo.
	 * @param string $title Refers to the name of third party integration.
	 */
	public function __construct( $src_image, $title ) {
		$this->src_image = $src_image;
		$this->title     = $title;
	}

	/**
	 * Refers to the location of the integration logo.
	 *
	 * @var string $src_image
	 */
	public $src_image;

	/**
	 * Refers to the name of third party integration.
	 *
	 * @var string $title
	 */
	public $title;
}
