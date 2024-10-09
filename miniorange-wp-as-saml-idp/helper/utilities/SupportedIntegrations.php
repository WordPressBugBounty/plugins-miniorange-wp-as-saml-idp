<?php
/**
 * This file contains the `SupportedIntegrationsDetails` class that is used
 * to describe the plugin's supported third party integrations.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Traits\Instance;

/**
 * This class describes the plugin's supported third party
 * integrations.
 */
class SupportedIntegrationsDetails {

	use Instance;

	/**
	 * List of all the supported integrations.
	 *
	 * @var array $integration_details
	 */
	public $integration_details;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->integration_details = array(
			'MemberPress' => new Integrations(
				MSI_URL . '/includes/images/memberpress.png',
				'MemberPress',
			),
		);
	}
}
