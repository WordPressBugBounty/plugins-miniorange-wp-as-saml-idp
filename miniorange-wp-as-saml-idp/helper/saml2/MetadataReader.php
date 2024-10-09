<?php
/**
 * This class contains the `MetadataReader` class which parses the
 * SP Metadata XML to gather Service Provider configuration, and the
 * `ServiceProviders` class that describes the Service Provider
 * configuration.
 *
 * @package miniorange-wp-as-saml-idp\helper\saml2
 */

namespace IDP\Helper\SAML2;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Utilities\SAMLUtilities;

/**
 * This class parses the SP Metadata XML and generates
 * `ServiceProviders` object.
 */
class MetadataReader {

	/**
	 * Refers to the Service Providers
	 * in the SP Metadata XML.
	 *
	 * @var array $service_providers
	 */
	private $service_providers;

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param \DOMNode $xml Refers to the SP Metadata XML.
	 */
	public function __construct( \DOMNode $xml = null ) {
		$flag = 0;

		$entity_descriptors = SAMLUtilities::xp_query( $xml, './saml_metadata:EntityDescriptor' );
		foreach ( $entity_descriptors as $entity_descriptor ) {
			$sp_sso_descriptor = SAMLUtilities::xp_query( $entity_descriptor, './saml_metadata:SPSSODescriptor' );

			if ( isset( $sp_sso_descriptor ) && ! empty( $sp_sso_descriptor ) ) {
				if ( SAMLUtilities::xp_query( $sp_sso_descriptor[0], './saml_metadata:AssertionConsumerService' ) ) {
					$flag = 1;
				}
			}
		}

		if ( 0 === $flag ) {
			$this->service_providers = null;
		} else {
			$this->service_providers = array();
			$entity_descriptors      = SAMLUtilities::xp_query( $xml, './saml_metadata:EntityDescriptor' );

			foreach ( $entity_descriptors as $entity_descriptor ) {
				// TODO: add sp descriptor.
				$sp_sso_descriptor = SAMLUtilities::xp_query( $entity_descriptor, './saml_metadata:SPSSODescriptor' );

				if ( isset( $sp_sso_descriptor ) && ! empty( $sp_sso_descriptor ) ) {
					array_push( $this->service_providers, new ServiceProviders( $entity_descriptor ) );
				}
			}
		}
	}

	/**
	 * Getter function for `$service_providers`.
	 *
	 * @return ServiceProviders
	 */
	public function get_service_providers() {
		return $this->service_providers;
	}
}

// phpcs:disable Generic.Files.OneObjectStructurePerFile.MultipleFound -- Existing structure of file.
/**
 * This class represents a Service Provider.
 */
class ServiceProviders {

	/**
	 * The Entity ID of the Service Provider.
	 *
	 * @var string $entity_id
	 */
	private $entity_id;

	/**
	 * The Assertion Consumer Service URL of
	 * the Service Provider.
	 *
	 * @var string $acs_url
	 */
	private $acs_url;

	/**
	 * Specifies whether the Service Provider
	 * expects signed Assertions or not.
	 *
	 * @var string $want_assertions_signed
	 */
	private $want_assertions_signed;

	/**
	 * The NameIDFormat used by the Service
	 * Provider for SSO Requests.
	 *
	 * @var string $name_id_format
	 */
	private $name_id_format;

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param \DOMElement $xml Refers to the SP Metadata XML.
	 */
	public function __construct( \DOMElement $xml = null ) {

		$sp_sso_descriptor = SAMLUtilities::xp_query( $xml, './saml_metadata:SPSSODescriptor' );

		$this->entity_id              = $xml->getAttribute( 'entityID' );
		$this->want_assertions_signed = $sp_sso_descriptor[0]->getAttribute( 'WantAssertionsSigned' );

		$sso_name_id = SAMLUtilities::xp_query( $sp_sso_descriptor[0], './saml_metadata:NameIDFormat' );
		if ( ! empty( $sso_name_id ) ) {
			$this->name_id_format = trim( $sso_name_id[0]->nodeValue );
		} else {
			$this->name_id_format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
		}

		$this->parse_acs_url( $sp_sso_descriptor[0] );
	}

	/**
	 * Parse the Assertion Consumer Service (ACS) URL
	 * from the SP metadata XML.
	 *
	 * @param \DOMNode $xml Refers to the SP Metadata XML.
	 * @return void
	 */
	private function parse_acs_url( $xml ) {
		$sso_acs_url   = SAMLUtilities::xp_query( $xml, './saml_metadata:AssertionConsumerService' );
		$this->acs_url = $sso_acs_url[0]->getAttribute( 'Location' );
	}

	/**
	 * Getter function for `$entity_id`.
	 *
	 * @return string
	 */
	public function get_entity_id() {
		return $this->entity_id;
	}

	/**
	 * Getter function for `$acs_url`.
	 *
	 * @return string
	 */
	public function get_acs_url() {
		return $this->acs_url;
	}

	/**
	 * Getter function for `$want_assertions_signed`.
	 *
	 * @return string
	 */
	public function get_signed_assertion() {
		return $this->want_assertions_signed;
	}

	/**
	 * Getter function for `$name_id_format`.
	 *
	 * @return string
	 */
	public function get_name_id_format() {
		return $this->name_id_format;
	}
}
