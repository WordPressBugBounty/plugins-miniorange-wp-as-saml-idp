<?php
/**
 * This class contains the `MetadataGenerator` class which is
 * responsible for generating the IDP Metadata XML.
 *
 * @package miniorange-wp-as-saml-idp\helper\saml2
 */

namespace IDP\Helper\SAML2;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Utilities\SAMLUtilities;

/**
 * This class generates SAML metadata for
 * the Identity Provider (IdP).
 */
class MetadataGenerator {

	/**
	 * The IDP Metadata XML.
	 *
	 * @var \DOMDocument $xml
	 */
	private $xml;

	/**
	 * Refers to the IDP Entity ID / Issuer.
	 *
	 * @var string $issuer
	 */
	private $issuer;

	/**
	 * Specifies whether or not SAML authentication
	 * requests should be signed.
	 *
	 * @var boolean $want_authn_requests_signed
	 */
	private $want_authn_requests_signed;

	/**
	 * The IDP X.509 signing certificate.
	 *
	 * @var string $x509_certificate
	 */
	private $x509_certificate;

	/**
	 * New IDP X.509 signing certificate.
	 *
	 * @var string $new_x509_certificate
	 */
	private $new_x509_certificate;

	/**
	 * NameID Formats accepted by the IDP.
	 *
	 * @var array $name_id_formats
	 */
	private $name_id_formats;

	/**
	 * SSO Endpoints of the IDP.
	 *
	 * @var array $single_sign_on_service_urls
	 */
	private $single_sign_on_service_urls;

	/**
	 * SLO Endpoints of the IDP.
	 *
	 * @var array $single_logout_service_urls
	 */
	private $single_logout_service_urls;

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param string  $issuer Refers to the IDP Entity ID / Issuer.
	 * @param boolean $want_authn_requests_signed Specifies whether or not SAML authentication requests should be signed.
	 * @param string  $x509_certificate The IDP X.509 signing certificate.
	 * @param string  $new_x509_certificate New IDP X.509 signing certificate.
	 * @param string  $sso_url_post SSO Endpoint (POST-Binding) of the IDP.
	 * @param string  $sso_url_redirect SSO Endpoint (Redirect-Binding) of the IDP.
	 * @param string  $slo_url_post SLO Endpoint (POST-Binding) of the IDP.
	 * @param string  $slo_url_redirect SLO Endpoint (Redirect-Binding) of the IDP.
	 */
	public function __construct( $issuer, $want_authn_requests_signed, $x509_certificate, $new_x509_certificate, $sso_url_post, $sso_url_redirect, $slo_url_post, $slo_url_redirect ) {
		$this->xml                     = new \DOMDocument( '1.0', 'utf-8' );
		$this->xml->preserveWhiteSpace = false;
		$this->xml->formatOutput       = true;

		$this->issuer                      = $issuer;
		$this->want_authn_requests_signed  = $want_authn_requests_signed;
		$this->x509_certificate            = $x509_certificate;
		$this->new_x509_certificate        = $new_x509_certificate;
		$this->name_id_formats             = array(
			'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
			'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
		);
		$this->single_sign_on_service_urls = array(
			'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' => $sso_url_post,
			'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' => $sso_url_redirect,
		);
		$this->single_logout_service_urls  = array(
			'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST' => $slo_url_post,
			'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect' => $slo_url_redirect,
		);
	}

	/**
	 * This is the main function that generates
	 * the IDP Metadata XML.
	 *
	 * @return string|false
	 */
	public function generate_metadata() {
		// Generating the Metadata Element.
		$entity = $this->create_entity_descriptor_element();
		$this->xml->appendChild( $entity );

		// Generating the IdpDescriptor Element.
		$idp_descriptor = $this->create_idp_descriptor_element();
		$entity->appendChild( $idp_descriptor );

		// Generating the Key descriptor element with the new certificate.
		if ( ! get_site_option( 'mo_idp_new_certs' ) ) {
			$key = $this->create_key_descriptor_element();
			$idp_descriptor->appendChild( $key );

			$key_info = $this->generate_key_info( true );
			$key->appendChild( $key_info );
		}

		// Generate the Key descriptor element for idpDescriptor.
		$key3 = $this->create_key_descriptor_element();
		$idp_descriptor->appendChild( $key3 );

		// Generate key info element for Key descriptor.
		$key3_info = $this->generate_key_info( false );
		$key3->appendChild( $key3_info );

		// Generate NameID Formats.
		$name_id_format_elements = $this->create_name_id_format_elements();
		foreach ( $name_id_format_elements as $name_id_format_element ) {
			$idp_descriptor->appendChild( $name_id_format_element );
		}

		// Generate SingleLogin URL Elements.
		$sso_url_elements = $this->create_sso_urls();
		foreach ( $sso_url_elements as $sso_url_element ) {
			$idp_descriptor->appendChild( $sso_url_element );
		}

		// Generate the organization details.
		$org_data        = $this->create_organization_element();
		$contact_details = $this->create_contact_person_element();

		$entity->appendChild( $org_data );
		$entity->appendChild( $contact_details );

		$metadata = $this->xml->saveXML();
		return $metadata;
	}

	/**
	 * Creates the `EntityDescriptor` element
	 * in the IDP Metadata XML.
	 *
	 * @return \DOMElement
	 */
	private function create_entity_descriptor_element() {
		$entity = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:EntityDescriptor' );
		$entity->setAttribute( 'entityID', esc_attr( $this->issuer ) );
		return $entity;
	}

	/**
	 * Creates the `IDPSSODescriptor` element
	 * in the IDP Metadata XML.
	 *
	 * @return \DOMElement
	 */
	private function create_idp_descriptor_element() {
		$idp_descriptor = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:IDPSSODescriptor' );
		$idp_descriptor->setAttribute( 'WantAuthnRequestsSigned', esc_attr( $this->want_authn_requests_signed ) );
		$idp_descriptor->setAttribute( 'protocolSupportEnumeration', 'urn:oasis:names:tc:SAML:2.0:protocol' );
		return $idp_descriptor;
	}

	/**
	 * Creates the `IDPSSODescriptor` element
	 * in the IDP Metadata XML.
	 *
	 * @return \DOMElement
	 */
	private function create_key_descriptor_element() {
		$key = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:KeyDescriptor' );
		$key->setAttribute( 'use', 'signing' );
		return $key;
	}

	/**
	 * Creates the `KeyInfo` element
	 * in the IDP Metadata XML.
	 *
	 * @param bool $use_new_cert Whether to generate keyinfo for new certificate or not.
	 * @return \DOMElement
	 */
	private function generate_key_info( $use_new_cert = false ) {
		$key_info  = $this->xml->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:KeyInfo' );
		$cert_data = $this->xml->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:X509Data' );
		if ( $use_new_cert ) {
			$cert_value = SAMLUtilities::desanitize_certificate( $this->new_x509_certificate );
		} else {
			$cert_value = SAMLUtilities::desanitize_certificate( $this->x509_certificate );
		}
		$cert_element = $this->xml->createElementNS( 'http://www.w3.org/2000/09/xmldsig#', 'ds:X509Certificate', esc_attr( $cert_value ) );
		$cert_data->appendChild( $cert_element );
		$key_info->appendChild( $cert_data );
		return $key_info;
	}

	/**
	 * Creates the `NameIDFormat` elements
	 * in the IDP Metadata XML.
	 *
	 * @return array(\DOMElement)
	 */
	private function create_name_id_format_elements() {
		$name_id_format_elements = array();
		foreach ( $this->name_id_formats as $name_id_format ) {
			array_push( $name_id_format_elements, $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:NameIDFormat', esc_attr( $name_id_format ) ) );
		}
		return $name_id_format_elements;
	}

	/**
	 * Creates the `SingleSignOnService` elements
	 * in the IDP Metadata XML.
	 *
	 * @return array(\DOMElement)
	 */
	private function create_sso_urls() {
		$sso_url_elements = array();
		foreach ( $this->single_sign_on_service_urls as $binding => $url ) {
			$sso_url_element = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:SingleSignOnService' );
			$sso_url_element->setAttribute( 'Binding', esc_attr( $binding ) );
			$sso_url_element->setAttribute( 'Location', esc_url( $url ) );
			array_push( $sso_url_elements, $sso_url_element );
		}
		return $sso_url_elements;
	}

	/**
	 * Creates the `Organization` element
	 * in the IDP Metadata XML.
	 *
	 * @return \DOMElement
	 */
	private function create_organization_element() {
		$org_data = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:Organization' );
		$name     = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:OrganizationName', 'miniOrange' );
		$name->setAttribute( 'xml:lang', 'en-US' );
		$display_name = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:OrganizationDisplayName', 'miniOrange' );
		$display_name->setAttribute( 'xml:lang', 'en-US' );
		$org_url = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:OrganizationURL', 'https://miniorange.com' );
		$org_url->setAttribute( 'xml:lang', 'en-US' );
		$org_data->appendChild( $name );
		$org_data->appendChild( $display_name );
		$org_data->appendChild( $org_url );

		return $org_data;
	}

	/**
	 * Creates the `ContactPerson` element
	 * in the IDP Metadata XML.
	 *
	 * @return \DOMElement
	 */
	private function create_contact_person_element() {
		$contact_details = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:ContactPerson' );
		$contact_details->setAttribute( 'contactType', 'technical' );
		$name    = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:GivenName', 'miniOrange' );
		$surname = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:SurName', 'Support' );
		$email   = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:metadata', 'md:EmailAddress', 'info@xecurify.com' );
		$contact_details->appendChild( $name );
		$contact_details->appendChild( $surname );
		$contact_details->appendChild( $email );

		return $contact_details;
	}
}
