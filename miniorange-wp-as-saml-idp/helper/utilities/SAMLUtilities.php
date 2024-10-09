<?php
/**
 * This file contains the `SAMLUtilities` utility class that
 * provides helper functions for the SAML flow.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use \RobRichards\XMLSecLibs\XMLSecurityDSig;
use \RobRichards\XMLSecLibs\XMLSecurityKey;

/**
 * This class provides helper functions used in the
 * SAML flow.
 */
class SAMLUtilities {

	/**
	 * This function parses the XML document node, and checks the
	 * presence of a certain element.
	 *
	 * @param \DomNode $node Refers to the XML document node.
	 * @param string   $query Refers to the element to query.
	 * @return array
	 */
	public static function xp_query( \DomNode $node, $query ) {
		static $xp_cache = null;

		if ( $node instanceof \DOMDocument ) {
			$doc = $node;
		} else {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMNode attributes.
			$doc = $node->ownerDocument;
		}

		if ( null === $xp_cache || ! $xp_cache->document->isSameNode( $doc ) ) {
			$xp_cache = new \DOMXPath( $doc );
			$xp_cache->registerNamespace( 'soap-env', 'http://schemas.xmlsoap.org/soap/envelope/' );
			$xp_cache->registerNamespace( 'saml_protocol', 'urn:oasis:names:tc:SAML:2.0:protocol' );
			$xp_cache->registerNamespace( 'saml_assertion', 'urn:oasis:names:tc:SAML:2.0:assertion' );
			$xp_cache->registerNamespace( 'saml_metadata', 'urn:oasis:names:tc:SAML:2.0:metadata' );
			$xp_cache->registerNamespace( 'ds', 'http://www.w3.org/2000/09/xmldsig#' );
			$xp_cache->registerNamespace( 'xenc', 'http://www.w3.org/2001/04/xmlenc#' );
		}

		$results = $xp_cache->query( $query, $node );
		$ret     = array();
		for ( $i = 0; $i < $results->length; $i++ ) {
			$ret[ $i ] = $results->item( $i );
		}

		return $ret;
	}

	/**
	 * This function validates the element in the XML
	 * document.
	 *
	 * @param \DOMElement $root Refers to the XML Document.
	 * @return array
	 */
	public static function validate_element( \DOMElement $root ) {
		$obj_xml_sec_d_sig = new XMLSecurityDSig();

		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with XMLSecurityDSig attributes.
		$obj_xml_sec_d_sig->idKeys[] = 'ID';

		$signature_element = self::xp_query( $root, './ds:Signature' );

		if ( count( $signature_element ) === 0 ) {

			return false;
		} elseif ( count( $signature_element ) > 1 ) {
			echo 'XMLSec: more than one signature element in root.';
			exit;
		}

		$signature_element = $signature_element[0];
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with XMLSecurityDSig attributes.
		$obj_xml_sec_d_sig->sigNode = $signature_element;

		$obj_xml_sec_d_sig->canonicalizeSignedInfo();

		if ( ! $obj_xml_sec_d_sig->validateReference() ) {
			echo 'XMLsec: digest validation failed';
			exit;
		}

		$root_signed = false;

		foreach ( $obj_xml_sec_d_sig->getValidatedNodes() as $signed_node ) {
			if ( $signed_node->isSameNode( $root ) ) {
				$root_signed = true;
				break;
				// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMElement attributes.
			} elseif ( $root->parentNode instanceof \DOMDocument && $signed_node->isSameNode( $root->ownerDocument ) ) {

				$root_signed = true;
				break;
			}
		}

		if ( ! $root_signed ) {
			echo 'XMLSec: The root element is not signed.';
			exit;
		}

		$certificates = array();
		foreach ( self::xp_query( $signature_element, './ds:KeyInfo/ds:X509Data/ds:X509Certificate' ) as $cert_node ) {
			// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMNode attributes.
			$cert_data      = trim( $cert_node->textContent );
			$cert_data      = str_replace( array( "\r", "\n", "\t", ' ' ), '', $cert_data );
			$certificates[] = $cert_data;
		}

		$ret = array(
			'Signature'    => $obj_xml_sec_d_sig,
			'Certificates' => $certificates,
		);

		return $ret;
	}

	/**
	 * This function parses the XML Document, and returns
	 * a boolean value for the attribute in question.
	 *
	 * @param \DOMElement $node Refers to the XML Document.
	 * @param string      $attribute_name Refers to the attribute value to check.
	 * @param mixed|null  $default_value Refers to the value to return in case the attribute is not present in the XML Document.
	 * @return boolean
	 * @throws \Exception In case the attribute contains a non-boolean value.
	 */
	public static function parse_boolean( \DOMElement $node, $attribute_name, $default_value = null ) {
		if ( ! $node->hasAttribute( $attribute_name ) ) {
			return $default_value;
		}
		$value = $node->getAttribute( $attribute_name );
		switch ( strtolower( $value ) ) {
			case '0':
			case 'false':
				return false;
			case '1':
			case 'true':
				return true;
			default:
				throw new \Exception( 'Invalid value of boolean attribute ' . print_r( $attribute_name, true ) . ': ' . var_export( $value, true ) ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_print_r, WordPress.PHP.DevelopmentFunctions.error_log_var_export -- Debugging function requires use of `error_log()`.
		}
	}

	/**
	 * This function is use to sanitize the certificate.
	 *
	 * @param string $certificate Refers to the certificate to sanitize.
	 * @return string
	 */
	public static function sanitize_certificate( $certificate ) {
		$certificate = preg_replace( "/[\r\n]+/", '', $certificate );
		$certificate = str_replace( '-', '', $certificate );
		$certificate = str_replace( 'BEGIN CERTIFICATE', '', $certificate );
		$certificate = str_replace( 'END CERTIFICATE', '', $certificate );
		$certificate = str_replace( ' ', '', $certificate );
		$certificate = chunk_split( $certificate, 64, "\r\n" );
		$certificate = "-----BEGIN CERTIFICATE-----\r\n" . $certificate . '-----END CERTIFICATE-----';
		return $certificate;
	}

	/**
	 * This function is used to desantize the certificate.
	 *
	 * @param string $certificate Refers to the certificate to desantize.
	 * @return string
	 */
	public static function desanitize_certificate( $certificate ) {
		$certificate = preg_replace( "/[\r\n]+/", '', $certificate );
		$certificate = str_replace( '-----BEGIN CERTIFICATE-----', '', $certificate );
		$certificate = str_replace( '-----END CERTIFICATE-----', '', $certificate );
		$certificate = str_replace( ' ', '', $certificate );
		return $certificate;
	}
}
