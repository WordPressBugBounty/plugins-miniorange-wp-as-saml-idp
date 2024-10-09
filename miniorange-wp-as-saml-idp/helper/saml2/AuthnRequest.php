<?php
/**
 * This class contains the `AuthnRequest` class which describes
 * the SAML Request.
 *
 * @package miniorange-wp-as-saml-idp\helper\saml2
 */

namespace IDP\Helper\SAML2;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidRequestInstantException;
use IDP\Exception\InvalidRequestVersionException;
use IDP\Exception\MissingIssuerValueException;
use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Factory\RequestHandlerFactory;
use IDP\Helper\Utilities\SAMLUtilities;

/**
 * This class parses and validates
 * the $xml passed as a valid SAML Request.
 */
class AuthnRequest implements RequestHandlerFactory {

	/**
	 * The incoming SAML Request (AuthnRequest) XML.
	 *
	 * @var \DOMElement $xml
	 */
	private $xml;

	/**
	 * The endpoint where the SAML Response is consumed.
	 *
	 * @var string $assertion_consumer_service_url
	 */
	private $assertion_consumer_service_url;

	/**
	 * The unique identifier of the Service Provider.
	 *
	 * @var string $issuer
	 */
	private $issuer;

	/**
	 * The version of the AuthnRequest.
	 *
	 * @var string $version
	 */
	private $version;

	/**
	 * The timestamp at which the AuthnRequest
	 * was generated.
	 *
	 * @var string $issue_instant
	 */
	private $issue_instant;

	/**
	 * The unique ID of the AuthnRequest.
	 *
	 * @var string $request_id
	 */
	private $request_id;

	/**
	 * The type of the incoming SSO Request.
	 *
	 * @var string $request_type
	 */
	private $request_type = MoIDPConstants::AUTHN_REQUEST;

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param \DOMElement|null $xml Refers to the incoming SAML Request (AuthnRequest) XML.
	 * @throws InvalidRequestInstantException Exception when the AuthnRequest generation timestamp is ahead of the current timestamp.
	 * @throws InvalidRequestVersionException Exception when the AuthnRequest SAML version is not 2.0.
	 * @throws MissingIssuerValueException Exception when the AuthnRequest does not contain the Issuer.
	 */
	public function __construct( \DOMElement $xml = null ) {
		if ( null === $xml ) {
			return;
		}
		$this->xml = $xml;
		if ( $xml->hasAttribute( 'AssertionConsumerServiceURL' ) ) {
			$this->assertion_consumer_service_url = $xml->getAttribute( 'AssertionConsumerServiceURL' );
		}
		if ( $xml->hasAttribute( 'Version' ) ) {
			$this->version = $xml->getAttribute( 'Version' );

		}
		if ( $xml->hasAttribute( 'IssueInstant' ) ) {
			$this->issue_instant = $xml->getAttribute( 'IssueInstant' );

		}
		if ( $xml->hasAttribute( 'ID' ) ) {
			$this->request_id = $xml->getAttribute( 'ID' );

		}
		$this->check_authn_request_issue_instant();
		$this->check_saml_request_version();
		$this->parse_issuer( $xml );
	}

	/**
	 * Parse the incoming SAML Request XML to
	 * set the value of the `$issuer`.
	 *
	 * @param \DOMElement $xml The incoming SAML Request XML.
	 * @return void
	 * @throws MissingIssuerValueException Exception when the AuthnRequest does not contain the Issuer.
	 */
	protected function parse_issuer( \DOMElement $xml ) {
		$issuer = SAMLUtilities::xp_query( $xml, './saml_assertion:Issuer' );
		if ( empty( $issuer ) ) {
			throw new MissingIssuerValueException();
		}
		$this->issuer = trim( $issuer[0]->textContent );
	}

	/**
	 * This function checks if the issueInstant in the SAML request is
	 * within the valid time frame and that it's not a stale request.
	 *
	 * @return void
	 * @throws InvalidRequestInstantException Exception when the AuthnRequest generation timestamp is ahead of the current timestamp.
	 */
	public function check_authn_request_issue_instant() {
		if ( strtotime( $this->issue_instant ) >= time() + 60 ) {
			throw new InvalidRequestInstantException();
		}
	}

	/**
	 * This function checks the version of the SAML request made.
	 * Makes sure the SAML request is a valid SAML 2.0 request.
	 *
	 * @return void
	 * @throws InvalidRequestVersionException Exception when the AuthnRequest SAML version is not 2.0.
	 */
	public function check_saml_request_version() {
		if ( '2.0' !== $this->version ) {
			throw new InvalidRequestVersionException();
		}
	}

	/**
	 * This function is used to generate AuthnRequest. This is currently
	 * not implemented as AuthnRequest is mostly generated on the SP side
	 * and this is the IDP plugin.
	 *
	 * @return void
	 */
	public function generate_request() {
	}

	/**
	|                                          |
	| GETTER , SETTERS AND TO STRING FUNCTION  |
	|                                          |
	 */

	/**
	 * Returns the string representation of AuthnRequest,
	 * with all the relevant members.
	 *
	 * @return string
	 */
	public function __toString() {
		$html  = '[ AUTHN REQUEST PARAMS';
		$html .= ', ID = ' . $this->request_id;
		$html .= ', Issuer = ' . $this->issuer;
		$html .= ', ACS URL = ' . $this->assertion_consumer_service_url;
		$html .= ', Issue Instant = ' . $this->issue_instant;
		$html .= ', Version = ' . $this->version;
		$html .= ']';
		return $html;
	}

	/**
	 * Getter function for `$xml`.
	 *
	 * @return \DOMElement
	 */
	public function get_xml() {
		return $this->xml;
	}

	/**
	 * Setter function for `$xml`.
	 *
	 * @param \DOMElement $xml The incoming SAML Request (AuthnRequest) XML.
	 * @return AuthnRequest
	 */
	public function set_xml( $xml ) {
		$this->xml = $xml;
		return $this;
	}

	/**
	 * Getter function for `$assertion_consumer_service_url`.
	 *
	 * @return string
	 */
	public function get_assertion_consumer_service_url() {
		return $this->assertion_consumer_service_url;
	}

	/**
	 * Setter function for `$assertion_consumer_service_url`.
	 *
	 * @param string $assertion_consumer_service_url The endpoint where the SAML Response is consumed.
	 * @return AuthnRequest
	 */
	public function set_assertion_consumer_service_url( $assertion_consumer_service_url ) {
		$this->assertion_consumer_service_url = $assertion_consumer_service_url;
		return $this;
	}

	/**
	 * Getter function for `$issuer`.
	 *
	 * @return string
	 */
	public function get_issuer() {
		return $this->issuer;
	}

	/**
	 * Setter function for `$issuer`.
	 *
	 * @param string $issuer The unique identifier of the Service Provider.
	 * @return AuthnRequest
	 */
	public function set_issuer( $issuer ) {
		$this->issuer = $issuer;
		return $this;
	}

	/**
	 * Getter function for `$request_id`.
	 *
	 * @return string
	 */
	public function get_request_id() {
		return $this->request_id;
	}

	/**
	 * Setter function for `$request_id`.
	 *
	 * @param string $request_id The unique ID of the AuthnRequest.
	 * @return AuthnRequest
	 */
	public function set_request_id( $request_id ) {
		$this->request_id = $request_id;
		return $this;
	}

	/**
	 * Getter function for `$request_type`.
	 *
	 * @return string
	 */
	public function get_request_type() {
		return $this->request_type;
	}

	/**
	 * Setter function for `$request_type`.
	 *
	 * @param string $request_type The type of the incoming SSO Request.
	 * @return AuthnRequest
	 */
	public function set_request_type( $request_type ) {
		$this->request_type = $request_type;
		return $this;
	}
}
