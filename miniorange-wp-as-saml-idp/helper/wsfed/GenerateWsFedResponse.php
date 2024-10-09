<?php
/**
 * This class contains the `GenerateWsFedResponse` class which is
 * responsible for generating the WS-Fed Response.
 *
 * @package miniorange-wp-as-saml-idp\helper\wsfed
 */

namespace IDP\Helper\WSFED;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Utilities\MoIDPUtility;
use \RobRichards\XMLSecLibs\XMLSecurityKey;
use \RobRichards\XMLSecLibs\XMLSecurityDSig;
use IDP\Exception\InvalidSSOUserException;
use IDP\Helper\Factory\ResponseHandlerFactory;

/**
 * This class is used to generate the WS-Fed Response to
 * be sent to the client. The response can be signed or unsigned
 * depending on plugin settings.
 */
class GenerateWsFedResponse implements ResponseHandlerFactory {

	/**
	 * The WS-Fed Response XML.
	 *
	 * @var \DOMDocument $xml
	 */
	private $xml;

	/**
	 * This element identifies the entity
	 * that issued the security token.
	 *
	 * @var string $issuer
	 */
	private $issuer;

	/**
	 * The relying party realm that the Response is intended for.
	 *
	 * @var string $wtrealm
	 */
	private $wtrealm;

	/**
	 * The type of response that the client expects to receive.
	 *
	 * @var string $wa
	 */
	private $wa;

	/**
	 * This is used to pass context information between the
	 * relying party and the identity provider.
	 *
	 * @var string $wctx
	 */
	private $wctx;

	/**
	 * List of attributes to be sent to the Service Provider.
	 *
	 * @var array $sp_attr
	 */
	private $sp_attr;

	/**
	 * The XML element that identifies the principal
	 * for whom the Assertion is being made.
	 * Contains `NameID` and `SubjectConfirmation` nodes.
	 *
	 * @var \DOMNode $subject
	 */
	private $subject;

	/**
	 * The NameID Attribute key.
	 *
	 * @var string $mo_idp_nameid_attr
	 */
	private $mo_idp_nameid_attr;

	/**
	 * The NameID Format.
	 *
	 * @var string $mo_idp_nameid_format
	 */
	private $mo_idp_nameid_format;

	/**
	 * Current logged in user.
	 *
	 * @var \WP_User $current_user
	 */
	private $current_user;

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param string                 $wtrealm The relying party realm that the Response is intended for.
	 * @param string                 $wa The type of response that the client expects to receive.
	 * @param string                 $wctx This is used to pass context information between the relying party and the identity provider.
	 * @param string                 $issuer This element identifies the entity that issued the security token.
	 * @param array|object|null|void $sp The Service Provider object from the database.
	 * @param array                  $sp_attr The unique ID of the AuthnRequest.
	 * @param string                 $login Username of the logged in user.comment.
	 */
	public function __construct( $wtrealm, $wa, $wctx, $issuer, $sp, $sp_attr, $login ) {
		$this->xml                     = new \DOMDocument( '1.0', 'utf-8' );
		$this->xml->preserveWhiteSpace = false;
		$this->xml->formatOutput       = false;
		$this->wctx                    = $wctx;
		$this->issuer                  = $issuer;
		$this->wtrealm                 = $wtrealm;
		$this->sp_attr                 = $sp_attr;
		$this->wa                      = $wa;
		$this->mo_idp_nameid_format    = $sp->mo_idp_nameid_format;
		$this->mo_idp_nameid_attr      = $sp->mo_idp_nameid_attr;
		$this->current_user            = is_null( $login ) ? wp_get_current_user() : get_user_by( 'login', $login );
	}

	/**
	 * The main function that is called to create the WS-Fed Response.
	 * This function in turn processes and decides which elements
	 * need to be present in the WS-Fed Response.
	 *
	 * @return string
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function generate_response() {
		if ( MoIDPUtility::is_blank( $this->current_user ) ) {
			throw new InvalidSSOUserException();
		}
		$response_params = $this->get_response_params();

		// Create Response Elements.
		$resp = $this->create_response_element( $response_params );
		$this->xml->appendChild( $resp );

		// Sign the node.
		$private_key = MoIDPUtility::get_private_key();
		// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Working with PHP DOMNode attributes.
		$this->sign_node( $private_key, $resp->firstChild->nextSibling->nextSibling->firstChild, null, $response_params );

		$xml_response_string = $this->xml->saveXML();
		return $xml_response_string;
	}

	/**
	 * This function is used to get some common response parameters like the
	 * TimeStamps, assertId, the certificate, etc. This function is
	 * basically used to generate all the static values of the WS-Fed Response.
	 *
	 * @return array
	 */
	private function get_response_params() {
		$response_params                 = array();
		$time                            = time();
		$response_params['IssueInstant'] = str_replace( '+00:00', 'Z', gmdate( 'c', $time ) );
		$response_params['NotOnOrAfter'] = str_replace( '+00:00', 'Z', gmdate( 'c', $time + 300 ) );
		$response_params['NotBefore']    = str_replace( '+00:00', 'Z', gmdate( 'c', $time - 30 ) );
		$response_params['AuthnInstant'] = str_replace( '+00:00', 'Z', gmdate( 'c', $time - 120 ) );
		$response_params['AssertID']     = $this->generate_unique_id( 40 );

		$public_key = MoIDPUtility::get_public_cert();
		$obj_key    = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, array( 'type' => 'public' ) );
		$obj_key->loadKey( $public_key, false, true );
		$response_params['x509'] = $obj_key->getX509Certificate();
		return $response_params;
	}

	/**
	 * Function is used to generate a unique ID to
	 * be used to generate unique WS-Fed Response IDs.
	 *
	 * @param int $length A value to denote the length of unique ID.
	 * @return string
	 */
	private function generate_unique_id( $length ) {
		return MoIDPUtility::generate_random_alphanumeric_value( $length );
	}

	/**
	 * This function is used to create the Response element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_response_element( $response_params ) {
		$resp = $this->xml->createElementNS( 'http://schemas.xmlsoap.org/ws/2005/02/trust', 't:RequestSecurityTokenResponse' );

		$resp1 = $this->create_response_element_lifetime( $response_params );
		$resp->appendChild( $resp1 );

		$resp2 = $this->create_response_element_applies_to( $response_params );
		$resp->appendChild( $resp2 );

		$resp3 = $this->create_requested_security_token( $response_params );

		$resp->appendChild( $resp3 );

		$resp4 = $this->create_token_type();
		$resp->appendChild( $resp4 );

		$resp5 = $this->create_request_type();
		$resp->appendChild( $resp5 );

		$resp6 = $this->create_key_type();
		$resp->appendChild( $resp6 );

		return $resp;
	}

	/**
	 * This function builds the TokenType element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_token_type() {
		$resp = $this->xml->createElement( 't:TokenType', 'urn:oasis:names:tc:SAML:1.0:assertion' );
		return $resp;
	}

	/**
	 * This function builds the KeyType element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_key_type() {
		$resp = $this->xml->createElement( 't:KeyType', 'http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey' );
		return $resp;
	}

	/**
	 * This function builds the RequestType element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_request_type() {
		$resp = $this->xml->createElement( 't:RequestType', 'http://schemas.xmlsoap.org/ws/2005/02/trust/Issue' );
		return $resp;
	}

	/**
	 * This function builds the RequestedSecurityToken element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_requested_security_token( $response_params ) {
		$resp  = $this->xml->createElement( 't:RequestedSecurityToken' );
		$resp1 = $this->create_assertion( $response_params );
		$resp->appendChild( $resp1 );
		return $resp;
	}

	/**
	 * This function builds the assertion element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_assertion( $response_params ) {
		$assertion = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:1.0:assertion', 'saml:Assertion' );
		$assertion->setAttribute( 'MajorVersion', '1' );
		$assertion->setAttribute( 'MinorVersion', '1' );
		$assertion->setAttribute( 'AssertionID', $response_params['AssertID'] );
		$assertion->setAttribute( 'Issuer', $this->issuer );
		$assertion->setAttribute( 'IssueInstant', $response_params['IssueInstant'] );

		$saml_conditions = $this->create_saml_conditions( $response_params );
		$assertion->appendChild( $saml_conditions );

		$authn_statement = $this->create_authentication_statement( $response_params );
		$assertion->appendChild( $authn_statement );

		return $assertion;
	}

	/**
	 * Used to sign the Response or Assertion, and append the signature and
	 * public certificate in the WS-Fed response. This function is only called
	 * if Response or Assertion is signed.
	 *
	 * @param string   $private_key The key to sign the response or assertion with.
	 * @param \DOMNode $node The node after or before which the signature will be appended.
	 * @param \DOMNode $subject Refers to the subject.
	 * @param array    $response_params The static params generated by `get_response_params()` function.
	 * @return void
	 */
	private function sign_node( $private_key, $node, $subject, $response_params ) {
		$obj_key = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, array( 'type' => 'private' ) );
		$obj_key->loadKey( $private_key, false );

		// Sign the Assertion.
		$obj_xml_sec_d_sig = new XMLSecurityDSig();
		$obj_xml_sec_d_sig->setCanonicalMethod( XMLSecurityDSig::EXC_C14N );

		$obj_xml_sec_d_sig->addReferenceList(
			array( $node ),
			XMLSecurityDSig::SHA256,
			array(
				'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
				XMLSecurityDSig::EXC_C14N,
			),
			array(
				'id_name'   => 'AssertionID',
				'overwrite' => false,
			)
		);
		$obj_xml_sec_d_sig->sign( $obj_key );
		$obj_xml_sec_d_sig->add509Cert( $response_params['x509'] );

		$obj_xml_sec_d_sig->insertSignature( $node, null );
	}

	/**
	 * This function builds the AuthenticationStatement element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_authentication_statement( $response_params ) {
		$resp = $this->xml->createElement( 'saml:AuthenticationStatement' );
		$resp->setAttribute( 'AuthenticationMethod', 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' );
		$resp->setAttribute( 'AuthenticationInstant', $response_params['AuthnInstant'] );
		$resp1         = $this->create_subject();
		$this->subject = $resp1;
		$resp->appendChild( $resp1 );

		return $resp;
	}

	/**
	 * This function builds the SubjectConfirmation element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_subject_confirmation() {
		$resp  = $this->xml->createElement( 'saml:SubjectConfirmation' );
		$resp1 = $this->create_confirmation_method();
		$resp->appendChild( $resp1 );
		return $resp;
	}

	/**
	 * This function builds the ConfirmationMethod element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_confirmation_method() {
		$resp = $this->xml->createElement( 'saml:ConfirmationMethod', 'urn:oasis:names:tc:SAML:1.0:cm:bearer' );
		return $resp;
	}

	/**
	 * This function builds the Subject element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_subject() {
		$resp  = $this->xml->createElement( 'saml:Subject' );
		$resp1 = $this->create_name_id();
		$resp->appendChild( $resp1 );
		$resp2 = $this->create_subject_confirmation();
		$resp->appendChild( $resp2 );
		return $resp;
	}

	/**
	 * This function builds the NameIdentifier element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_name_id() {
		$name_id_key   = ! empty( $this->mo_idp_nameid_attr ) && 'emailAddress' !== $this->mo_idp_nameid_attr ? $this->mo_idp_nameid_attr : 'user_email';
		$name_id_value = MoIDPUtility::is_blank( $this->current_user->$name_id_key )
					? get_user_meta( $this->current_user->ID, $name_id_key, true ) : $this->current_user->$name_id_key;

		$name_id_value = apply_filters( 'generate_wsfed_attribute_value', $name_id_value, $this->current_user, 'NameID' );
		$resp          = $this->xml->createElement( 'saml:NameIdentifier', $name_id_value );
		$resp->setAttribute( 'Format', 'urn:oasis:names:tc:SAML:' . $this->mo_idp_nameid_format );
		return $resp;
	}

	/**
	 * This function builds the Conditions element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_saml_conditions( $response_params ) {
		$resp = $this->xml->createElement( 'saml:Conditions' );
		$resp->setAttribute( 'NotBefore', $response_params['NotBefore'] );
		$resp->setAttribute( 'NotOnOrAfter', $response_params['NotOnOrAfter'] );

		$resp1 = $this->create_saml_audience();
		$resp->appendChild( $resp1 );
		return $resp;
	}

	/**
	 * This function builds the AudienceRestrictionCondition element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_saml_audience() {
		$resp  = $this->xml->createElement( 'saml:AudienceRestrictionCondition' );
		$resp1 = $this->build_audience();
		$resp->appendChild( $resp1 );
		return $resp;
	}

	/**
	 * This function builds the Audience element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function build_audience() {
		$resp = $this->xml->createElement( 'saml:Audience', $this->wtrealm );
		return $resp;
	}

	/**
	 * This function builds the Lifetime element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_response_element_lifetime( $response_params ) {
		$resp  = $this->xml->createElement( 't:Lifetime' );
		$resp1 = $this->create_lifetime( $response_params );
		$resp2 = $this->expire_lifetime( $response_params );
		$resp->appendChild( $resp1 );
		$resp->appendChild( $resp2 );
		return $resp;
	}

	/**
	 * This function builds the AppliesTo element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_response_element_applies_to( $response_params ) {
		$resp  = $this->xml->createElementNS( 'http://schemas.xmlsoap.org/ws/2004/09/policy', 'wsp:AppliesTo' );
		$resp1 = $this->build_applies_to( $response_params );
		$resp->appendChild( $resp1 );
		return $resp;
	}

	/**
	 * This function builds the EndpointReference element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_applies_to( $response_params ) {
		$resp  = $this->xml->createElementNS( 'http://www.w3.org/2005/08/addressing', 'wsa:EndpointReference' );
		$resp1 = $this->create_address();
		$resp->appendChild( $resp1 );
		return $resp;
	}

	/**
	 * This function builds the Address element of the WS-Fed XML Response.
	 *
	 * @return \DOMNode
	 */
	private function create_address() {
		$resp = $this->xml->createElement( 'wsa:Address', $this->wtrealm );
		return $resp;
	}

	/**
	 * This function builds the Created element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_lifetime( $response_params ) {
		$issue_instant = $response_params['IssueInstant'];
		$resp          = $this->xml->createElementNS(
			'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
			'wsu:Created',
			$issue_instant
		);
		return $resp;
	}

	/**
	 * This function builds the Expires element of the WS-Fed XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function expire_lifetime( $response_params ) {
		$not_on_or_after = $response_params['NotOnOrAfter'];
		$resp            = $this->xml->createElementNS(
			'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd',
			'wsu:Expires',
			$not_on_or_after
		);
		return $resp;
	}
}
