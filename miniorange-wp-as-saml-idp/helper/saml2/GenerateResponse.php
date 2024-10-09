<?php
/**
 * This class contains the `GenerateResponse` class which is
 * responsible for generating the SAML Response.
 *
 * @package miniorange-wp-as-saml-idp\helper\saml2
 */

namespace IDP\Helper\SAML2;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidSSOUserException;
use IDP\Helper\Utilities\MoIDPUtility;
use \RobRichards\XMLSecLibs\XMLSecurityKey;
use \RobRichards\XMLSecLibs\XMLSecurityDSig;
use IDP\Helper\Factory\ResponseHandlerFactory;

/**
 * This class is used to generate the SAML Response to
 * be sent to the SP. The response can be signed or unsigned
 * depending on plugin settings.
 */
class GenerateResponse implements ResponseHandlerFactory {

	/**
	 * The SAML Response XML.
	 *
	 * @var \DOMDocument $xml
	 */
	private $xml;

	/**
	 * The endpoint where the SAML Response is consumed.
	 *
	 * @var string $acs_url
	 */
	private $acs_url;

	/**
	 * The unique identifier of the Service Provider.
	 *
	 * @var string $issuer
	 */
	private $issuer;

	/**
	 * The intended recipient of the SAML Response.
	 *
	 * @var string $audience
	 */
	private $audience;

	/**
	 * List of attributes to be sent to the Service Provider.
	 *
	 * @var array $sp_attr
	 */
	private $sp_attr;

	/**
	 * The unique ID of the AuthnRequest.
	 *
	 * @var string $request_id
	 */
	private $request_id;

	/**
	 * The XML element that identifies the principal
	 * for whom the Assertion is being made.
	 * Contains `NameID` and `SubjectConfirmation` nodes.
	 *
	 * @var \DOMNode $subject
	 */
	private $subject;

	/**
	 * Flag to denote if the SAML Assertion is signed.
	 *
	 * @var boolean $mo_idp_assertion_signed
	 */
	private $mo_idp_assertion_signed;

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
	 * @param string                 $acs_url The endpoint where the SAML Response is consumed.
	 * @param string                 $issuer The unique identifier of the Service Provider.
	 * @param string                 $audience The intended recipient of the SAML Response.
	 * @param string                 $request_id The unique ID of the AuthnRequest.
	 * @param array                  $sp_attr The unique ID of the AuthnRequest.
	 * @param array|object|null|void $sp The Service Provider object from the database.
	 * @param string                 $login Username of the logged in user.
	 */
	public function __construct( $acs_url, $issuer, $audience, $request_id, $sp_attr, $sp, $login ) {
		$this->xml                     = new \DOMDocument( '1.0', 'utf-8' );
		$this->acs_url                 = $acs_url;
		$this->issuer                  = $issuer;
		$this->audience                = $audience;
		$this->request_id              = $request_id;
		$this->sp_attr                 = $sp_attr;
		$this->mo_idp_nameid_format    = $sp->mo_idp_nameid_format;
		$this->mo_idp_assertion_signed = $sp->mo_idp_assertion_signed;
		$this->mo_idp_nameid_attr      = $sp->mo_idp_nameid_attr;
		$this->current_user            = is_null( $login ) ? wp_get_current_user() : get_user_by( 'login', $login );
	}

	/**
	 * The main function that is called to create the SAML Response.
	 * This function in turn processes and decides which elements
	 * need to be present in the SAML Response.
	 *
	 * @return string
	 * @throws InvalidSSOUserException Exception when the user is not logged into WordPress.
	 */
	public function generate_response() {
		if ( MoIDPUtility::is_blank( $this->current_user ) ) {
			throw new InvalidSSOUserException();
		}
		$response_params = $this->get_response_params();

		// Create Response Element.
		$resp = $this->create_response_element( $response_params );
		$this->xml->appendChild( $resp );

		// Build Issuer.
		$issuer = $this->build_issuer();
		$resp->appendChild( $issuer );

		// Build Status.
		$status = $this->build_status();
		$resp->appendChild( $status );

		$status_code = $this->build_status_code();
		$status->appendChild( $status_code );

		// Build Assertion.
		$assertion = $this->build_assertion( $response_params );
		$resp->appendChild( $assertion );

		// Sign Assertion.
		if ( $this->mo_idp_assertion_signed ) {
			$private_key = MoIDPUtility::get_private_key();
			$this->sign_node( $private_key, $assertion, $this->subject, $response_params );
		}

		$saml_response = $this->xml->saveXML();

		return $saml_response;
	}

	/**
	 * This function is used to get some common response parameters like the
	 * TimeStamps, Issue value ID, assertId, the certificate, etc. This function
	 * is basically used to generate all the static values of the SAML Response.
	 *
	 * @return array
	 */
	private function get_response_params() {
		$response_params                        = array();
		$time                                   = time();
		$response_params['IssueInstant']        = str_replace( '+00:00', 'Z', gmdate( 'c', $time ) );
		$response_params['NotOnOrAfter']        = str_replace( '+00:00', 'Z', gmdate( 'c', $time + 300 ) );
		$response_params['NotBefore']           = str_replace( '+00:00', 'Z', gmdate( 'c', $time - 30 ) );
		$response_params['AuthnInstant']        = str_replace( '+00:00', 'Z', gmdate( 'c', $time - 120 ) );
		$response_params['SessionNotOnOrAfter'] = str_replace( '+00:00', 'Z', gmdate( 'c', $time + 3600 * 8 ) );
		$response_params['ID']                  = $this->generate_unique_id( 40 );
		$response_params['AssertID']            = $this->generate_unique_id( 40 );
		$response_params['Issuer']              = $this->issuer;
		$public_key                             = MoIDPUtility::get_public_cert();
		$obj_key                                = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, array( 'type' => 'public' ) );
		$obj_key->loadKey( $public_key, false, true );
		$response_params['x509'] = $obj_key->getX509Certificate();
		return $response_params;
	}

	/**
	 * This function is used to create the Response element of the SAML XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function create_response_element( $response_params ) {
		$resp = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Response' );
		$resp->setAttribute( 'ID', $response_params['ID'] );
		$resp->setAttribute( 'Version', '2.0' );
		$resp->setAttribute( 'IssueInstant', $response_params['IssueInstant'] );
		$resp->setAttribute( 'Destination', $this->acs_url );
		if ( ! is_null( $this->request_id ) ) {
			$resp->setAttribute( 'InResponseTo', $this->request_id );
		}
		return $resp;
	}

	/**
	 * This function builds the Issuer element of the SAML XML Response.
	 *
	 * @return \DOMNode
	 */
	private function build_issuer() {
		$issuer = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Issuer', $this->issuer );
		return $issuer;
	}

	/**
	 * This function builds the Status element of the SAML XML Response.
	 *
	 * @return \DOMNode
	 */
	private function build_status() {
		$status = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:Status' );
		return $status;
	}

	/**
	 * This function builds the StatusCode element of the SAML XML Response.
	 *
	 * @return \DOMNode
	 */
	private function build_status_code() {
		$status_code = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:protocol', 'samlp:StatusCode' );
		$status_code->setAttribute( 'Value', 'urn:oasis:names:tc:SAML:2.0:status:Success' );
		return $status_code;
	}

	/**
	 * This function builds the Assertion element of the SAML XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_assertion( $response_params ) {
		$assertion = $this->xml->createElementNS( 'urn:oasis:names:tc:SAML:2.0:assertion', 'saml:Assertion' );
		$assertion->setAttribute( 'ID', $response_params['AssertID'] );
		$assertion->setAttribute( 'IssueInstant', $response_params['IssueInstant'] );
		$assertion->setAttribute( 'Version', '2.0' );

		// Build Issuer.
		$issuer = $this->build_issuer( $response_params );
		$assertion->appendChild( $issuer );

		// Build Subject.
		$subject       = $this->build_subject( $response_params );
		$this->subject = $subject;
		$assertion->appendChild( $subject );

		// Build Condition.
		$condition = $this->build_condition( $response_params );
		$assertion->appendChild( $condition );

		// Build AuthnStatement.
		$authnstat = $this->build_authn_statement( $response_params );
		$assertion->appendChild( $authnstat );

		return $assertion;
	}

	/**
	 * This function builds the Subject element of the SAML XML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_subject( $response_params ) {
		$subject = $this->xml->createElement( 'saml:Subject' );
		$nameid  = $this->build_name_identifier();
		$subject->appendChild( $nameid );
		$confirmation = $this->build_subject_confirmation( $response_params );
		$subject->appendChild( $confirmation );
		return $subject;
	}

	/**
	 * This function builds the nameIdentifier element of the SAML XML Response.
	 * This is an important element, and needs to have a value specified when the
	 * SAML Response is generated.
	 *
	 * @return \DOMNode
	 */
	private function build_name_identifier() {
		$name_id_key   = ! empty( $this->mo_idp_nameid_attr ) && 'emailAddress' !== $this->mo_idp_nameid_attr ? $this->mo_idp_nameid_attr : 'user_email';
		$name_id_value = MoIDPUtility::is_blank( $this->current_user->$name_id_key )
					? get_user_meta( $this->current_user->ID, $name_id_key, true ) : $this->current_user->$name_id_key;

		$name_id_value = apply_filters( 'generate_saml_attribute_value', $name_id_value, $this->current_user, 'NameID' );

		$name_id = $this->xml->createElement( 'saml:NameID', $name_id_value );
		$name_id->setAttribute( 'Format', 'urn:oasis:names:tc:SAML:' . $this->mo_idp_nameid_format );
		return $name_id;
	}

	/**
	 * This function is used build the SubjectConfirmation element.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_subject_confirmation( $response_params ) {
		$confirmation = $this->xml->createElement( 'saml:SubjectConfirmation' );
		$confirmation->setAttribute( 'Method', 'urn:oasis:names:tc:SAML:2.0:cm:bearer' );
		$confirmation_data = $this->build_subject_confirmation_data( $response_params );
		$confirmation->appendChild( $confirmation_data );
		return $confirmation;
	}

	/**
	 * This function is used build the SubjectConfirmationData element.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_subject_confirmation_data( $response_params ) {
		$confirmation_data = $this->xml->createElement( 'saml:SubjectConfirmationData' );
		$confirmation_data->setAttribute( 'NotOnOrAfter', $response_params['NotOnOrAfter'] );
		$confirmation_data->setAttribute( 'Recipient', $this->acs_url );
		if ( ! is_null( $this->request_id ) ) {
			$confirmation_data->setAttribute( 'InResponseTo', $this->request_id );
		}
		return $confirmation_data;
	}

	/**
	 * This function is used add the NotBefore or NotOnOrAfter attributes of the
	 * assertion. This is to make sure there are no stale responses.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_condition( $response_params ) {
		$condition = $this->xml->createElement( 'saml:Conditions' );
		$condition->setAttribute( 'NotBefore', $response_params['NotBefore'] );
		$condition->setAttribute( 'NotOnOrAfter', $response_params['NotOnOrAfter'] );

		// Build AudienceRestriction.
		$audiencer = $this->build_audience_restriction();
		$condition->appendChild( $audiencer );

		return $condition;
	}

	/**
	 * This function is used add the AudienceRestriction XML element of the
	 * SAML Response.
	 *
	 * @return \DOMNode
	 */
	private function build_audience_restriction() {
		$audience_restriction = $this->xml->createElement( 'saml:AudienceRestriction' );
		$audience             = $this->xml->createElement( 'saml:Audience', $this->audience );
		$audience_restriction->appendChild( $audience );
		return $audience_restriction;
	}

	/**
	 * This function is used build the AuthnStatement element of the SAML Response.
	 *
	 * @param array $response_params The static params generated by `get_response_params()` function.
	 * @return \DOMNode
	 */
	private function build_authn_statement( $response_params ) {
		$authnstat = $this->xml->createElement( 'saml:AuthnStatement' );
		$authnstat->setAttribute( 'AuthnInstant', $response_params['AuthnInstant'] );
		$authnstat->setAttribute( 'SessionIndex', '_' . $this->generate_unique_id( 30 ) );
		$authnstat->setAttribute( 'SessionNotOnOrAfter', $response_params['SessionNotOnOrAfter'] );

		$authncontext     = $this->xml->createElement( 'saml:AuthnContext' );
		$authncontext_ref = $this->xml->createElement( 'saml:AuthnContextClassRef', 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport' );
		$authncontext->appendChild( $authncontext_ref );
		$authnstat->appendChild( $authncontext );

		return $authnstat;
	}

	/**
	 * Used to sign the Response or Assertion, and append the signature and
	 * public certificate in the SAML response. This function is only called
	 * if Response or Assertion is signed.
	 *
	 * @param string   $private_key The key to sign the response or assertion with.
	 * @param \DOMNode $node The node after or before which the signature will be appended.
	 * @param \DOMNode $subject Refers to the subject.
	 * @param array    $response_params The static params generated by `get_response_params()` function.
	 * @return void
	 */
	private function sign_node( $private_key, $node, $subject, $response_params ) {
		// Private key.
		$obj_key = new XMLSecurityKey( XMLSecurityKey::RSA_SHA256, array( 'type' => 'private' ) );
		$obj_key->loadKey( $private_key, false );

		// Sign the Assertion.
		$obj_xml_sec_d_sig = new XMLSecurityDSig();
		$obj_xml_sec_d_sig->setCanonicalMethod( XMLSecurityDSig::EXC_C14N );

		$obj_xml_sec_d_sig->addReferenceList(
			array( $node ),
			XMLSecurityDSig::SHA256,
			array( 'http://www.w3.org/2000/09/xmldsig#enveloped-signature', XMLSecurityDSig::EXC_C14N ),
			array(
				'id_name'   => 'ID',
				'overwrite' => false,
			)
		);
		$obj_xml_sec_d_sig->sign( $obj_key );
		$obj_xml_sec_d_sig->add509Cert( $response_params['x509'] );
		$obj_xml_sec_d_sig->insertSignature( $node, $subject );
	}

	/**
	 * Function is used to generate a unique ID to
	 * be used to generate unique SAML Response IDs.
	 *
	 * @param int $length A value to denote the length of unique ID.
	 * @return string
	 */
	private function generate_unique_id( $length ) {
		return MoIDPUtility::generate_random_alphanumeric_value( $length );
	}
}
