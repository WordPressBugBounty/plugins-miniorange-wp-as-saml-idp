<?php
/**
 * This class contains the `WsFedRequest` class which describes
 * the WS-Fed Request.
 *
 * @package miniorange-wp-as-saml-idp\helper\wsfed
 */

namespace IDP\Helper\WSFED;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\MissingWaAttributeException;
use IDP\Exception\MissingWtRealmAttributeException;
use IDP\Helper\Constants\MoIDPConstants;
use IDP\Helper\Factory\RequestHandlerFactory;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class parses the $_REQUEST to build a
 * WS-Fed Request.
 */
class WsFedRequest implements RequestHandlerFactory {

	/**
	 * The client-generated identifier for the WS-Fed request.
	 *
	 * @var string $client_request_id
	 */
	private $client_request_id;

	/**
	 * This is used to pass context information between the
	 * relying party and the identity provider.
	 *
	 * @var string $wctx
	 */
	private $wctx;

	/**
	 * The type of response that the client expects to receive.
	 *
	 * @var string $wa
	 */
	private $wa;

	/**
	 * The relying party realm that the Response is intended for.
	 *
	 * @var string $wtrealm
	 */
	private $wtrealm;

	/**
	 * The type of the incoming SSO Request.
	 *
	 * @var string $request_type
	 */
	private $request_type = MoIDPConstants::WS_FED;

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param array $sanitized_request Sanitized PHP Superglobals `$_REQUEST`.
	 * @throws MissingWaAttributeException Exception when the WS-Fed Request does not contain the `wa` attribute.
	 * @throws MissingWtRealmAttributeException Exception when the WS-Fed Request does not contain the `wtrealm` attribute.
	 */
	public function __construct( $sanitized_request ) {
		$this->client_request_id = ! empty( $sanitized_request['client-request-id'] ) ? $sanitized_request['client-request-id'] : null;
		$this->wa                = ! empty( $sanitized_request['wa'] ) ? $sanitized_request['wa'] : null;
		$this->wtrealm           = ! empty( $sanitized_request['wtrealm'] ) ? $sanitized_request['wtrealm'] : null;
		$this->wctx              = ! empty( $sanitized_request['wctx'] ) ? $sanitized_request['wctx'] : null;

		if ( MoIDPUtility::is_blank( $this->wa ) ) {
			throw new MissingWaAttributeException();

		}
		if ( MoIDPUtility::is_blank( $this->wtrealm ) ) {
			throw new MissingWtRealmAttributeException();
		}
	}

	/**
	 * This function is used to generate WsFedRequest. This is currently
	 * not implemented as WsFedRequest is mostly generated on the SP side
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
	 * Returns the string representation of WsFedRequest,
	 * with all the relevant members.
	 *
	 * @return string
	 */
	public function __toString() {
		$html  = 'WS-FED REQUEST PARAMS [';
		$html .= ' wa = ' . $this->wa;
		$html .= ', wtrealm =  ' . $this->wtrealm;
		$html .= ', clientRequestId = ' . $this->client_request_id;
		$html .= ', wctx = ' . $this->wctx;
		$html .= ']';
		return $html;
	}

	/**
	 * Getter function for `$client_request_id`.
	 *
	 * @return string
	 */
	public function get_client_request_id() {
		return $this->client_request_id;
	}

	/**
	 * Setter function for `$client_request_id`.
	 *
	 * @param string $client_request_id The client-generated identifier for the WS-Fed request.
	 * @return WsFedRequest
	 */
	public function set_client_request_id( $client_request_id ) {
		$this->client_request_id = $client_request_id;
		return $this;
	}

	/**
	 * Getter function for `$wctx`.
	 *
	 * @return string
	 */
	public function get_wctx() {
		return $this->wctx;
	}

	/**
	 * Setter function for `$wctx`.
	 *
	 * @param string $wctx This is used to pass context information between the relying party and the identity provider.
	 * @return WsFedRequest
	 */
	public function set_wctx( $wctx ) {
		$this->wctx = $wctx;
		return $this;
	}

	/**
	 * Getter function for `$wa`.
	 *
	 * @return string
	 */
	public function get_wa() {
		return $this->wa;
	}

	/**
	 * Setter function for `$wa`.
	 *
	 * @param string $wa The type of response that the client expects to receive.
	 * @return WsFedRequest
	 */
	public function set_wa( $wa ) {
		$this->wa = $wa;
		return $this;
	}

	/**
	 * Getter function for `$wtrealm`.
	 *
	 * @return string
	 */
	public function get_wtrealm() {
		return $this->wtrealm;
	}

	/**
	 * Setter function for `$wtrealm`.
	 *
	 * @param string $wtrealm The relying party realm that the Response is intended for.
	 * @return WsFedRequest
	 */
	public function set_wtrealm( $wtrealm ) {
		$this->wtrealm = $wtrealm;
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
	 * @return WsFedRequest
	 */
	public function set_request_type( $request_type ) {
		$this->request_type = $request_type;
		return $this;
	}
}
