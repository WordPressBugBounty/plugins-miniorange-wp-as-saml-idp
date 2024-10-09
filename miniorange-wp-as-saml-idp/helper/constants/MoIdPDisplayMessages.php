<?php
/**
 * This file contains the `MoIdPDisplayMessages` class that is
 * responsible for displaying admin notices to users.
 *
 * @package miniorange-wp-as-saml-idp\helper\constants
 */

namespace IDP\Helper\Constants;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class handles the display of all the different
 * notices used in the plugin.
 */
class MoIdPDisplayMessages {

	/**
	 * Refers to the message to be displayed.
	 *
	 * @var string $message
	 */
	private $message;

	/**
	 * Refers to the type of the message.
	 * Can be `CUSTOM_MESSAGE`, `NOTICE`, `ERROR` or
	 * `SUCCESS`.
	 *
	 * @var string $type
	 */
	private $type;

	/**
	 * Parameterized constructor to create
	 * instance of the class. Also registers
	 * the hooks to display the admin notices.
	 *
	 * @param string $message Refers to the message to be displayed.
	 * @param string $type Refers to the type of the message.
	 */
	public function __construct( $message, $type ) {
		$this->message = $message;
		$this->type    = $type;
		add_action( 'admin_notices', array( $this, 'render' ) );
	}

	/**
	 * This function is responsible for rendering
	 * the admin notices, based on the message and
	 * the type of the message supplied.
	 *
	 * @return void
	 */
	public function render() {
		switch ( $this->type ) {
			case 'CUSTOM_MESSAGE':
				echo wp_kses_post( $this->message );
				break;
			case 'NOTICE':
				echo '<div  class="is-dismissible notice notice-warning mo-idp-note-endp mo-idp-margin-left"> <p>' . wp_kses_post( $this->message ) . '</p> </div>';
				break;
			case 'ERROR':
				echo '<div  class="notice notice-error is-dismissible mo-idp-note-error mo-idp-margin-left"> <p>' . wp_kses_post( $this->message ) . '</p> </div>';
				break;
			case 'SUCCESS':
				echo '<div  class="notice notice-success is-dismissible mo-idp-note-success mo-idp-margin-left"> <p>' . wp_kses_post( $this->message ) . '</p> </div>';
				break;
		}
	}
}
