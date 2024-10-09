<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the deactivation
 * feedback form view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

$handler              = \IDP\Handler\FeedbackHandler::get_instance();
$message              = 'We are sad to see you go :( 
                        Have you found a bug? Did you feel something was missing? 
                        Whatever it is, we\'d love to hear from you and get better.';
$nonce                = $handler->nonce;
$keep_settings_intact = get_site_option( 'idp_keep_settings_intact' );

require MSI_DIR . 'views/feedback.php';
