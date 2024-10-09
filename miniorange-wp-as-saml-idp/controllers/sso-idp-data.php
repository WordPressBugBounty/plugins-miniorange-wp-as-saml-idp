<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the idp-data (IDP
 * Metadata) view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\IDPSettingsHandler;
use IDP\Helper\Utilities\MoIDPUtility;
use IDP\Helper\Utilities\SAMLUtilities;

$metadata_url = home_url( '/?option=mo_idp_metadata' );
$metadata_dir = MSI_DIR . 'metadata.xml';

$protocol_type       = get_site_option( 'mo_idp_protocol' );
$plugins_url         = MSI_URL;
$blogs               = is_multisite() ? get_sites() : null;
$site_url            = is_null( $blogs ) ? site_url( '/' ) : get_site_url( $blogs[0]->blog_id, '/' );
$certificate_url     = MoIDPUtility::get_public_cert_url();
$new_certificate_url = MoIDPUtility::get_new_public_cert_url();
$certificate         = SAMLUtilities::desanitize_certificate( MoIDPUtility::get_public_cert() );
$request_uri         = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url( 'admin.php' );
$idp_settings        = add_query_arg( array( 'page' => $sp_settings_tab_details->menu_slug ), $request_uri );
$idp_entity_id       = get_site_option( 'mo_idp_entity_id' ) ? get_site_option( 'mo_idp_entity_id' ) : $plugins_url;
$nonce               = IDPSettingsHandler::get_instance()->nonce;

$wsfed_command = 'Set-MsolDomainAuthentication -Authentication Federated -DomainName ' .
						' <b>&lt;your_domain&gt;</b> ' .
						'-IssuerUri "' . $idp_entity_id .
						'" -LogOffUri "' . $site_url .
						'" -PassiveLogOnUri "' . $site_url .
						'" -SigningCertificate "' . $certificate .
						'" -PreferredAuthenticationProtocol WSFED';

$expired_cert = get_site_option( 'mo_idp_new_certs' ) ? get_site_option( 'mo_idp_new_certs' ) : false;

// Generate the metadata file if no file exists.
if ( ! file_exists( $metadata_dir ) || filesize( $metadata_dir ) === 0 ) {
	MoIDPUtility::create_metadata_file();
}

if ( ! get_site_option( 'mo_idp_new_certs' ) ) {
	MoIDPUtility::create_metadata_file();
} else {
	$use_new_cert = MoIDPUtility::check_cert_expiry();
	if ( true === $use_new_cert ) {
		update_site_option( 'mo_idp_new_certs', false );
	}
}

require MSI_DIR . 'views/idp-data.php';
