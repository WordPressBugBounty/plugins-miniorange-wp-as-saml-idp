<?php
/**
 * This file is a controller, which defines all the
 * required variables to be used in the attr-settings
 * (Attribute / Role Mapping) view.
 *
 * @package miniorange-wp-as-saml-idp\controllers
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Handler\SPSettingsHandler;

/**
 * Global variable to access the `MoDbQueries`
 * object and call its required methods for
 * different database operations.
 *
 * @global \IDP\Helper\Database\MoDbQueries $moidp_db_queries
 */
global $moidp_db_queries;

$disabled                 = ! $registered || ! $verified ? '' : null;
$sp_list                  = $moidp_db_queries->get_sp_list();
$sp                       = empty( $sp_list ) ? '' : $sp_list[0];
$idp_change_name_id_nonce = SPSettingsHandler::get_instance()->nonce;

require MSI_DIR . 'views/attr-settings.php';
