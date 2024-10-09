<?php
/**
 * This file contains the `SPSettingsUtility` class that provides
 * helper functions used to process the Service Provider settings.
 *
 * @package miniorange-wp-as-saml-idp\handler
 */

namespace IDP\Handler;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Exception\InvalidEncryptionCertException;
use IDP\Exception\IssuerValueAlreadyInUseException;
use IDP\Exception\NoServiceProviderConfiguredException;
use IDP\Exception\SPNameAlreadyInUseException;
use IDP\Helper\Database\MoDbQueries;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This class extends the `BaseHandler` class and
 * provides helper functions used to process the
 * Service Provider settings.
 */
class SPSettingsUtility extends BaseHandler {

	/**
	 * Check if the user has configured the Service Provider.
	 * This makes sure if SP related operations are being
	 * performed on valid SPs.
	 *
	 * @param array       $sp Refers to the SP id in question or the array which might have the id.
	 * @param boolean     $is_array Flag to denote if the `$sp` is an array.
	 * @param string|null $key Refers to the key which will have the id of the SP.
	 * @throws NoServiceProviderConfiguredException Exception when the ID of the Service Provider is blank.
	 */
	public function check_if_valid_service_provider( $sp, $is_array = false, $key = null ) {
		if ( ( $is_array && empty( $sp[ $key ] ) ) || MoIDPUtility::is_blank( $sp ) ) {
			throw new NoServiceProviderConfiguredException();
		}
	}

	/**
	 * Check if the Issuer value provided by the admin for a
	 * Service Provider is already in use by some other SP. This
	 * makes sure that no two Service Providers have the same
	 * Issuer value.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param string $issuer Refers to the Issuer value admin is trying to update.
	 * @param string $id Refers to the id of the SP in the database for whom we are updating the Issuer value.
	 * @param string $name Refers to the SP Name value admin is trying to update.
	 * @throws IssuerValueAlreadyInUseException Exception when there already exists a configured Service Provider with the similar Issuer value.
	 */
	public function check_issuer_already_in_use( $issuer, $id, $name ) {
		global $moidp_db_queries;
		$sp = $moidp_db_queries->get_sp_from_issuer( $issuer );

		if ( ! MoIDPUtility::is_blank( $sp ) && ! MoIDPUtility::is_blank( $id )
			&& $sp->id !== $id ) {
			throw new IssuerValueAlreadyInUseException( $sp );
		}

		if ( ! MoIDPUtility::is_blank( $sp ) && ! MoIDPUtility::is_blank( $name )
			&& $name !== $sp->mo_idp_sp_name ) {
			throw new IssuerValueAlreadyInUseException( $sp );
		}
	}

	/**
	 * Check if the SP name provided by the admin for a
	 * Service Provider is already in use by other SP. This
	 * makes sure no two Service Provider have the same Name.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @param string      $name Refers to the Name value provided by the admin.
	 * @param string|null $id Refers to the id of the SP in the database for whom we are updating the Name.
	 * @throws SPNameAlreadyInUseException Exception when the Service Provider name is similar to the existing Service Provider that is configured.
	 */
	public function check_name_already_in_use( $name, $id = null ) {
		global $moidp_db_queries;
		$sp = $moidp_db_queries->get_sp_from_name( $name );

		if ( ! MoIDPUtility::is_blank( $sp ) && ! MoIDPUtility::is_blank( $id )
			&& $sp->id !== $id ) {
			throw new SPNameAlreadyInUseException( $sp );
		}

		if ( ! MoIDPUtility::is_blank( $sp ) && MoIDPUtility::is_blank( $id ) ) {
			throw new SPNameAlreadyInUseException( $sp );
		}
	}

	/**
	 * Check if Admin has provided a valid Cert file for encrypted
	 * assertion from the SP. This makes sure Admin provides a valid cert.
	 *
	 * @param string $option Refers to the encrypted assertion checkbox value.
	 * @param string $cert Refers to the cert value provided by admin.
	 * @throws InvalidEncryptionCertException Exception when invalid certificate is provided.
	 */
	public function check_if_valid_encryption_cert_provided( $option, $cert ) {
		if ( ! MoIDPUtility::is_blank( $option ) && MoIDPUtility::is_blank( $cert ) ) {
			throw new InvalidEncryptionCertException();
		}
	}
}
