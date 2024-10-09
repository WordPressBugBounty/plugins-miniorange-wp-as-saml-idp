<?php
/**
 * This file contains the common functions used
 * in different views.
 *
 * @package miniorange-wp-as-saml-idp\views
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Helper\Database\MoDbQueries;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * Generates a select box for the NameID .
 * It returns the select box with user_meta and user_info keys.
 *
 * @param boolean                $disabled References if the select box should be disabled.
 * @param array|object|null|void $sp References the current chosen SP.
 */
function get_nameid_select_box( $disabled, $sp ) {
	$user_info = get_user_info_list();
	$nameid    = ! empty( $sp->mo_idp_nameid_attr ) && 'emailAddress' !== $sp->mo_idp_nameid_attr ? $sp->mo_idp_nameid_attr : 'user_email';
	if ( isset( $sp ) && ! empty( $sp ) ) {
		echo '<select ' . esc_attr( $disabled ) . " style='width:60%'  name='idp_nameid_attr'";
		echo "><option value=''>Select Data to be sent in the NameID</option>";
		foreach ( $user_info as $key => $value ) {
			echo "<option value='" . esc_attr( $key ) . "'";
			if ( ! is_null( $sp ) ) {
				echo $nameid === $key ? 'selected' : '';
			}
			echo '>' . esc_attr( $key ) . '</option>';
		}
		echo '</select>';
	} else {
		echo '<div class="mo-idp-note">Please Configure a Service Provider</div>';
	}
}


/**
 * Generate an error if the user doesn't
 * have write access on the website.
 *
 * @param boolean $registered References whether the user is a registered customer.
 * @param boolean $verified References whether the user is a verified customer.
 */
function able_to_write_files( $registered, $verified ) {
	if ( $registered && $verified && ! MoIDPUtility::is_admin() ) {
		echo "<div style='display:block;margin-top:10px;color:red;
                          background-color:rgba(251, 232, 0, 0.15);
                          padding:5px;border:solid 1px rgba(255, 0, 9, 0.36);'>
                You don't have write access on the website. Please contact administrator for generation of certificates and metadata file. 
			</div>";
	}
}

/**
 * This function is used to get the usermeta values to be shown in the
 * Attribute/Role Mapping Tab. It can be modified to show other custom
 * attributes as well.
 *
 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
 * @return array
 */
function get_user_info_list() {
	global $moidp_db_queries;
	$current_user = wp_get_current_user();
	$user_attr    = array();
	$user_info    = $moidp_db_queries->get_distinct_meta_attributes();
	foreach ( $user_info as $key => $value ) {
		$user_attr[ $value->meta_key ] = $value->meta_key; // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- Retrieving distinct meta_keys from the usermeta table.
	}
	foreach ( $current_user->data as $key => $value ) {
		$user_attr[ $key ] = $key;
	}

	// this was added to increase customization option. Users will be able to
	// add their own user related info attributes that they want to show.
	$user_attr = apply_filters( 'user_info_attr_list', $user_attr );
	return $user_attr;
}

/**
 * Creates an error message on the plugin settings page to indicate
 * the user that the cURL is not installed or enabled on their site.
 */
function check_is_curl_installed() {
	if ( ! MoIDPUtility::is_curl_installed() ) {
		echo '<div id="help_curl_warning_title" class="mo_wpum_title_panel">
			    <p>
			        <font color="#FF0000">
			            Warning: PHP cURL extension is not installed or disabled. 
			            <span style="color:blue">Click here</span> for instructions to enable it.
                    </font>
                </p>
		</div>
		<div hidden="" id="help_curl_warning_desc" class="mo_wpum_help_desc">
			<ul>
				<li>Step 1:&nbsp;&nbsp;&nbsp;&nbsp;Open php.ini file located under php installation folder.</li>
				<li>Step 2:&nbsp;&nbsp;&nbsp;&nbsp;Search for <b>extension=php_curl.dll</b> </li>
				<li>Step 3:&nbsp;&nbsp;&nbsp;&nbsp;Uncomment it by removing the semi-colon(<b>;</b>) in front of it.</li>
				<li>Step 4:&nbsp;&nbsp;&nbsp;&nbsp;Restart the Apache Server.</li>
			</ul>
			For any further queries, please <a href="mailto:wpidpsupport@xecurify.com">contact us</a>.								
		</div>';
	}
}

/**
 * Generates a message to indicate that the user
 * needs to register himself on miniOrange.
 *
 * @param boolean $registered References whether the user is a registered customer.
 */
function is_customer_registered_idp( $registered ) {
	if ( ! $registered ) {
		echo '<div style="display:block;font-size: 0.8rem;width: 91.6%;margin-left: 3.4rem;font-weight: 600;" class="mo-idp-note-endp">
		      You have to';
			echo ' <a href="' . esc_url( mo_idp_get_registration_url() ) . '">';
			echo '    Register or Login with miniOrange</a> in order to be able to Upgrade.
		      </div>';
	}
}

/**
 * Renders the UI for the user to navigate through different
 * SSO protocols.
 *
 * @param array|object|null|void $sp References the current chosen SP.
 * @param string                 $protocol_inuse Selected protocol.
 */
function show_protocol_options( $sp, $protocol_inuse ) {
	if ( ! MoIDPUtility::is_blank( $sp ) ) {
		return;
	}
	echo '
		<div style="margin-bottom:-1.188rem;">
		<!--	<h3 class="mo-idp-text-center" style="font-size: 1.188rem;">Choose Your Protocol</h3>-->
			<div class="mo-idp--center" id="mo-idp-protocolDiv" style="width:99.6%;">
				<div class="protocol_choice_saml mo-idp--center ' .
					( 'SAML' === $protocol_inuse ? 'selected' : '' ) . '" data-toggle="add_sp">
				    SAML
                </div>
				<div class="protocol_choice_wsfed mo-idp--center ' .
					( 'WSFED' === $protocol_inuse ? 'selected' : '' ) . '" data-toggle="add_wsfed_app">
				    WS-FED
                </div>
				<div class="protocol_choice_jwt mo-idp--center ' .
					( 'JWT' === $protocol_inuse ? 'selected' : '' ) . '" data-toggle="add_jwt_app">
				    JWT
                </div>
			</div>
			<br/>
			<div hidden class="mo-idp-loader mo-idp-note">
			    <img src="' . esc_url( MSI_LOADER ) . '">
            </div>
		</div>';
}
