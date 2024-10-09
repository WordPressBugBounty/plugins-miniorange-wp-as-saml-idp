<?php
/**
 * This is the file for displaying the navigation
 * bar in the WordPress IDP plugin.
 *
 * @package miniorange-wp-as-saml-idp\views
 */

use IDP\Helper\Constants\MoIDPConstants;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo '
    <div class="mo-idp-visual-tour-overlay" id="mo-idp-overlay" hidden></div>
    <div class="wrap mo-idp-p-3 mo-idp-mr-0 mo-idp-mt-0 mo-idp-margin-left mo-idp-bg-white">';
			echo ' <div class="mo-idp-row">
                <div class="mo-idp-col-md-5">
                    <div>
                        <img class="mo-idp-contact-label" src="' . esc_url( MSI_LOGO_URL ) . '"> <span class="mo-idp-navbar-head">WP IDP Single Sign On</span>
                    </div>
              </div>';
			echo ' <div class="mo-idp-col-md-3">
                    <a class="mo-idp-upgrade-btn mo-idp-btn-free" href="' . esc_url( $license_url ) . '" target="_blank">Upgrade Now <span class="dashicons dashicons-external"></span></a>
                </div>';

			echo ' <div class="mo-idp-col-md-3 mo-idp-flex">
                    <div id="mo-idp-quicklinks" class="mo-idp-nav-dropdown">
                        <a class="mo-idp-dropdown-btn mo-idp-faq-btn ">Documentation / FAQs <span class="dashicons dashicons-arrow-down-alt2"></span></a>';
						echo ' <div class="mo-idp-dropdown-content">
                                <a href="' . esc_url( MoIDPConstants::FAQ_URL ) . '" target="_blank">FAQs</a>
                                <a href="' . esc_url( MoIDPConstants::SAML_DOC ) . '" target="_blank">SAML Documentation</a>
                                <a href="' . esc_url( MoIDPConstants::WSFED_DOC ) . '" target="_blank">WS-Fed Documentation</a>   
                            </div> ';
				echo ' </div>';
				echo ' <div id="mo-idp-quicklinks">
                        <a class="mo-idp-faq-btn mo-idp-btn-free" href="' . esc_url( $support_url ) . '">Stuck? Need Help?</a>
                    </div>
                </div>
            </div>
    </div>';

	check_is_curl_installed();

	echo '<div id="tab" class="mo-idp-tab mo-idp-flex nav-tab-wrapper"> ';
			echo '  <div class="mo-idp-header-tab">
                    <a  class="mo-idp-nav-tab 
                        ' . ( $active_tab === $idp_dashboard_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '" 
                        href="' . esc_url( $dashboard_url ) . '">
                        ' . esc_attr( $idp_dashboard_tab_details->tab_name ) . '
                    </a>
                </div>';
			echo ' <div class="mo-idp-header-tab">
                <a  class="mo-idp-nav-tab 
                    ' . ( $active_tab === $sp_settings_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '" 
                    href="' . esc_url( $idp_settings ) . '">
                    ' . esc_attr( $sp_settings_tab_details->tab_name ) . '
                </a>
            </div>';
			echo '<div class="mo-idp-header-tab">
                <a  class="mo-idp-nav-tab 
                    ' . ( $active_tab === $metadata_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '" 
                    href="' . esc_url( $sp_settings ) . '">
                    ' . esc_attr( $metadata_tab_details->tab_name ) . '
                </a>
            </div>';
			echo '<div class="mo-idp-header-tab">
                <a class="mo-idp-nav-tab 
                    ' . ( $active_tab === $attr_map_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '" 
                    href="' . esc_url( $attr_settings ) . '">
                    ' . esc_attr( $attr_map_tab_details->tab_name ) . '
                </a>
            </div>';
			echo '<div class="mo-idp-header-tab">
                <a  class="mo-idp-nav-tab 
                    ' . ( $active_tab === $settings_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '" 
                    href="' . esc_url( $login_settings ) . '">
                    ' . esc_attr( $settings_tab_details->tab_name ) . '
                </a>
            </div>';
			echo '<div class="mo-idp-header-tab">
                <a class="mo-idp-nav-tab
                    ' . ( $active_tab === $demo_request_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '"
                    href="' . esc_url( $demo_request_url ) . '">
                    ' . esc_attr( $demo_request_tab_details->tab_name ) . '
                </a>
            </div>';
			echo '<div class="mo-idp-header-tab">
                <a class="mo-idp-nav-tab
                    ' . ( $active_tab === $idp_addons_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '"
                    href="' . esc_url( $idp_addons_url ) . '">
                    ' . esc_attr( $idp_addons_tab_details->tab_name ) . '
                </a>
            </div>';
			echo '<div class="mo-idp-header-tab">
                <a class="mo-idp-nav-tab 
                    ' . ( $active_tab === $profile_tab_details->menu_slug ? 'mo-idp-nav-tab-active' : '' ) . '" 
                    href="' . esc_url( $register_url ) . '">
                    ' . esc_attr( $profile_tab_details->tab_name ) . '
                </a>
            </div>';
echo ' </div>';

if ( ! get_site_option( 'mo_idp_new_certs' ) ) {
	echo "
    <div class='mo-idp-bg mo-idp-divided-layout mo-idp-full mo-idp-margin-left'>
    <div style='display:block; width:91.4%; margin:auto; margin-top:32px; color:black; background-color:rgba(251, 232, 0, 0.15); 
    padding:0.938rem; border:solid 1px rgba(204, 204, 0, 0.36); font-size:large; line-height:normal;transform: translate(10px);'>
    <span style='color:red;'><span class='dashicons dashicons-warning'></span> <b>WARNING</b>:</span> The existing certificates have expired. Please update the certificates ASAP to secure your SSO.<br> Go to the <a href='admin.php?page=idp_metadata'><b>IDP Metadata</b></a> tab
    of the plugin to update your certificates. Make sure to update your Service Provider with the new certificate to ensure your SSO does not break.
    </div>
</div>";
}
