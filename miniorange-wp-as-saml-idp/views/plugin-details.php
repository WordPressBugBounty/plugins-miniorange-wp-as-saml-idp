<?php
/**
 * This is the file for displaying the view under
 * the Dashboard tab.
 *
 * @package miniorange-wp-as-saml-idp\views
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

echo '
<div class="mo-idp-bg mo-idp-divided-layout mo-idp-full mo-idp-margin-left">
    <div class="mo-idp-flex mo-idp-home mo-idp-p-3">
        <div class="mo-idp-home-row1">';
			$count = 0;
			$class = '';
			$start = '';
foreach ( $tab_details as $idp_tabs ) {
	if ( 4 === $count ) {
		break;
	}
	$request_uri = ! empty( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : admin_url( 'admin.php' );
	$tab_link    = add_query_arg( array( 'page' => $idp_tabs->menu_slug ), $request_uri );
	if ( 0 === $count ) {
		$class              = 'mo-idp-start-here-card';
		$function1          = 'mo_idp_dashboard_start()';
		$head               = 'Start here';
		$idp_tabs->tab_name = 'Configure Service Provider';
		$img_bg             = 'mo-idp-img-bg';
		$href               = 'mo-idp-home-card-link-href';
	} else {
		$class     = 'mo-idp-home-card';
		$function1 = 'mo_idp_dashboard_rest()';
		$head      = 'Go there';
		$start     = '';
		$img_bg    = '';
		$href      = 'mo-idp-home-card-link-href-rest';
	}
	echo '
                    <div class="' . esc_attr( $class ) . '" onclick="location.href=\'' . esc_url( $tab_link ) . '\'">
                        <div class="mo-idp-home-flex">
                            <div class="' . esc_attr( $img_bg ) . '">
                                <img class="mo-idp-img-size"  src="';
						echo esc_url( MSI_URL ) . 'includes/images/' . esc_attr( $idp_tabs->menu_slug ) . '.png'; echo '" />
                            </div>
                            <span class="mo-idp-home-card-head addon-table-list-status">' . esc_attr( $idp_tabs->tab_name ) . '</span>
                        </div>
                        <p class="mo-idp-home-card-desc addon-table-list-name" >' . esc_attr( $idp_tabs->description ) . '</p>
                        <a class="' . esc_attr( $href ) . '" href="' . esc_url( $tab_link ) . '"> ' . esc_attr( $head ) . ' &#8594 </a>
                    </div>
                ';
	++$count;
}
	echo '            
    </div>

    <div class="mo-idp-home-advt mo-idp-mt-5" >';
		echo '';
		echo '<div class="mo-idp-home-advt-integration">
            <h2 style="color:#01316D;margin-bottom:2rem;" class="mo-idp-text-center mo-idp-home-card-link mo-idp-mt-0">Supported Integrations</h2>';
			$count = 0;
foreach ( $integrations_details as $integration_name => $integration_image ) {
	if ( 0 === $count % 3 ) {
		echo '
                    <div class="mo-idp-flex mo-idp-flex-integration">
                        <div class="mo-idp-logo-saml-cstm">
                        <a href="' . esc_url( $idp_addons_url ) . '" class="mo-idp-upload-data-anchor">
                            <img class="mo-idp-dashboard-logo" src="' . esc_url( $integration_image ) . '"/>
                            <p class="mo-idp-home-card-desc mo-idp-text-center" id="idp_entity_id" >' . esc_attr( $integration_name ) . '</p>
                        </a>
                        </div>
                    
                    ';
	} else {
		echo '    
                    <div class="mo-idp-logo-saml-cstm">
                        <a href="' . esc_url( $idp_addons_url ) . '" class="mo-idp-upload-data-anchor">
                            <img class="mo-idp-dashboard-logo" src="' . esc_url( $integration_image ) . '"/>
                            <p class="mo-idp-home-card-desc mo-idp-text-center" id="idp_entity_id">' . esc_attr( $integration_name ) . '</p>
                            </a>
                        </div>
                    
                    ';
	}
	++$count;
	if ( 0 === $count % 3 ) {
		echo '</div>';
	}
}

echo '  
        </div>        
    </div>
</div>
    
</div>
';
