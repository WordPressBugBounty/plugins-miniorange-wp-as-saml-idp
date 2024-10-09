<?php
/**
 * This file contains the `MoIDP` class that is the
 * main class of the plugin.
 *
 * @package miniorange-wp-as-saml-idp
 */

namespace IDP;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

use IDP\Actions\RegistrationActions;
use IDP\Actions\SettingsActions;
use IDP\Actions\SSOActions;
use IDP\Helper\Constants\MoIdPDisplayMessages;
use IDP\Helper\Database\MoDbQueries;
use IDP\Helper\Traits\Instance;
use IDP\Helper\Utilities\MenuItems;
use IDP\Helper\Utilities\MoIDPUtility;

/**
 * This is the main class for the WordPress IDP
 * plugin.
 */
final class MoIDP {

	use Instance;

	/**
	 * Private constructor to avoid direct object creation.
	 */
	private function __construct() {
		$this->initialize_global_variables();
		$this->initialize_actions();
		$this->add_hooks();
	}

	/**
	 * This function is used to initialize the global variables
	 * which will be used across the plugin.
	 *
	 * @return void
	 */
	private function initialize_global_variables() {
		global $moidp_db_queries;
		$moidp_db_queries = MoDbQueries::get_instance();
	}

	/**
	 * This function is used to register various hooks and their
	 * respective callable functions required by the plugin.
	 * This includes hooks to add the plugin menu item, enqueue
	 * scripts, etc.
	 *
	 * @return void
	 */
	private function add_hooks() {
		add_action( 'mo_idp_show_message', array( $this, 'mo_show_message' ), 1, 2 );
		add_action( 'admin_menu', array( $this, 'mo_idp_menu' ) );
		add_action( 'admin_init', array( $this, 'check_tables_and_run_queries_wrapper' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'mo_idp_plugin_settings_style' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'mo_idp_plugin_settings_script' ) );
		add_action( 'enqueue_scripts', array( $this, 'mo_idp_plugin_settings_style' ) );
		add_action( 'enqueue_scripts', array( $this, 'mo_idp_plugin_settings_script' ) );
		add_action( 'admin_footer', array( $this, 'feedback_request' ) );
		add_filter( 'plugin_action_links_' . MSI_PLUGIN_NAME, array( $this, 'mo_idp_plugin_anchor_links' ) );
		register_activation_hook( MSI_PLUGIN_NAME, array( $this, 'mo_plugin_activate' ) );
	}

	/**
	 * Adds a wrapper function on top of check_tables_and_run_queries
	 * to avoid unnecessary initialization of $moidp_db_queries while
	 * adding action on hook.
	 *
	 * @return void
	 */
	public function check_tables_and_run_queries_wrapper() {
		global $moidp_db_queries;
		$moidp_db_queries->check_tables_and_run_queries();
	}


	/**
	 * This function is used to initialize the Action
	 * classes responsible for processing the forms
	 * submitted by user, and the SSO operations.
	 *
	 * @return void
	 */
	private function initialize_actions() {
		SettingsActions::get_instance();
		RegistrationActions::get_instance();
		SSOActions::get_instance();
	}

	/**
	 * This function is the callable function for the
	 * `admin_menu` hook, and generates the menu item
	 * for the plugin.
	 *
	 * @return void
	 */
	public function mo_idp_menu() {
		new MenuItems( $this );
	}

	/**
	 * This is the callback function for the menu item
	 * and the submenu items of the plugin.
	 *
	 * @return void
	 */
	public function mo_sp_settings() {
		include 'controllers/sso-main-controller.php';
	}

	/**
	 * This function is the callable function for the
	 * `admin_enqueue_scripts` and the `enqueue_scripts`
	 * hooks, and loads the CSS files used by the plugin.
	 *
	 * @return void
	 */
	public function mo_idp_plugin_settings_style() {
		wp_enqueue_style( 'mo_idp_admin_settings_style', MSI_CSS_URL, array(), MSI_VERSION );
	}

	/**
	 * This function is the callable function for the
	 * `admin_enqueue_scripts` and the `enqueue_scripts`
	 * hooks, and loads the JS files used by the plugin.
	 *
	 * @return void
	 */
	public function mo_idp_plugin_settings_script() {
		wp_enqueue_script( 'mo_idp_admin_settings_script', MSI_JS_URL, array( 'jquery' ), MSI_VERSION, true );
	}

	/**
	 * This function is the callable function for the
	 * `register_activation_hook` hook, and runs when
	 * the plugin is activated. It checks whether the
	 * plugin is installed for the first time, and
	 * accordingly generates the tables required to
	 * store the configuration.
	 *
	 * @global MoDbQueries $moidp_db_queries Global variable to access the `MoDbQueries` object and call its required methods for different database operations.
	 * @return void
	 */
	public function mo_plugin_activate() {
		global $moidp_db_queries;
		$moidp_db_queries->check_tables_and_run_queries();
		if ( ! get_site_option( 'mo_idp_new_certs' ) ) {
			MoIDPUtility::use_new_certs();
		}
		$metadata_dir = MSI_DIR . 'metadata.xml';
		if ( file_exists( $metadata_dir ) && filesize( $metadata_dir ) > 0 ) {
			wp_delete_file( $metadata_dir );
			MoIDPUtility::create_metadata_file();
		}
		if ( get_site_option( 'idp_keep_settings_intact', null ) === null ) {
			update_site_option( 'idp_keep_settings_intact', true );
		}
	}

	/**
	 * This function is the callable function for the
	 * `mo_idp_show_message` hook, and generates the
	 * success / error message to be displayed.
	 *
	 * @param string $content Body of the message to be displayed.
	 * @param string $type Type of the message - SUCCESS / ERROR / NOTICE / CUSTOM_MESSAGE.
	 * @return void
	 */
	public function mo_show_message( $content, $type ) {
		new MoIdPDisplayMessages( $content, $type );
	}

	/**
	 * This function is the callable function for the
	 * `admin_footer` hook, and generates the deactivation
	 * feedback form to be displayed.
	 *
	 * @return void
	 */
	public function feedback_request() {
		include MSI_DIR . 'controllers/feedback.php';
	}

	/**
	 * This function is the callable function for the
	 * `plugin_action_links_` hook, and adds the links
	 * to the plugins settings and licensing plans to
	 * the plugin anchor links.
	 *
	 * @param array $links Refers to the default plugin anchor links.
	 * @return array
	 */
	public function mo_idp_plugin_anchor_links( $links ) {
		if ( isset( $links['deactivate'] ) ) {
			$arr  = array();
			$data = array(
				'Settings'         => 'idp_configure_idp',
				'Purchase License' => 'idp_upgrade_settings',
			);

			foreach ( $data as $key => $val ) {
				$url         = esc_url(
					add_query_arg(
						'page',
						$val,
						get_admin_url() . 'admin.php?'
					)
				);
				$anchor_link = "<a href='$url'>" . esc_html( $key ) . '</a>';
				array_push( $arr, $anchor_link );
			}
			$links = $arr + $links;
		}
		return $links;
	}
}
