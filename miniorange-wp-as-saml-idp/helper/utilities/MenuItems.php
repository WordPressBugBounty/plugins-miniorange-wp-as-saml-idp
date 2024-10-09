<?php
/**
 * This file contains the `MenuItems` class that is responsible
 * for adding menu items in the WordPress dashboard.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class simply adds menu items for the plugin
 * in the WordPress dashboard.
 */
final class MenuItems {

	/**
	 * The URL for the plugin icon to be shown in the dashboard.
	 *
	 * @var string
	 */
	private $callback;

	/**
	 * The slug for the main menu.
	 *
	 * @var string
	 */
	private $menu_logo;

	/**
	 * Array of PluginPageDetails Object detailing
	 * all the page menu options.
	 *
	 * @var array $tab_details
	 */
	private $tab_details;

	/**
	 * The Parent Slug of the plugin.
	 *
	 * @var string
	 */
	private $parent_slug;

	/**
	 * MenuItems constructor.
	 *
	 * @param string $base_class Refers to the base class.
	 */
	public function __construct( $base_class ) {
		$this->callback    = array( $base_class, 'mo_sp_settings' );
		$this->menu_logo   = MSI_ICON;
		$tab_details       = TabDetails::get_instance();
		$this->tab_details = $tab_details->tab_details;
		$this->parent_slug = $tab_details->parent_slug;
		$this->add_main_menu();
		$this->add_sub_menus();
	}

	/**
	 * Function adds the menu item for the plugin
	 * in the WordPress dashboard.
	 *
	 * @return void
	 */
	private function add_main_menu() {
		add_menu_page(
			'SAML IDP',
			'WordPress IDP',
			'manage_options',
			$this->parent_slug,
			$this->callback,
			$this->menu_logo
		);
	}

	/**
	 * Function adds the submenu items for different
	 * tabs of the plugin in the WordPress dashboard.
	 *
	 * @return void
	 */
	private function add_sub_menus() {
		foreach ( $this->tab_details as $tab_detail ) {
			if ( 'Dashboard' !== $tab_detail->menu_title ) {
				add_submenu_page(
					$this->parent_slug,
					$tab_detail->page_title,
					$tab_detail->menu_title,
					'manage_options',
					$tab_detail->menu_slug,
					$this->callback
				);
			}
		}
	}
}
