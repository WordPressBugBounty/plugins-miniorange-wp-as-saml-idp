<?php
/**
 * This file contains the `PluginPageDetails` class that is used
 * to describe the plugin pages.
 *
 * @package miniorange-wp-as-saml-idp\helper\utilities
 */

namespace IDP\Helper\Utilities;

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * This class describes the plugin pages.
 */
class PluginPageDetails {

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param string $page_title Refers to the page title.
	 * @param string $menu_slug Refers to the menu slug.
	 * @param string $menu_title Refers to the menu title.
	 * @param string $tab_name Refers to the tab name.
	 * @param string $description Refers to the tab description.
	 */
	public function __construct( $page_title, $menu_slug, $menu_title, $tab_name, $description ) {
		$this->page_title  = $page_title;
		$this->menu_slug   = $menu_slug;
		$this->menu_title  = $menu_title;
		$this->tab_name    = $tab_name;
		$this->description = $description;
	}

	/**
	 * The page title.
	 *
	 * @var string  $page_title
	 */
	public $page_title;

	/**
	 * The menuSlug.
	 *
	 * @var string  $menu_slug
	 */
	public $menu_slug;


	/**
	 * The menu title.
	 *
	 * @var string  $menu_title
	 */
	public $menu_title;


	/**
	 * Tab Name.
	 *
	 * @var String $tab_name
	 */
	public $tab_name;

	/**
	 * Tab Description.
	 *
	 * @var string $description
	 */
	public $description;
}
