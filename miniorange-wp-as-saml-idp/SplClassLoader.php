<?php
/**
 * This file contains the `SplClassLoader` class that is responsible
 * for auto including all files being used in the plugin.
 *
 * @package miniorange-wp-as-saml-idp
 */

namespace IDP;

/**
 * This class is used to auto include all files being
 * used in the plugin. Removes the pain of individually
 * including all files.
 */
final class SplClassLoader {

	/**
	 * Refers to the extension of the file
	 * to load.
	 *
	 * @var string $file_extension
	 */
	private $file_extension = '.php';

	/**
	 * Refers to the namespace of the
	 * class / interface to load.
	 *
	 * @var string $namespace
	 */
	private $namespace;

	/**
	 * Refers to the base path of the file
	 * to load.
	 *
	 * @var string $include_path
	 */
	private $include_path;

	/**
	 * Refers to the namespace separator
	 * to use.
	 *
	 * @var string $namespace_separator
	 */
	private $namespace_separator = '\\';

	/**
	 * Parameterized constructor to create
	 * instance of the class.
	 *
	 * @param string $ns Refers to the namespace.
	 * @param string $include_path Refers to the base path of the file.
	 */
	public function __construct( $ns = null, $include_path = null ) {
		$this->namespace    = $ns;
		$this->include_path = $include_path;
	}

	/**
	 * Installs this class loader on the SPL autoload stack.
	 *
	 * @return void
	 */
	public function register() {
		spl_autoload_register( array( $this, 'load_class' ) );
	}

	/**
	 * Uninstalls this class loader from the SPL autoloader stack.
	 *
	 * @return void
	 */
	public function unregister() {
		spl_autoload_unregister( array( $this, 'load_class' ) );
	}

	/**
	 * Loads the given class or interface.
	 *
	 * @param string $class_name Name of the class to load.
	 * @return void
	 */
	public function load_class( $class_name ) {
		if ( null === $this->namespace
			|| substr( $class_name, 0, strlen( $this->namespace . $this->namespace_separator ) ) === $this->namespace . $this->namespace_separator ) {
			$file_name   = '';
			$namespace   = '';
			$last_ns_pos = strripos( $class_name, $this->namespace_separator );
			if ( false !== $last_ns_pos ) {
				$namespace  = strtolower( substr( $class_name, 0, $last_ns_pos ) );
				$class_name = substr( $class_name, $last_ns_pos + 1 );
				$file_name  = str_replace( $this->namespace_separator, DIRECTORY_SEPARATOR, $namespace ) . DIRECTORY_SEPARATOR;
			}
			$file_name .= str_replace( '_', DIRECTORY_SEPARATOR, $class_name ) . $this->file_extension;
			$file_name  = str_replace( 'idp', MSI_NAME, $file_name ); // replace the idp namespace with plugin folder name.
			// phpcs:ignore PEAR.Functions.FunctionCallSignature.SpaceBeforeOpenBracket, PEAR.Files.IncludingFile.BracketsNotRequired -- Required for getting the file names correctly.
			require ( null !== $this->include_path ? $this->include_path . DIRECTORY_SEPARATOR : '' ) . $file_name;
		}
	}
}
