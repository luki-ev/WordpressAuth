<?php
// Function based on https://github.com/WordPress/wordpress-develop/blob/6.8.1/src/wp-includes/pluggable.php#L2713


if ( ! function_exists( 'wp_check_password' ) ) :
	/**
	 * Checks a plaintext password against a hashed password.
	 *
	 * Note that this function may be used to check a value that is not a user password.
	 * A plugin may use this function to check a password of a different type, and there
	 * may not always be a user ID associated with the password.
	 *
	 * For integration with other applications, this function can be overwritten to
	 * instead use the other package password hashing algorithm.
	 *
	 * @since 2.5.0
	 * @since 6.8.0 Passwords in WordPress are now hashed with bcrypt by default. A
	 *              password that wasn't hashed with bcrypt will be checked with phpass.
	 *
	 * @global PasswordHash $wp_hasher phpass object. Used as a fallback for verifying
	 *                                 passwords that were hashed with phpass.
	 *
	 * @param string     $password Plaintext password.
	 * @param string     $hash     Hash of the password to check against.
	 */
	function wp_check_password(
		#[\SensitiveParameter]
		$password,
		$hash
	) {
		if ( strlen( $hash ) <= 32 ) {
			// Check the hash using md5 regardless of the current hashing mechanism.
			$check = hash_equals( $hash, md5( $password ) );
		} if ( strlen( $password ) > 4096 ) {
			// Passwords longer than 4096 characters are not supported.
			$check = false;
		} elseif ( str_starts_with( $hash, '$wp' ) ) {
			// Check the password using the current prefixed hash.
			$password_to_verify = base64_encode( hash_hmac( 'sha384', $password, 'wp-sha384', true ) );
			$check              = password_verify( $password_to_verify, substr( $hash, 3 ) );
		} elseif ( str_starts_with( $hash, '$P$' ) ) {
			// Check the password using phpass.
			require_once __DIR__ . '/class-phpass.php';
			$check = ( new PasswordHash( 8, true ) )->CheckPassword( $password, $hash );
		} else {
			// Check the password using compat support for any non-prefixed hash.
			$check = password_verify( $password, $hash );
		}

		return $check;
	}
endif;
