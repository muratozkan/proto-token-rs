#[cfg(feature = "crypto_openssl")]
mod openssl;

#[cfg(feature = "crypto_openssl")]
pub use self::openssl::KeyPair;

#[cfg(feature = "crypto_openssl")]
pub use self::openssl::do_sign;

#[cfg(feature = "crypto_rustcrypto")]
mod rc;

#[cfg(feature = "crypto_rustcrypto")]
pub use self::rc::KeyPair;

#[cfg(feature = "crypto_rustcrypto")]
pub use self::rc::do_sign;
