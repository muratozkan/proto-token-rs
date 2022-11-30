#[cfg(feature = "crypto_openssl")]
mod openssl;

#[cfg(feature = "crypto_openssl")]
pub use self::openssl::KeyPair;

#[cfg(feature = "crypto_openssl")]
pub use self::openssl::do_sign;
