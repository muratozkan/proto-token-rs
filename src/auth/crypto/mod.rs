#[cfg(feature = "openssl")]
mod openssl;

#[cfg(feature = "openssl")]
pub use self::openssl::KeyPair;

#[cfg(feature = "openssl")]
pub use self::openssl::do_sign;

#[cfg(feature = "wasm")]
mod rc;

#[cfg(feature = "wasm")]
pub use self::rc::KeyPair;

#[cfg(feature = "wasm")]
pub use self::rc::do_sign;
