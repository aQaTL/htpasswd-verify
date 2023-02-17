//! Verify apache's htpasswd file
//!
//! Supports MD5, BCrypt, SHA1, Unix crypt
//!
//! # Examples
//!
//! Verify MD5 hash
//!
//! ```
//! let data = "user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
//! let htpasswd = htpasswd_verify::Htpasswd::new(data);
//! assert!(htpasswd.check("user", "password"));
//! ```
//!
//! It also allows to encrypt with md5 (not the actual md5, but the apache specific md5 that
//! htpasswd file uses)
//!
//! ```
//! use htpasswd_verify::md5::{md5_apr1_encode, format_hash};
//!
//! let password = "password";
//! let hash = md5_apr1_encode(password, "RandSalt");
//! let hash = format_hash(&hash, "RandSalt");
//! assert_eq!(hash, "$apr1$RandSalt$PgCXHRrkpSt4cbyC2C6bm/");
//! ```

use crate::md5::APR1_ID;
use crypto::{digest::Digest, sha1::Sha1};
use std::collections::HashMap;

pub mod md5;

static BCRYPT_ID: &str = "$2y$";
static SHA1_ID: &str = "{SHA}";

pub struct Htpasswd(HashMap<String, Hash>);

#[derive(Debug, Eq, PartialEq)]
pub enum Hash {
	MD5(MD5Hash),
	BCrypt(String),
	SHA1(String),
	Crypt(String),
}

#[derive(Debug, Eq, PartialEq)]
pub struct MD5Hash {
	pub salt: String,
	pub hash: String,
}

impl Htpasswd {
	pub fn new(bytes: impl AsRef<str>) -> Htpasswd {
		let lines = bytes.as_ref().split('\n');
		let hashes = lines
			.filter_map(parse_hash_entry)
			.collect::<HashMap<String, Hash>>();
		Htpasswd(hashes)
	}

	pub fn check<S: AsRef<str>>(&self, username: S, password: S) -> bool {
		self.0
			.get(username.as_ref())
			.map(|hash| hash.check(password))
			.unwrap_or_default()
	}
}

impl Hash {
	pub fn check<S: AsRef<str>>(&self, password: S) -> bool {
		let password = password.as_ref();
		match self {
			Hash::MD5(hash) => md5::md5_apr1_encode(password, &hash.salt).as_str() == hash.hash,
			Hash::BCrypt(hash) => bcrypt::verify(password, hash).unwrap(),
			Hash::SHA1(hash) => {
				let mut hasher = Sha1::new();
				hasher.input_str(password);
				let size = hasher.output_bytes();
				let mut buf = vec![0u8; size];
				hasher.result(&mut buf);
				base64::encode(&buf).as_str() == *hash
			}
			Hash::Crypt(hash) => pwhash::unix_crypt::verify(password, hash),
		}
	}

	/// Parses the hash part of the htpasswd entry.
	///
	/// Example:
	///
	/// ```
	/// use htpasswd_verify::{Hash, MD5Hash};
	///
	/// let entry = "user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
	/// let semicolon = entry.find(':').unwrap();
	/// let username = &entry[..semicolon];
	///
	/// let hash_id = &entry[(semicolon + 1)..];
	/// assert_eq!(hash_id, "$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00");
	/// let hash = Hash::parse(hash_id);
	/// assert_eq!(
	///     hash,
	///     Hash::MD5(MD5Hash {
	///         salt: "lZL6V/ci".to_string(),
	///         hash: "eIMz/iKDkbtys/uU7LEK00".to_string(),
	///     },
	/// ));
	/// ```
	pub fn parse(hash: &str) -> Self {
		if hash.starts_with(APR1_ID) {
			Hash::MD5(MD5Hash {
				salt: hash[(APR1_ID.len())..(APR1_ID.len() + 8)].to_string(),
				hash: hash[(APR1_ID.len() + 8 + 1)..].to_string(),
			})
		} else if hash.starts_with(BCRYPT_ID) {
			Hash::BCrypt(hash.to_string())
		} else if hash.starts_with("{SHA}") {
			Hash::SHA1(hash[SHA1_ID.len()..].to_string())
		} else {
			//Ignore plaintext, assume crypt
			Hash::Crypt(hash.to_string())
		}
	}
}

fn parse_hash_entry(entry: &str) -> Option<(String, Hash)> {
	let separator = entry.find(':')?;
	let username = &entry[..separator];
	let hash_id = &entry[(separator + 1)..];
	Some((username.to_string(), Hash::parse(hash_id)))
}

#[cfg(test)]
mod tests {
	use super::*;

	static DATA: &str = "user2:$apr1$7/CTEZag$omWmIgXPJYoxB3joyuq4S/
user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00
bcrypt_test:$2y$05$nC6nErr9XZJuMJ57WyCob.EuZEjylDt2KaHfbfOtyb.EgL1I2jCVa
sha1_test:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
crypt_test:bGVh02xkuGli2";

	#[test]
	fn unix_crypt_verify_htpasswd() {
		let htpasswd = Htpasswd::new(DATA);
		assert_eq!(htpasswd.check("crypt_test", "password"), true);
	}

	#[test]
	fn sha1_verify_htpasswd() {
		let htpasswd = Htpasswd::new(DATA);
		assert_eq!(htpasswd.check("sha1_test", "password"), true);
	}

	#[test]
	fn bcrypt_verify_htpasswd() {
		let htpasswd = Htpasswd::new(DATA);
		assert_eq!(htpasswd.check("bcrypt_test", "password"), true);
	}

	#[test]
	fn md5_verify_htpasswd() {
		let htpasswd = Htpasswd::new(DATA);
		assert_eq!(htpasswd.check("user", "password"), true);
		assert_eq!(htpasswd.check("user", "passwort"), false);
		assert_eq!(htpasswd.check("user2", "zaq1@WSX"), true);
		assert_eq!(htpasswd.check("user2", "ZAQ1@WSX"), false);
	}

	#[test]
	fn md5_apr1() {
		assert_eq!(
			md5::format_hash(
				md5::md5_apr1_encode("password", "xxxxxxxx").as_str(),
				"xxxxxxxx",
			),
			"$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0".to_string()
		);
	}

	#[test]
	fn apr1() {
		assert!(
			md5::verify_apr1_hash("$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0", "password").unwrap()
		);
	}

	#[test]
	fn user_not_found() {
		let htpasswd = Htpasswd::new(DATA);
		assert_eq!(htpasswd.check("user_does_not_exist", "password"), false);
	}
}
