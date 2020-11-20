//! Verify apache's htpasswd file
//!
//! Supports MD5, BCrypt, SHA1, Unix crypt
//!
//! # Examples
//!
//! Verify MD5 hash
//!
//! ```
//!	let data = "user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
//! let htpasswd = htpasswd_verify::load(data);
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

static BCRYPT_ID: &'static str = "$2y$";
static SHA1_ID: &'static str = "{SHA}";

pub struct Htpasswd<'a>(pub HashMap<&'a str, Hash<'a>>);

#[derive(Debug)]
pub enum Hash<'a> {
	MD5(MD5Hash<'a>),
	BCrypt(&'a str),
	SHA1(&'a str),
	Crypt(&'a str),
}

#[derive(Debug)]
pub struct MD5Hash<'a> {
	pub salt: &'a str,
	pub hash: &'a str,
}

impl Htpasswd<'_> {
	pub fn check(&self, username: &str, password: &str) -> bool {
		let hash = &self.0.get(username);
		match hash {
			Some(Hash::MD5(hash)) => {
				md5::md5_apr1_encode(password, hash.salt).as_str() == hash.hash
			}
			Some(Hash::BCrypt(hash)) => bcrypt::verify(password, hash).unwrap(),
			Some(Hash::SHA1(hash)) => {
				let mut hasher = Sha1::new();
				hasher.input_str(password);
				let size = hasher.output_bytes();
				let mut buf = vec![0u8; size];
				hasher.result(&mut buf);
				base64::encode(&buf).as_str() == *hash
			}
			Some(Hash::Crypt(hash)) => pwhash::unix_crypt::verify(password, hash),
			None => false,
		}
	}
}

pub fn load(bytes: &str) -> Htpasswd {
	let lines = bytes.split('\n');
	let hashes = lines
		.filter_map(parse_hash_entry)
		.collect::<HashMap<&str, Hash>>();
	Htpasswd(hashes)
}

fn parse_hash_entry(entry: &str) -> Option<(&str, Hash)> {
	let semicolon = match entry.find(':') {
		Some(idx) => idx,
		None => return None,
	};
	let username = &entry[..semicolon];

	let hash_id = &entry[(semicolon + 1)..];
	if hash_id.starts_with(md5::APR1_ID) {
		Some((
			username,
			Hash::MD5(MD5Hash {
				salt: &entry[(semicolon + 1 + APR1_ID.len())..(semicolon + 1 + APR1_ID.len() + 8)],
				hash: &entry[(semicolon + 1 + APR1_ID.len() + 8 + 1)..],
			}),
		))
	} else if hash_id.starts_with(BCRYPT_ID) {
		Some((username, Hash::BCrypt(&entry[(semicolon + 1)..])))
	} else if hash_id.starts_with("{SHA}") {
		Some((
			username,
			Hash::SHA1(&entry[(semicolon + 1 + SHA1_ID.len())..]),
		))
	} else {
		//Ignore plaintext, assume crypt

		Some((username, Hash::Crypt(&entry[(semicolon + 1)..])))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	static DATA: &'static str = "user2:$apr1$7/CTEZag$omWmIgXPJYoxB3joyuq4S/
user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00
bcrypt_test:$2y$05$nC6nErr9XZJuMJ57WyCob.EuZEjylDt2KaHfbfOtyb.EgL1I2jCVa
sha1_test:{SHA}W6ph5Mm5Pz8GgiULbPgzG37mj9g=
crypt_test:bGVh02xkuGli2";

	#[test]
	fn unix_crypt_verify_htpasswd() {
		let htpasswd = load(DATA);
		assert_eq!(htpasswd.check("crypt_test", "password"), true);
	}

	#[test]
	fn sha1_verify_htpasswd() {
		let htpasswd = load(DATA);
		assert_eq!(htpasswd.check("sha1_test", "password"), true);
	}

	#[test]
	fn bcrypt_verify_htpasswd() {
		let htpasswd = load(DATA);
		assert_eq!(htpasswd.check("bcrypt_test", "password"), true);
	}

	#[test]
	fn md5_verify_htpasswd() {
		let htpasswd = load(DATA);
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
		let htpasswd = load(DATA);
		assert_eq!(htpasswd.check("user_does_not_exist", "password"), false);
	}
}
