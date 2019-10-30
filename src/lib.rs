use crate::md5::APR1_ID;
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::ptr::hash;

mod md5;

pub struct Htpasswd<'a>(HashMap<&'a str, Hash<'a>>);

#[derive(Debug)]
pub enum Hash<'a> {
	MD5(MD5Hash<'a>),
}

#[derive(Debug)]
pub struct MD5Hash<'a> {
	salt: &'a str,
	hash: &'a str,
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
	} else if hash_id.starts_with("$2y$") {
		None
	} else if hash_id.starts_with("{SHA}") {
		None
	} else {
		//Ignore plaintext, assume crypt
		None
	}
}

impl Htpasswd<'_> {
	pub fn check(&self, username: &str, password: &str) -> bool {
		let hash = &self.0[username];
		match hash {
			Hash::MD5(hash) => md5::md5_apr1_encode(password, hash.salt).as_str() == hash.hash,
			_ => unimplemented!(),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn md5_verify_htpasswd() {
		let data = "user2:$apr1$7/CTEZag$omWmIgXPJYoxB3joyuq4S/
user:$apr1$lZL6V/ci$eIMz/iKDkbtys/uU7LEK00";
		let htpasswd = load(data);
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
				"xxxxxxxx"
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
	fn md5_classic() {
		let buf = md5::md5_encode("password");
		assert_eq!(
			buf,
			[95, 77, 204, 59, 90, 167, 101, 214, 29, 131, 39, 222, 184, 130, 207, 153]
		);
	}

	#[test]
	fn md5_classic_2() {
		let buf = md5::md5_encode("2[p1o340[123v'pasdaf2-34");
		assert_eq!(
			buf,
			[78, 114, 155, 6, 82, 67, 172, 173, 221, 8, 1, 74, 2, 167, 57, 0]
		);
	}
}
