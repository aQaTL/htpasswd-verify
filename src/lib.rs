mod md5;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn md5_apr1() {
		assert_eq!(
			md5::md5_apr1_encode("password", "xxxxxxxx"),
			"$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0".to_string()
		);
	}

	#[test]
	fn apr1() {
		assert!(md5::verify_apr1_hash("$apr1$xxxxxxxx$dxHfLAsjHkDRmG83UXe8K0", "password").unwrap());
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
