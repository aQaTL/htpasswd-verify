//#![deny(unsafe_code)]

mod md5;

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn md5_apr1() {
		assert_eq!(
			md5::md5_encode("password", "xxxxxxxx"),
			"dxHfLAsjHkDRmG83UXe8K0".to_string()
		);
	}

	#[test]
	fn md5_classic() {
		let buf = md5::md5_classic("password");
		assert_eq!(
			buf,
			[95, 77, 204, 59, 90, 167, 101, 214, 29, 131, 39, 222, 184, 130, 207, 153]
		);
	}

	#[test]
	fn md5_classic_2() {
		let buf = md5::md5_classic("2[p1o340[123v'pasdaf2-34");
		assert_eq!(
			buf,
			[78, 114, 155, 6, 82, 67, 172, 173, 221, 8, 1, 74, 2, 167, 57, 0]
		);
	}
}
