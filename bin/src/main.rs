use std::path::PathBuf;
use structopt::StructOpt;
use anyhow::anyhow;

#[derive(StructOpt, Debug)]
#[structopt(
	name = "httpaswd-verify",
	about = "Verify user credentials against htpasswd file"
)]
struct Opt {
	#[structopt(name = "file", parse(from_os_str))]
	file_name: PathBuf,
	#[structopt(name = "username")]
	username: String,
	#[structopt(name = "password")]
	password: String,
}

fn main() -> anyhow::Result<()> {
	let opt = Opt::from_args();

	let data = std::fs::read_to_string(opt.file_name)?;
	let htpasswd = htpasswd_verify::load(&data);
	let check_res = htpasswd.check(&opt.username, &opt.password);
	if check_res {
		println!("Password correct");
		Ok(())
	} else {
		println!("Password incorrect");
		Err(anyhow!("incorrect password"))
	}
}
