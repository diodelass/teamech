static VERSION:&str = "0.12.1 December 2018";

use std::fs::File;
use std::process;
use std::io::prelude::*;
use std::io;
use std::env::args;

fn bytes_to_hex(v:&[u8]) -> String {
	let mut result:String = String::from("");
	for x in 0..v.len() {
		if v[x] == 0x00 {
			result.push_str(&format!("00"));
		} else if v[x] < 0x10 {
			result.push_str(&format!("0{:x?}",v[x]));
		} else {
			result.push_str(&format!("{:x?}",v[x]));
		}
	}
	return result;
}

fn get_rand_bytes(buffer:&mut [u8]) -> Result<(),io::Error> {
	let random_device_path:&str = "/dev/urandom";
	let mut random_device_descriptor:File = match File::open(&random_device_path) {
		Err(why) => return Err(why),
		Ok(file) => file,
	};
	match random_device_descriptor.read(buffer) {
		Err(why) => return Err(why),
		Ok(_) => return Ok(()),
	};
}

fn main() {
	let env_args:Vec<String> = args().collect::<Vec<String>>();
	let mut command = "";
	if let Some(com) = env_args.first() {
		command = &com;
	}
	if env_args.len() < 2 || env_args.contains(&"--help".to_owned()) || env_args.contains(&"-h".to_owned()) {
		println!("Teamech identity file generator {}",VERSION);
		println!("Generates identity files containing keys to be used for secure Teamech connections.");
		println!("Ellie D. Martin-Eberhardt");
		println!("Usage:");
		println!("{} <FILE>",command);
		println!("Example:");
		println!("{} testkey.tmi",command);
		return;
	}
	let filename = &env_args[1];
	let mut file_text:Vec<u8> = Vec::new();
	file_text.push(b'I');
	let mut ibuffer:[u8;8] = [0;8];
	let _ = get_rand_bytes(&mut ibuffer);
	for byte in bytes_to_hex(&ibuffer).as_bytes().iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	file_text.push(b'K');
	let mut kbuffer:[u8;32] = [0;32];
	let _ = get_rand_bytes(&mut kbuffer);
	for byte in bytes_to_hex(&kbuffer).as_bytes().iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	file_text.push(b'@');
	for byte in b"example_name".iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	file_text.push(b'#');
	for byte in b"example_class".iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	let mut output_file:File = match File::create(&filename) {
		Err(why) => {
			eprintln!("Could not create specified file: {}",why);
			process::exit(1);
		},
		Ok(file) => file,
	};
	match output_file.write_all(&file_text[..]) {
		Err(why) => {
			eprintln!("Could not write to specified file: {}",why);
			process::exit(1);
		},
		Ok(_) => (),
	};
}
