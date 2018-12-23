static VERSION:&str = "0.10.0 October 2018";

#[macro_use]
extern crate clap;

use std::fs::File;
use std::process;
use std::io::prelude::*;
use std::io;

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
	let arguments = clap_app!(app =>
		(name: "Teamech Identity File Generator")
		(version: VERSION)
		(author: "Ellie D.")
		(about: "Generates identity key files to enable links between clients and servers..")
		(@arg FILE: +required "Path to the file to which the identity data should be written.")
		(@arg name: -n --name +takes_value "Name to use for this client.")
		(@arg class: -c --class +takes_value "Main class to use for this client.")
	).get_matches();
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
	for byte in arguments.value_of("name").unwrap_or("unset_name").as_bytes().iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	file_text.push(b'#');
	for byte in arguments.value_of("class").unwrap_or("unset_class").as_bytes().iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	let mut output_file:File = match File::create(&arguments.value_of("FILE").expect("could not parse command line arguments")) {
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
