static VERSION:&str = "0.10.0 October 2018";

#[macro_use]
extern crate clap;

extern crate rand;

extern crate byteorder;
use byteorder::{LittleEndian,WriteBytesExt};

use std::fs::File;
use std::process;
use std::io::prelude::*;

fn u64_to_bytes(number:&u64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	bytes.as_mut().write_u64::<LittleEndian>(*number).expect("failed to convert u64 to bytes");
	return bytes;
}

fn bytes_to_hex(v:&Vec<u8>) -> String {
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

fn main() {
	let arguments = clap_app!(app =>
		(name: "Teamech Identity File Generator")
		(version: VERSION)
		(author: "Ellie D.")
		(about: "Generates identity key files to enable links between clients and servers..")
		(@arg FILE: "Path to the file to which the identity data should be written.")
		(@arg name: -n --name +takes_value "Name to use for this client.")
		(@arg class: -c --class +takes_value "Main class to use for this client.")
	).get_matches();
	let mut file_text:Vec<u8> = Vec::new();
	file_text.push(b'I');
	for byte in bytes_to_hex(&u64_to_bytes(&rand::random::<u64>()).to_vec()).as_bytes().iter() {
		file_text.push(*byte);
	}
	file_text.push(b'\n');
	file_text.push(b'K');
	for _ in 0..4 {
		for byte in bytes_to_hex(&u64_to_bytes(&rand::random::<u64>()).to_vec()).as_bytes().iter() {
			file_text.push(*byte);
		}
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
