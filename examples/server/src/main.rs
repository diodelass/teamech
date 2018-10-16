static VERSION:&str = "0.9.0 October 2018";
static LOG_DIRECTORY:&str = ".teamech-logs/server/";

extern crate teamech;

#[macro_use]
extern crate clap;

extern crate dirs;
use dirs::home_dir;

extern crate chrono;
use chrono::prelude::*;

use std::process;
use std::path::{Path,PathBuf};
use std::io;
use std::io::prelude::*;
use std::fs;
use std::fs::File;

struct Logger {
	log_file_name:String,
}

impl Logger {

	// Accepts a path to a log file, and writes a line to it, generating a human- and machine-readable log.
	fn log_to_file(&self,logstring:&str) -> Result<(),io::Error> {
		let userhome:PathBuf = match home_dir() {
			None => PathBuf::new(),
			Some(pathbuf) => pathbuf,
		};
		let logdir:&Path = &userhome.as_path().join(&LOG_DIRECTORY);
		match fs::create_dir_all(&logdir) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let logpath:&Path = &logdir.join(&self.log_file_name);
		let mut log_file = match fs::OpenOptions::new() 
											.append(true)
											.open(&logpath) {
			Ok(file) => file,
			Err(why) => match why.kind() {
				io::ErrorKind::NotFound => match File::create(&logpath) {
					Ok(file) => file,
					Err(why) => return Err(why),
				},
				_ => return Err(why),
			},
		};
		match writeln!(log_file,"{}",&logstring) {
			Ok(_) => return Ok(()),
			Err(why) => return Err(why),
		};
	}

	fn log(&self,logstring:&str) {
		let log_file_name:String = self.log_file_name.clone();
		match self.log_to_file(&logstring) {
			Err(why) => {
				eprintln!("ERROR: Failed to write to log file at {}: {}",&log_file_name,why);
			},
			Ok(()) => (),
		};
	}

}

fn main() {
	// use Clap to obtain command-line arguments
	let arguments = clap_app!(app =>
		(name: "Teamech Server")
		(version: VERSION)
		(author: "Ellie D.")
		(about: "Server for the Teamech protocol.")
		(@arg PORT: +required "Local port number on which to listen for incoming data.")
		(@arg PADFILE: +required "Pad file to use for encryption/decryption (must be same as clients').")
		(@arg name: -n --name +takes_value "Unique name to identify this server to other servers.")
	).get_matches();
	// parse values from arguments
	let port_number:u16 = match arguments.value_of("PORT").unwrap_or("6666").parse::<u16>() {
		Err(why) => {
			eprintln!("Failed to parse port number argument as an integer. See --help for help.");
			eprintln!("{}",why);
			process::exit(1);
		},
		Ok(n) => n,
	};
	let logger:Logger = Logger {
		log_file_name:format!("{}-teamech-server.log",Local::now().format("%Y-%m-%dT%H:%M:%S").to_string()),
	};
	let pad_path:&str = arguments.value_of("PADFILE").unwrap_or("");
	let server_name:&str = arguments.value_of("name").unwrap_or("server");
	// recovery loop handles basic stateful setup of server initially, and catches breaks from the processor loop.
	'recovery:loop {
		// initialize a new server object with the arguments collected from the command line.
		let mut server = match teamech::new_server(&server_name,&pad_path,port_number) {
			Err(why) => {
				eprintln!("Failed to instantiate server: {}",why);
				process::exit(1);
			},
			Ok(server) => server,
		};
		// set this server to asynchronous mode, with an idle rep rate of 10 Hz
		match server.set_asynchronous(100) {
			Err(why) => eprintln!("Warning: Failed to set server to asynchronous mode: {}",why),
			Ok(_) => (),
		};
		// processor loop does not break under ideal conditions and handles all standard functions.
		'processor:loop {
			// collect packets from clients, and append them to the server's receive_queue.
			match server.get_packets() {
				Err(why) => eprintln!("Failed to receive incoming packets: {}",why),
				Ok(_) => (),
			};
			while let Some(packet) = server.receive_queue.pop_front() {
				// relay every packet. the relay function will automatically refuse to send invalid packets.
				match server.relay_packet(&packet) {
					Err(why) => eprintln!("Failed to relay packet: {}",why),
					Ok(_) => (),
				};
			}
			match server.resend_unacked() {
				Err(why) => eprintln!("Failed to resend unacknowledged packets: {}",why),
				Ok(_) => (),
			};
			while let Some(event) = server.event_log.pop_front() {
				let event_string:String = event.to_string();
				println!("{}",event_string);
				logger.log(&event_string);
			}
		}
	}
}
