static VERSION:&str = "0.12.1 December 2018";
static MAIN_DIRECTORY:&str = "teamech/";
static LOG_DIRECTORY:&str = "logs/server/";
static KEY_DIRECTORY:&str = "keys/server/";
static ERROR_THRESHOLD:u64 = 10;
static ERROR_DECAY_TIME:i64 = 5000;

extern crate teamech;

#[macro_use]
extern crate clap;

extern crate time;
use time::{now_utc,Timespec};

use std::process;
use std::path::{Path,PathBuf};
use std::io;
use std::io::prelude::*;
use std::fs;
use std::fs::File;

fn milliseconds_now() -> i64 {
	let now:Timespec = now_utc().to_timespec();
	return now.sec*1000 + (now.nsec as i64)/1000000;
}

struct Logger {
	log_file_path:PathBuf,
}

impl Logger {

	// Accepts a path to a log file, and writes a line to it, generating a human- and machine-readable log.
	fn log_to_file(&self,logstring:&str) -> Result<(),io::Error> {
		let log_dir:&Path = match self.log_file_path.parent() {
			None => Path::new("."),
			Some(dir) => dir,
		};
		match fs::create_dir_all(&log_dir) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let mut log_file = match fs::OpenOptions::new() 
		.append(true)
		.open(&self.log_file_path) {
			Ok(file) => file,
			Err(why) => match why.kind() {
				io::ErrorKind::NotFound => match File::create(&self.log_file_path) {
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

	// A wrapper around log_to_file() that captures the errors and prints them to the console.
	fn log(&self,logstring:&str) {
		let log_file_name:String = self.log_file_path.to_str().unwrap_or("unknown").to_owned();
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
		(@arg logs: -l --logdir +takes_value "Path to directory where logs files should be stored.")
		(@arg keys: -k --iddir +takes_value "Path to directory where identity files are stored.")
		(@arg port: -p --port +takes_value "Local port number on which to listen for incoming data.")
		(@arg name: -n --name +takes_value "Unique name to identify this server to other servers.")
	).get_matches();
	// parse values from arguments
	let port_number:u16 = match arguments.value_of("port").unwrap_or("3840").parse::<u16>() {
		Err(why) => {
			eprintln!("Failed to parse given port number as an integer. See --help for help.");
			eprintln!("{}",why);
			process::exit(1);
		},
		Ok(n) => n,
	};
	let home_dir:PathBuf = Path::new(".").to_owned();
	let identity_dir:PathBuf = match arguments.value_of("keys") {
		None => (home_dir.join(Path::new(&MAIN_DIRECTORY)).join(Path::new(&KEY_DIRECTORY))).to_owned(),
		Some(pathvalue) => Path::new(&pathvalue).to_owned(),
	};

	let log_dir:PathBuf = match arguments.value_of("logs") {
		None => (home_dir.join(Path::new(&MAIN_DIRECTORY)).join(Path::new(&LOG_DIRECTORY))).to_owned(),
		Some(pathvalue) => Path::new(&pathvalue).to_owned(),
	};
	let logger:Logger = Logger {
		log_file_path:log_dir.join(Path::new(&format!("{}-teamech-server.log",now_utc().rfc3339()))),
	};
	let server_name:&str = arguments.value_of("name").unwrap_or("server");
	// recovery loop handles basic stateful setup of server initially, and catches breaks from the processor loop.
	'recovery:loop {
		// initialize a new server object with the arguments collected from the command line.
		let mut server = match teamech::new_server(&server_name,&port_number) {
			Err(why) => {
				eprintln!("Failed to instantiate server: {}",why);
				process::exit(1);
			},
			Ok(server) => server,
		};
		// set this server to asynchronous mode, with an idle rep rate of 10 Hz
		match server.set_asynchronous(1) {
			Err(why) => eprintln!("Warning: Failed to set server to asynchronous mode: {}",why),
			Ok(_) => (),
		};
		match server.load_identities(&identity_dir) {
			Err(why) => {
				eprintln!("Failed to load identities from {}: {}",&identity_dir.display(),why);
			},
			Ok(_) => (),
		};
		if server.identities.len() == 0 {
			eprintln!("Error: no readable identities found in {}. No client subscriptions can be opened!",&identity_dir.display());
		}
		let mut error_count:u64 = 0;
		let mut last_error:i64 = milliseconds_now();
		// processor loop does not break under ideal conditions and handles all standard functions.
		'processor:loop {
			// collect packets from clients, and append them to the server's receive_queue.
			match server.process_packets() {
				Err(why) => {
					eprintln!("Failed to process incoming packets: {}",why);
					error_count += 1;
					last_error = milliseconds_now();
				},
				Ok(_) => (),
			};
			match server.resend_unacked() {
				Err(why) => {
					eprintln!("Failed to resend unacknowledged packets: {}",why);
					error_count += 1;
					last_error = milliseconds_now();
				},
				Ok(_) => (),
			};
			while let Some(event) = server.event_stream.pop_front() {
				let event_string:String = event.to_string();
				println!("{}",event_string);
				logger.log(&event_string);
			}
			if error_count > ERROR_THRESHOLD {
				break 'processor;
			}
			if milliseconds_now() > last_error+ERROR_DECAY_TIME && error_count > 0 {
				error_count -= 1;
				last_error = milliseconds_now();
			}
		}
	}
}
