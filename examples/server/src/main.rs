static VERSION:&str = "0.12.1 December 2018";
static MAIN_DIRECTORY:&str = "teamech/";
static LOG_DIRECTORY:&str = "logs/";
static KEY_DIRECTORY:&str = "keys/";
static ERROR_THRESHOLD:u64 = 10;
static ERROR_DECAY_TIME:i64 = 5000;

extern crate teamech;

extern crate time;
use time::{now_utc,Timespec};

use std::process;
use std::path::{Path,PathBuf};
use std::io;
use std::io::prelude::*;
use std::fs;
use std::fs::File;
use std::env::args;
use std::collections::HashMap;

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
	let env_args:Vec<String> = args().collect::<Vec<String>>();
	let valued_flags:Vec<char> = vec!['p','n'];
	let valued_switches:Vec<&str> = vec!["port","name"];
	let mut flags:Vec<char> = Vec::new();
	let mut switches:Vec<&str> = Vec::new();
	let mut arguments:Vec<&str> = Vec::new();
	let mut command:&str = "";
	let mut flags_seeking_values:Vec<char> = Vec::new();
	let mut switches_seeking_values:Vec<&str> = Vec::new();
	let mut flag_values:HashMap<char,&str> = HashMap::new();
	let mut switch_values:HashMap<&str,&str> = HashMap::new();
	for i in 0..env_args.len() {
		if i == 0 {
			command = &env_args[i];
		} else if env_args[i].starts_with("--") {
			let switch = env_args[i].trim_matches('-');
			if valued_switches.contains(&switch) {
				switches_seeking_values.insert(0,&switch);
			}
			switches.push(&switch);
		} else if env_args[i].starts_with("-") {
			for c in env_args[i].trim_matches('-').chars() {
				if valued_flags.contains(&c) {
					flags_seeking_values.insert(0,c);
				}
				flags.push(c);
			}
		} else if let Some(valued_flag) = flags_seeking_values.pop() {
			flag_values.insert(valued_flag,&env_args[i]);
		} else if let Some(valued_switch) = switches_seeking_values.pop() {
			switch_values.insert(valued_switch,&env_args[i]);
		} else {
			arguments.push(&env_args[i]);
		}
	}
	let help_flag:bool = flags.contains(&'h') || switches.contains(&"help");
	let too_many_arguments:bool = arguments.len() > 0;
	//let too_few_arguments:bool = arguments.len() < 0;
	let unvalued_flags:bool = switches_seeking_values.len()+flags_seeking_values.len() > 0;
	if help_flag || too_many_arguments || unvalued_flags { //  || too_few_arguments {
		if help_flag {
			println!("Teamech Server {}",VERSION);
			println!("Server for the Teamech protocol");
			println!("Ellie D. Martin-Eberhardt");
		} else if too_many_arguments {
			println!("One or more of the specified arguments were not understood.");
		//} else if too_few_arguments {
		//	println!("One or more required arguments were not provided.");
		} else if unvalued_flags {
			println!("One or more of the specified flags requires a value, but no value was found.");
		}
		println!("Usage:");
		println!("{} [OPTIONS]",command);
		println!("Overview of options:");
		println!("-p, --port <number>: Remote UDP port number to connect to on the remote server.");
		println!("-n, --name <name>: Name of this server to present to clients.");
		println!("-v --verbose: Show all debugging information.");
		return;
	}
	// parse values from arguments
	let mut port_arg:&str = "3840";
	if let Some(port) = flag_values.get(&'p') {
		port_arg = port;
	} else if let Some(port) = switch_values.get(&"port") {
		port_arg = port;
	}
	let port_number:u16 = match port_arg.parse::<u16>() {
		Err(why) => {
			eprintln!("Failed to parse given port number as an integer. See --help for help.");
			eprintln!("{}",why);
			process::exit(1);
		},
		Ok(n) => n,
	};
	let home_dir:PathBuf = Path::new(".").to_owned();
	let identity_dir:PathBuf = home_dir.join(Path::new(&MAIN_DIRECTORY)).join(Path::new(&KEY_DIRECTORY)).to_owned();
	let log_dir:PathBuf = home_dir.join(Path::new(&MAIN_DIRECTORY)).join(Path::new(&LOG_DIRECTORY)).to_owned();
	let logger:Logger = Logger {
		log_file_path:log_dir.join(Path::new(&format!("{}-teamech-server.log",now_utc().rfc3339()))),
	};
	let mut server_name:&str = "server";
	if let Some(name) = flag_values.get(&'n') {
		server_name = name;
	} else if let Some(name) = switch_values.get(&"name") {
		server_name = name;
	}
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
			eprintln!("Error: no readable identities found in {}. No client connections can be opened!",&identity_dir.display());
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
