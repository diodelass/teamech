static VERSION:&str = "0.7.1 October 2018";

extern crate teamech;

#[macro_use]
extern crate clap;

use std::process;
use std::collections::VecDeque;

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
	let pad_path:&str = arguments.value_of("PADFILE").unwrap_or("");
	let server_name:&str = arguments.value_of("name").unwrap_or("server");
	// recovery loop handles basic stateful setup of server initially, and catches breaks from the processor loop.
	'recovery:loop {
		// set up a queue of log lines to be printed to the console.
		let mut log_lines:VecDeque<String> = VecDeque::new();
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
				match event.class {
					teamech::EventClass::Acknowledge => (),
					teamech::EventClass::Create => {
						log_lines.push_back(format!("[{}] Server initialized.",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f")));
					},
					teamech::EventClass::Subscribe => {
						log_lines.push_back(format!("[{}] Subscription opened by {} [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::Unsubscribe => {
						log_lines.push_back(format!("[{}] Subscription closed by {} [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::ServerLink => {
						log_lines.push_back(format!("[{}] Linked to server at [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ServerLinkFailure => {
						log_lines.push_back(format!("[{}] Could not link to server at [{}]: {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.contents),
							String::from_utf8_lossy(&event.parameter)));
					},
					teamech::EventClass::ServerUnlink => {
						log_lines.push_back(format!("[{}] Unlinked from server at [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ReceiveMessage => {
						log_lines.push_back(format!("[{}] {} [{}] -> >[{}] {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.parameter),String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ReceiveFailure => {
						log_lines.push_back(format!("[{}] Could not receive packet: {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::SendMessage => {
						log_lines.push_back(format!("[{}] >[{}] {} -> {} [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::SendFailure => {
						log_lines.push_back(format!("[{}] Could not send packet to {} [{}]: {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::DeadEndMessage => {
						log_lines.push_back(format!("[{}] Not relayed (no matching recipients): >[{}] {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::HaltedMessage => {
						log_lines.push_back(format!("[{}] Not relayed (returning packet): >[{}] {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::TestMessage => {
						log_lines.push_back(format!("[{}] Match test: >[{}] [matches {}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::RoutedMessage => {
						log_lines.push_back(format!("[{}] >[{}] {} -> {} [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::GlobalMessage => {
						log_lines.push_back(format!("[{}] >[{}] {} -> [all clients]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::InvalidMessage => {
						log_lines.push_back(format!("[{}] [SIGNATURE INVALID] {} [{}] -> >[{}] {}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.parameter),String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::DeliveryRetry => {
						log_lines.push_back(format!("[{}] [resending] >[{}] {} -> {} [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::DeliveryFailure => {
						log_lines.push_back(format!("[{}] [delivery failed] >[{}] {} -> {} [{}]",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.parameter),
							String::from_utf8_lossy(&event.contents),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::NameUpdate => {
						log_lines.push_back(format!("[{}] {} [{}] set name to @{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::NameUpdateFailure => {
						log_lines.push_back(format!("[{}] {} [{}] could not set name to @{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ClassAdd => {
						log_lines.push_back(format!("[{}] {} [{}] added class #{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ClassAddFailure => {
						log_lines.push_back(format!("[{}] {} [{}] could not add class #{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ClassRemove => {
						log_lines.push_back(format!("[{}] {} [{}] deleted class #{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ClassListRequest => {
						log_lines.push_back(format!("[{}] {} [{}] requested class list.",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::ClassListResponse => {
						log_lines.push_back(format!("[{}] class list for {} [{}]: #{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
					teamech::EventClass::ClientListRequest => {
						log_lines.push_back(format!("[{}] {} [{}] requested client list.",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address));
					},
					teamech::EventClass::ClientListResponse => {
						log_lines.push_back(format!("[{}] client list for {} [{}]: #{}",
							event.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),String::from_utf8_lossy(&event.identifier),event.address,
							String::from_utf8_lossy(&event.contents)));
					},
				};
			}
			while let Some(line) = log_lines.pop_front() {
				println!("{}",line);
			}
		}
	}
}
