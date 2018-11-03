// Teamech v 0.11.0 October 2018
// License: AGPL v3

/*
Feature Outline

Functionality														Implemented

I. Network
	A. UDP																		[X]
		1. Sending															[X]
		2. Receiving														[X]
		3. WAN Links/Holepunching								[X]
	B. Addresses															[X]
		1. IPv4																	[X]
		2. IPv6																	[X]
		3. DNS resolution												[X]
	C. Bulk data/file transfers								[X]
II. Server																		
	A. Subscriptions													[X]
		1. Acceptance														[X]
		2. Cancellation													[X]
			a. Upon request												[X]
			b. Upon absence												[X]
		3. Banning															[X]
		4. Identifiers													[X]
			a. Names (unique)											[X]
				i. Setting													[X]
				ii. Changing												[X]
			b. Classes (nonunique)								[X]
				i. Setting													[X]
				ii. Unsetting												[X]
	B. Relaying																[X]
		1. To all clients												[X]
		2. To specific clients									[X]
		3. To sets of clients										[X]
		4. To other servers											[X]
		5. Handling acknowledgements						[X]
			a. Resending													[X]
			b. Relaying acks back to source				[X]
	C. Server-Server Links										[X]
		1. Opening															[X] 
		2. Closing															[X]
III. Client																	
	A. Subscribing														[X]
		1. Opening subscription									[X]
		2. Closing subscription									[X]
		3. Responding to closure								[X]
	B. Sending																[X]
	C. Receiving															[X]
IV. Security																[X]
	A. Encryption															[X]
	B. Decryption															[X]
	C. Validation															[X]
	D. Incident Logs													[X]
V. Logging																	[X]
	A. Log Events															[X]
	B. Log Event Classification								[X]

*/

extern crate rand;

extern crate tiny_keccak;
use tiny_keccak::Keccak;

extern crate chrono;
use chrono::prelude::*;

extern crate resolve;

use std::io::prelude::*;
use std::io;
use std::fs::{File,read_dir,create_dir_all};
use std::path::Path;
use std::collections::{VecDeque,HashMap,HashSet};
use std::time::Duration;
use std::thread::sleep;
use std::net::{UdpSocket,SocketAddr,IpAddr};
use std::str::FromStr;

fn i64_to_bytes(number:&i64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	for x in 0..8 {
		bytes[x] = ((*number >> (8*x)) & 0xFF) as u8;
	}
	return bytes;
}

fn u64_to_bytes(number:&u64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	for x in 0..8 {
		bytes[x] = ((*number >> (8*x)) & 0xFF) as u8;
	}
	return bytes;
}

fn bytes_to_i64(bytes:&[u8;8]) -> i64 {
	let mut number:i64 = 0;
	for x in 0..8 {
		number += (bytes[x] as i64) << (8*x)
	}
	return number;
}

fn bytes_to_u64(bytes:&[u8;8]) -> u64 {
	let mut number:u64 = 0;
	for x in 0..8 {
		number += (bytes[x] as u64) << (8*x)
	}
	return number;
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
		if x < v.len()-1 {
			result.push_str(".");
		}
	}
	return result;
}

// accepts a boolean expression in the form `(foo|bar)&baz` and determines if it matches a 
// string of words in the form `foo bar baz`
// edge cases:
// - an empty pattern will always return true
// - a malformed or unparseable pattern will return false
// - words containing boolean operators cannot be matched and should not be included
fn wordmatch(pattern:&str,input:&str) -> bool {
	if pattern == "" || pattern == "@" || input.contains(&pattern) {
		// handle true-returning edge cases first, for speed
		return true;
	}
	let paddedinput:&str = &format!(" {} ",input);
	let ops:Vec<&str> = vec!["/","!","&","|","^","(",")"];
	let mut fixedpattern:String = String::from(pattern);
	for c in ops.iter() {
		// first, pad all the operators with spaces to make them come up as their own elements
		// when the string is split on whitespace.
		fixedpattern = fixedpattern.replace(c,&format!(" {} ",c));
	}
	for element in fixedpattern.clone().split_whitespace() {
		// replace all the terms of the expression with "1" or "0" depending on whether they 
		// individually match the input.
		let paddedelement:&str = &format!(" {} ",element);
		if !ops.contains(&element) {
			if paddedinput.contains(&paddedelement) {
				fixedpattern = fixedpattern.replace(&element,"1");
			} else {
				fixedpattern = fixedpattern.replace(&element,"0");
			}
		}
	}
	// now the expression consists only of operators, "1", and "0".
	// we remove whatever space padding is left, and start condensing it.
	fixedpattern = fixedpattern.replace(" ","");
	fixedpattern = fixedpattern.replace("/","&");
	loop {
		// expression evaluation works by replacing combinations of operators and arguments
		// with their results. this method is perhaps not as fast as it could be, but it
		// makes for some nice simple code. it's also easy to set up order-of-operations
		// behavior and handle parentheses correctly.
		// this would naturally not be an option with decimal numbers or other arguments which
		// have unlimited possible values, but for booleans, it's still fairly concise.
		let mut subpattern:String = fixedpattern.clone();
		// NOT
		subpattern = subpattern.replace("!0","1");
		subpattern = subpattern.replace("!1","0");
		// OR
		subpattern = subpattern.replace("0|1","1");
		subpattern = subpattern.replace("1|0","1");
		subpattern = subpattern.replace("1|1","1");
		subpattern = subpattern.replace("0|0","0");
		// AND
		subpattern = subpattern.replace("0&1","0");
		subpattern = subpattern.replace("1&0","0");
		subpattern = subpattern.replace("1&1","1");
		subpattern = subpattern.replace("0&0","0");
		// XOR
		subpattern = subpattern.replace("0^1","1");
		subpattern = subpattern.replace("1^0","1");
		subpattern = subpattern.replace("1^1","0");
		subpattern = subpattern.replace("0^0","0");
		// Implied AND
		subpattern = subpattern.replace(")(","&");
		// Parens
		subpattern = subpattern.replace("(0)","0");
		subpattern = subpattern.replace("(1)","1");
		if subpattern == fixedpattern {
			break;
		}
		fixedpattern = subpattern;
	}
	if fixedpattern == "1" {
		return true;
	} else {
		return false;
	}
}

pub enum Event {
	Acknowledge {
		// server or client sent back an acknowledgement to something we transmitted.
		sender:String,
		address:SocketAddr,
		hash:Vec<u8>,
		matches:u64,
		timestamp:DateTime<Local>,
	},
	ServerCreate {
		// server object instantiated.
		timestamp:DateTime<Local>,
	},
	ClientCreate {
		// client object instantiated.
		timestamp:DateTime<Local>,
	},
	ServerSubscribe {
		// we're a server, and a client just subscribed to us.
		sender:String,
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
	ClientSubscribe {
		// we're a client, and we just subscribed to a server.
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
	ServerSubscribeFailure {
		// we're a server, and the subscription process for a client just failed for some reason.
		sender:String,
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ClientSubscribeFailure {
		// we're a client, and the subscription process for a client just failed for some reason.
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ServerUnsubscribe {
		// we're a server, and a client has just been unsubscribed.
		sender:String,
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ClientUnsubscribe {
		// we're a client, and we've just been unsubscribed.
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ServerUnsubscribeFailure {
		// we're a server, and something went wrong while trying to unsubscribe a client.
		sender:String,
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ClientUnsubscribeFailure {
		// we're a client, and something went wrong while unsubscribing.
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ServerLink {
		// we're a server, and have just linked to another server.
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
	ServerLinkFailure {
		// we're a server, and have failed to link to another server for some reason.
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ServerUnlink {
		// we're a server, and we've just closed the link to another server.
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ServerUnlinkFailure {
		// we're a server, and something went wrong during the process of unlinking from another server.
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ReceiveMessage {
		// we've just received a message.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	ReceiveFileHeader {
		// we're a client and we've just received the header for a file (the filename and the file length).
		sender:String,
		address:SocketAddr,
		filename:String,
		length:u64,
		timestamp:DateTime<Local>,
	},
	ReceiveFileData {
		// we're a client and we've just received a data segment from a file.
		sender:String,
		address:SocketAddr,
		index:u64,
		data:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	ReceiveFailure {
		// we've tried to receive a packet, but failed.
		reason:String,
		timestamp:DateTime<Local>,
	},
	SendMessage {
		// we've transmitted a packet.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	SendFailure {
		// we tried to send a packet, but it failed.
		destination:String,
		address:SocketAddr,
		reason:String,
		timestamp:DateTime<Local>,
	},
	DeadEndMessage {
		// we're a server and we've just received a message whose routing expression doesn't match any clients.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	HaltedMessage {
		// we're a server and we've just received a packet that we've seen before, and won't resend.			
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	TestMessage {
		// we're a server and we've just received a packet that has a routing expression, but no payload.
		// this means that it's a test packet that shouldn't actually be relayed.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		matches:u64,
		timestamp:DateTime<Local>,
	},
	TestResponse {
		// we've received a response to a test packet.
		sender:String,
		address:SocketAddr,
		hash:Vec<u8>,
		matches:u64,
		timestamp:DateTime<Local>,
	},
	RoutedMessage {
		// we're a server and we've relayed a packet that was sent by a client.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	RoutedFile {
		// we're a server and we're starting to relay a file sent by a client.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		filename:String,
		timestamp:DateTime<Local>,
	},
	InvalidMessage {
		// we've received a message that isn't of the expected structure or has a bad signature.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		reason:String,
		timestamp:DateTime<Local>,
	},
	NullDecrypt {
		// we've decrypted a packet using the null key, which isn't secure. 
		// this is done when two nodes need to talk to each other, but don't have any keys in common.
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
	NullEncrypt {
		// we've encrypted a packet using the null key, which isn't secure.
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
	DeliveryRetry {
		// we're a server and we're trying again to deliver a packet to a client.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	DeliveryFailure {
		// we're a server and we're giving up trying to deliver a message to a client who isn't responding.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		reason:String,
		timestamp:DateTime<Local>,
	},
	ClientListRequest {
		// we're a server and we're trying 
		sender:String,
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
	ClientListResponse {
		sender:String,
		address:SocketAddr,
		payload:String,
		timestamp:DateTime<Local>,
	},
	IdentityLoad {
		filename:String,
		name:String,
		classes:Vec<String>,
		tag:Vec<u8>,
		timestamp:DateTime<Local>,
	},
	IdentityLoadFailure {
		filename:String,
		reason:String,
		timestamp:DateTime<Local>,
	},
	UnknownSender {
		address:SocketAddr,
		timestamp:DateTime<Local>,
	},
}

impl Event {

	// formats the event as a human-readable string that can be printed to the console and/or written to log files.
	pub fn to_string(&self) -> String {
		match self {
			Event::Acknowledge {timestamp,hash,sender,address,matches} => {
				return format!("[{}] Acknowledgement of [{}] by {} [{}] ({} matches)",&timestamp,bytes_to_hex(&hash),&sender,&address,&matches);
			},
			Event::ServerCreate {timestamp} => {
				return format!("[{}] Server initialization complete.",&timestamp);
			},
			Event::ClientCreate {timestamp} => {
				return format!("[{}] Client initialization complete.",&timestamp);
			},
			Event::ServerSubscribe {timestamp,sender,address} => {
				return format!("[{}] Subscription requested by {} [{}]",&timestamp,&sender,&address);
			},
			Event::ServerUnsubscribe {timestamp,sender,address,reason} => {
				return format!("[{}] Subscription closed for {} [{}] ({})",&timestamp,&sender,&address,&reason);
			},
			Event::ClientSubscribe {timestamp,address} => {
				return format!("[{}] Subscribed to server at [{}]",&timestamp,&address);
			},
			Event::ClientUnsubscribe {timestamp,address,reason} => {
				return format!("[{}] Unsubscribed from server at [{}]: {}",&timestamp,&address,&reason);
			},
			Event::ServerLink {timestamp,address} => {
				return format!("[{}] Linked to server at [{}]",&timestamp,&address);
			},
			Event::ServerLinkFailure {timestamp,address,reason} => {
				return format!("[{}] Could not link to server at [{}]: {}",&timestamp,&address,&reason);
			},
			Event::ServerUnlink {timestamp,address,reason} => {
				return format!("[{}] Unlinked from server at [{}] ({})",&timestamp,&address,&reason);
			},
			Event::ReceiveMessage {timestamp,sender,address,parameter,payload} => {
				return format!("[{}] {} [{}]: [{}] {}",&timestamp,&sender,&address,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload));
			},
			Event::ReceiveFailure {timestamp,reason} => {
				return format!("[{}] Could not receive packet: {}",&timestamp,&reason);
			},
			Event::SendMessage {timestamp,destination,address,parameter,payload} => {
				return format!("[{}] {} [{}] -> [{}]: {}",&timestamp,&destination,&address,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload));
			},
			Event::SendFailure {timestamp,destination,address,reason} => {
				return format!("[{}] Could not send packet to {} [{}]: {}",&timestamp,&destination,&address,&reason);
			},
			Event::DeadEndMessage {timestamp,sender,address,parameter,payload} => {
				return format!("[{}] Not relayed (no matching recipients) {} [{}] -> [{}]: {}",&timestamp,&sender,&address,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload));
			},
			Event::HaltedMessage {timestamp,sender,address,parameter,payload} => {
				return format!("[{}] Not relayed (returning packet) {} [{}] -> [{}]: {}",&timestamp,&sender,&address,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload));
			},
			Event::TestMessage {timestamp,sender,address,parameter,matches} => {
				return format!("[{}] {} [{}] -> Match test: [{}] [matches {}]",&timestamp,&sender,&address,
					String::from_utf8_lossy(&parameter),&matches);
			},
			Event::RoutedMessage {timestamp,parameter,payload,destination,address} => {
				return format!("[{}] [RELAY] [{}] {} -> {} [{}]",&timestamp,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload),&destination,&address);
			},
			Event::RoutedFile {timestamp,parameter,filename,destination,address} => {
				return format!("[{}] [FILE] [{}] {} -> {} [{}]",&timestamp,String::from_utf8_lossy(&parameter),&filename,&destination,&address);
			}
			Event::InvalidMessage {timestamp,reason,sender,address,parameter,payload} => {
				return format!("[{}] [{}] {} [{}] -> [{}] {}",&timestamp,&reason,&sender,&address,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload));
			},
			Event::DeliveryRetry {timestamp,parameter,payload,destination,address} => {
				return format!("[{}] [resending] [{}] {} -> {} [{}]",&timestamp,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload),&destination,&address);
			},
			Event::DeliveryFailure {timestamp,reason,parameter,payload,destination,address} => {
				return format!("[{}] [delivery failed: {}] [{}] {} -> {} [{}]",&timestamp,&reason,
					String::from_utf8_lossy(&parameter),String::from_utf8_lossy(&payload),&destination,&address);
			},
			Event::ClientListRequest {timestamp,sender,address} => {
				return format!("[{}] client list requested by {} [{}]",&timestamp,&sender,&address);
			},
			Event::ClientListResponse {timestamp,sender,address,payload} => {
				return format!("[{}] client list for {} [{}]: {}",&timestamp,&sender,&address,&payload);
			},
			Event::IdentityLoad {timestamp,filename,name,classes,tag} => {
				return format!("[{}] found identity at {}: @{}/#{} [{}]",&timestamp,&filename,&name,&classes[0],bytes_to_hex(&tag));
			},
			Event::NullEncrypt {timestamp,address} => {
				return format!("[{}] WARNING: Sending unsecured message to {} due to missing keys!",&timestamp,&address);
			},
			Event::NullDecrypt {timestamp,address} => {
				return format!("[{}] WARNING: Receiving unsecured message from {} due to missing keys!",&timestamp,&address);
			},
			Event::UnknownSender {timestamp,address} => {
				return format!("[{}] invalid subscription request from {}",&timestamp,&address);
			},
			_ => return String::new(),
		};
	}

}

// Packet Structure: [sender.len][sender][parameter.len][parameter][payload][timestamp][signature][nonce]
// sender.len - 1 byte - length of sender string
// sender - (sender.len) bytes - sender string (@name/#primary_class)
// parameter.len - 1 bytes - length of the parameter string
// parameter - (parameter.len) bytes - parameter string (boolean routing expression or packet type)
// payload - arbitrary length - message data
// timestamp - 8 bytes - i64 milliseconds since epoch
// signature - 8 bytes - teacrypt signature for all parts of message before this point
// nonce - 8 bytes - teacrypt decryption nonce for this packet

// packet object representing a single packet returned from a socket read operation (on
// both the client and server ends). 
pub struct Packet {
	pub raw:Vec<u8>,				// raw received data, encrypted
	pub decrypted:Vec<u8>,	// raw decrypted data, not including timestamp, signature, or nonce
	pub valid:bool,					// signature validation passed?
	pub timestamp:i64,			// when packet was received
	pub source:SocketAddr,	// sending socket address
	pub sender:Vec<u8>,			// sender's declared identifier (@name/#class)
	pub crypt_tag:Vec<u8>,	// encryption identity tag (which key was used to decrypt)
	pub crypt_null:bool,		// was this packet decrypted with the null key?
	pub parameter:Vec<u8>,	// message parameter (e.g. routing expression)
	pub payload:Vec<u8>,		// message payload
}

#[derive(Clone)]
pub struct UnackedPacket {
	pub raw:Vec<u8>,						// raw received data, encrypted
	pub decrypted:Vec<u8>,			// raw decrypted data, not including timestamp, signature, or nonce
	pub timestamp:i64,					// when packet was last sent
	pub tries:u64,							// number of times this packet has had sending attempted
	pub source:SocketAddr,			// sender's socket address
	pub destination:SocketAddr,	// recipient socket address
	pub recipient:Vec<u8>,			// recipient's declared identifier (@name/#class)
	pub parameter:Vec<u8>,			// message parameter (e.g. routing expression)
	pub payload:Vec<u8>,				// message payload
}

// object representing a Teamech client, with methods for sending and receiving packets.
pub struct Client {
	pub socket:UdpSocket,																// local socket for transceiving data
	pub server_address:SocketAddr,											// address of server we're subscribed to
	pub name:String,																		// our self-declared name
	pub classes:Vec<String>,														// our self-declared classes
	pub identity:Identity,
	pub receive_queue:VecDeque<Packet>,									// incoming packets that need to be processed by the implementation
	pub subscribed:bool,																// are we subscribed?
	pub accept_files:bool,
	pub event_stream:VecDeque<Event>,											// log of events produced by the client
	pub last_number_matched:VecDeque<([u8;8],u64)>,			// tracks ack match-count reporting
	pub unacked_packets:HashMap<[u8;8],UnackedPacket>,	// packets that need to be resent if they aren't acknowledged
	pub recent_packets:VecDeque<[u8;8]>,								// hashes of packets that were recently seen, to merge double-sends
	pub max_recent_packets:usize,												// max number of recent packet hashes to store
	pub max_resend_tries:u64,														// maximum number of tries to resend a packet before discarding it
	pub uptime:i64,																			// time at which this client was created
	pub time_tolerance_ms:i64,													// maximum time difference a packet can have from now
	pub synchronous:bool,																// whether or not this client is synchronous
}

pub fn new_client(identity_path:&Path,string_address:&str,remote_port:u16,local_port:u16,use_ipv6:bool) -> Result<Client,io::Error> {
	let server_ip_address:IpAddr = match IpAddr::from_str(&string_address) {
		Ok(address) => address,
		Err(_) => {
			let mut resolv_config = match resolve::config::DnsConfig::load_default() {
				Err(_why) => return Err(io::Error::new(io::ErrorKind::NotFound,"could not get DNS configuration")),
				Ok(config) => config,
			};
			resolv_config.use_inet6 = use_ipv6;
			let resolver = match resolve::resolver::DnsResolver::new(resolv_config) {
				Err(_why) => return Err(io::Error::new(io::ErrorKind::NotFound,"could not initialize DNS resolver")),
				Ok(resolver) => resolver,
			};
			match resolver.resolve_host(&string_address) {
				Err(_why) => return Err(io::Error::new(io::ErrorKind::NotFound,"failed to resolve host")),
				Ok(addrs) => {
					let addrs_vec:Vec<IpAddr> = addrs.collect();
					if addrs_vec.len() > 0 {
						addrs_vec[0]
					} else {
						return Err(io::Error::new(io::ErrorKind::NotFound,"failed to resolve host"));
					}
				},
			}
		},
	};
	let server_socket_address:SocketAddr = SocketAddr::new(server_ip_address,remote_port);
	let new_identity:Identity = match load_identity_file(&identity_path) {
		Err(why) => return Err(why),
		Ok(id) => id,
	};
	let local_bind_address:&str;
	if use_ipv6 {
		local_bind_address = "[::]";
	} else {
		local_bind_address = "0.0.0.0";
	}
	match UdpSocket::bind(&format!("{}:{}",&local_bind_address,&local_port)) {
		Err(why) => return Err(why),
		Ok(socket) => {
			let mut created_client = Client {
				socket:socket,
				server_address:server_socket_address,
				name:String::new(),
				classes:Vec::new(),
				receive_queue:VecDeque::new(),
				event_stream:VecDeque::new(),
				last_number_matched:VecDeque::new(),
				subscribed:false,
				unacked_packets:HashMap::new(),
				accept_files:true,
				recent_packets:VecDeque::new(),
				max_recent_packets:32,
				max_resend_tries:3,
				identity:new_identity,
				uptime:Local::now().timestamp_millis(),
				time_tolerance_ms:3000,
				synchronous:true,
			};
			created_client.event_stream.push_back(Event::ClientCreate {
				timestamp:Local::now(),
			});
			return Ok(created_client);
		},
	};
}

impl Client {

	// set the socket to blocking mode, meaning the program will sit idle on calls to
	// get_packets() until packets are available. this is the default.
	pub fn set_synchronous(&mut self) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(None) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = true;
				return Ok(());
			},
		};
	}

	// set the socket to nonblocking mode, meaning the program will wait for a certain
	// interval during get_packets calls, then move on to something else if no packets
	// are received. the timeout must be specified as an argument.
	pub fn set_asynchronous(&mut self,wait_time_ms:u64) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(Some(Duration::new(wait_time_ms/1000,(wait_time_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = false;
				return Ok(());
			},
		}
	}

	pub fn decrypt_packet(&mut self,bottle:&Vec<u8>,source_address:&SocketAddr) -> Packet {
		let now:i64 = Local::now().timestamp_millis();
		let mut decrypted_bytes:Vec<u8> = Vec::new();
		let mut timestamp:i64 = 0;
		let mut message_valid:bool = false;
		let mut crypt_null:bool = false;
		let mut sender_bytes:Vec<u8> = Vec::new();
		let mut parameter_bytes:Vec<u8> = Vec::new();
		let mut payload_bytes:Vec<u8> = Vec::new();
		if bottle.len() >= 40 {
			if bottle[bottle.len()-8..] == vec![0;8][..] {
				let null_identity = Identity { key:vec![0;32],tag:vec![0;8],name:String::new(),classes:vec![] };
				let null_decryption = null_identity.decrypt(&bottle);
				if null_decryption.valid {
					decrypted_bytes = null_decryption.message;
					timestamp = null_decryption.timestamp;
					message_valid = null_decryption.valid;
					crypt_null = true;
					self.event_stream.push_back(Event::NullDecrypt {
						address:source_address.clone(),
						timestamp:Local::now(),
					});
				}
			} else {
				let decryption = self.identity.decrypt(&bottle);
				decrypted_bytes = decryption.message;
				timestamp = decryption.timestamp;
				message_valid = decryption.valid;
			}
		}
		if decrypted_bytes.len() >= 2 {
			// by this point, decrypted_bytes consists of the entire decrypted packet, minus the timestamp, signature,
			// and nonce. everything from the end of the parameter string to the last byte is the payload.
			let sender_length:usize = decrypted_bytes[0] as usize;
			if sender_length+2 <= decrypted_bytes.len() {
				for scan_position in 1..sender_length+1 {
					sender_bytes.push(decrypted_bytes[scan_position]);
				}
			}
			let parameter_length:usize = decrypted_bytes[sender_length+1] as usize;
			if sender_length+parameter_length+2 <= decrypted_bytes.len() {
				for scan_position in sender_length+2..sender_length+parameter_length+2 {
					parameter_bytes.push(decrypted_bytes[scan_position]);
				}
				for scan_position in sender_length+parameter_length+2..decrypted_bytes.len() {
					payload_bytes.push(decrypted_bytes[scan_position]);
				}
			}
		}
		if timestamp > now+self.time_tolerance_ms || timestamp < now-self.time_tolerance_ms {
			message_valid = false;
		}
		return Packet {
			raw:bottle.clone(),
			decrypted:decrypted_bytes,
			valid:message_valid,
			timestamp:timestamp,
			source:source_address.clone(),
			sender:sender_bytes,
			crypt_tag:self.identity.tag.clone(),
			crypt_null:crypt_null,
			parameter:parameter_bytes,
			payload:payload_bytes,
		}
	}

	// collect packets from the server and append them to our receive_queue. this function
	// will block indefinitely if the client is in synchronous mode (the default), or give
	// up after a set delay if it has been set to asynchronous mode. in asynchronous mode,
	// the WouldBlock errors resulting from no new packets being available are suppressed,
	// so they do not need to be handled in the implementation code.
	pub fn get_packets(&mut self) -> Result<(),io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => break,
					io::ErrorKind::Interrupted => break,
					_ => {
						self.event_stream.push_back(Event::ReceiveFailure {
							reason:format!("{}",why),
							timestamp:Local::now(),
						});
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					if source_address == self.server_address {
						let received_packet:Packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
						let mut packet_hash:[u8;8] = [0;8];
						let mut sha3 = Keccak::new_sha3_256();
						sha3.update(&input_buffer[..receive_length]);
						sha3.finalize(&mut packet_hash);
						if self.recent_packets.contains(&packet_hash) {
							self.event_stream.push_back(Event::HaltedMessage {
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:source_address.clone(),
								parameter:packet_hash.to_vec(),
								payload:received_packet.payload.clone(),
								timestamp:Local::now(),
							});
							return Ok(());
						}
						if received_packet.valid && received_packet.parameter.len() > 0 {
							match (received_packet.parameter[0],received_packet.payload.len()) {
								(0x03,16)|(0x06,16) => {
									let mut acked_hash:[u8;8] = [0;8];
									let mut number_matched_bytes:[u8;8] = [0;8];
									acked_hash.copy_from_slice(&received_packet.payload[..8]);
									number_matched_bytes.copy_from_slice(&received_packet.payload[8..]);
									let number_matched:u64 = bytes_to_u64(&number_matched_bytes);
									let mut matched:bool = false;
									for number in self.last_number_matched.iter_mut() {
										if number.0 == acked_hash {
											*number = (acked_hash.clone(),number.1+number_matched);
											matched = true;
											break;
										} 
									}
									if !matched {
										self.last_number_matched.push_back((acked_hash.clone(),number_matched));
									}
									let _ = self.unacked_packets.remove(&acked_hash);
									if received_packet.parameter[0] == 0x03 {
										self.event_stream.push_back(Event::TestResponse {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:source_address.clone(),
											matches:number_matched,
											hash:acked_hash.to_vec(),
											timestamp:Local::now(),
										});
									} else {
										self.event_stream.push_back(Event::Acknowledge {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:source_address.clone(),
											matches:number_matched,
											hash:acked_hash.to_vec(),
											timestamp:Local::now(),
										});
									}
								},
								(0x06,0) => {
									self.event_stream.push_back(Event::Acknowledge {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:source_address.clone(),
										matches:0,
										hash:Vec::new(),
										timestamp:Local::now(),
									});
								}
								(0x19,0) => {
									self.event_stream.push_back(Event::ClientUnsubscribe {
										address:source_address.clone(),
										reason:String::from("subscription terminated by server"),
										timestamp:Local::now(),
									});
									if self.subscribed { 
										match self.subscribe() {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
								(0x02,0) => {
									self.event_stream.push_back(Event::ClientSubscribe {
										address:self.server_address.clone(),
										timestamp:Local::now(),
									});
								}
								(b'>',_)|(0x0E,_)|(0x0F,_) => {
									let mut ack_payload:Vec<u8> = Vec::new();
									ack_payload.append(&mut packet_hash.to_vec());
									ack_payload.append(&mut u64_to_bytes(&1).to_vec());
									match self.send_packet(&vec![0x06],&ack_payload) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
									match received_packet.parameter[0] {
										0x0E => {
											let mut length_bytes:[u8;8] = [0;8];
											length_bytes.copy_from_slice(&received_packet.payload[..8]);
											self.event_stream.push_back(Event::ReceiveFileHeader {
												sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
												address:received_packet.source.clone(),
												length:bytes_to_u64(&length_bytes),
												filename:String::from_utf8_lossy(&received_packet.payload[8..]).to_string(),
												timestamp:Local::now(),
											});
										},
										0x0F => if received_packet.payload.len() > 8 {
											let mut index_bytes:[u8;8] = [0;8];
											index_bytes.copy_from_slice(&received_packet.payload[..8]);
											self.event_stream.push_back(Event::ReceiveFileData {
												sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
												address:received_packet.source.clone(),
												index:bytes_to_u64(&index_bytes),
												data:received_packet.payload[8..].to_vec(),
												timestamp:Local::now(),
											});
										},
										_ => self.event_stream.push_back(Event::ReceiveMessage {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:received_packet.source.clone(),
											parameter:received_packet.parameter.clone(),
											payload:received_packet.payload.clone(),
											timestamp:Local::now(),
										}),
									};
								},
								(_,_) => {
									match self.send_packet(&vec![0x15],&packet_hash.to_vec()) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
									self.event_stream.push_back(Event::InvalidMessage {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										parameter:received_packet.parameter.clone(),
										payload:received_packet.payload.clone(),
										reason:String::from("unknown parameter"),
										timestamp:Local::now(),
									});
								},
							};
						} else if !received_packet.valid {
							match self.send_packet(&vec![0x15],&packet_hash.to_vec()) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							self.event_stream.push_back(Event::InvalidMessage {
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:received_packet.source.clone(),
								parameter:received_packet.parameter.clone(),
								payload:received_packet.payload.clone(),
								reason:String::from("signature invalid"),
								timestamp:Local::now(),
							});
						} else {
							self.event_stream.push_back(Event::InvalidMessage {
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:received_packet.source.clone(),
								parameter:received_packet.parameter.clone(),
								payload:received_packet.payload.clone(),
								reason:String::from("parameter missing"),
								timestamp:Local::now(),
							});
						}
						self.receive_queue.push_back(received_packet);
					}
				},
			};
			if self.synchronous {
				break;
			}
		}
		return Ok(());
	}

	// encrypts and transmits a payload of bytes to the server.
	pub fn send_packet(&mut self,parameter:&Vec<u8>,payload:&Vec<u8>) -> Result<String,io::Error> {
		let mut message:Vec<u8> = Vec::new();
		message.push(0x00); // sender markings are redundant for client-to-server packets
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let bottle:Vec<u8> = self.identity.encrypt(&message);
		match self.send_raw(&bottle) {
			Err(why) => {
				self.event_stream.push_back(Event::SendFailure {
					destination:String::from("server"),
					address:self.server_address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		if parameter.len() > 0 && [0x0F,0x0E,b'>'].contains(&&parameter[0]) {
			let mut packet_hash:[u8;8] = [0;8];
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&bottle);
			sha3.finalize(&mut packet_hash);
			self.unacked_packets.insert(packet_hash,UnackedPacket {
				raw:bottle.clone(),
				decrypted:payload.clone(),
				timestamp:Local::now().timestamp_millis(),
				tries:0,
				source:self.server_address.clone(),
				destination:self.server_address.clone(),
				recipient:b"server".to_vec(),
				parameter:parameter.clone(),
				payload:payload.clone(),
			});
			self.event_stream.push_back(Event::SendMessage {
				destination:String::from("server"),
				address:self.server_address.clone(),
				parameter:parameter.clone(),
				payload:payload.clone(),
				timestamp:Local::now(),
			});
			return Ok(bytes_to_hex(&packet_hash.to_vec()));
		} else {
			return Ok(String::new());
		}
	}
	
	// transmits a raw vector of bytes without encryption or modification. remember that
	// the server will reject all packets which are not encrypted and formatted correctly,
	// so bytes passed to this function should be set up using other code.
	pub fn send_raw(&self,message:&Vec<u8>) -> Result<(),io::Error> {
		match self.socket.send_to(&message[..],&self.server_address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	// retransmit packets that haven't been acknowledged and were last sent a while ago.
	pub fn resend_unacked(&mut self) -> Result<(),io::Error> {
		let now:i64 = Local::now().timestamp_millis();
		for unacked_packet in self.unacked_packets.clone().iter() {
			let packet_hash:&[u8;8] = &unacked_packet.0;
			let packet_bottle:&Vec<u8> = &unacked_packet.1.raw;
			let packet_timestamp:&i64 = &unacked_packet.1.timestamp;
			let packet_tries:&u64 = &unacked_packet.1.tries;
			// if the packet's timestamp is a while ago, resend it.
			if *packet_timestamp < now-self.time_tolerance_ms {
				match self.send_raw(&packet_bottle) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				if packet_tries < &self.max_resend_tries {
					if let Some(list_packet) = self.unacked_packets.get_mut(packet_hash) {
						list_packet.tries += 1;
						list_packet.timestamp = Local::now().timestamp_millis();
					}
					self.event_stream.push_back(Event::DeliveryRetry {
						destination:String::from_utf8_lossy(&unacked_packet.1.recipient).to_string(),
						address:self.server_address.clone(),
						parameter:unacked_packet.1.parameter.clone(),
						payload:unacked_packet.1.payload.clone(),
						timestamp:Local::now(),
					});
				} else {
					self.unacked_packets.remove(packet_hash);
					self.event_stream.push_back(Event::DeliveryFailure {
						destination:String::from_utf8_lossy(&unacked_packet.1.recipient).to_string(),
						address:self.server_address.clone(),
						parameter:unacked_packet.1.parameter.clone(),
						payload:unacked_packet.1.payload.clone(),
						reason:String::from("maximum number of resend attempts exceeded"),
						timestamp:Local::now(),
					});
				}
			}
		}
		return Ok(());
	}

	pub fn get_response(&mut self,target_parameters:&Vec<u8>) -> Result<(),io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		let wait_start:i64 = Local::now().timestamp_millis();
		let original_timeout:Option<Duration>;
		original_timeout = match self.socket.read_timeout() {
			Err(why) => return Err(why),
			Ok(t) => t,
		};
		match self.socket.set_read_timeout(Some(Duration::new((self.time_tolerance_ms/1000) as u64,(self.time_tolerance_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => {
						return Err(io::Error::new(io::ErrorKind::NotFound,"no response"));
					},
					_ => {
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					let received_packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
					let mut packet_hash:[u8;8] = [0;8];
					let mut sha3 = Keccak::new_sha3_256();
					sha3.update(&received_packet.raw);
					sha3.finalize(&mut packet_hash);
					let _ = self.unacked_packets.remove(&packet_hash);
					if received_packet.parameter.len() > 0 && source_address == self.server_address {
						if target_parameters.contains(&received_packet.parameter[0]) {
							break;
						} else if received_packet.parameter[0] == 0x19 {
							return Err(io::Error::new(io::ErrorKind::InvalidData,"authorization rejected"));
						} else if received_packet.parameter[0] == 0x15 {
							return Err(io::Error::new(io::ErrorKind::ConnectionRefused,"operation refused"));
						} else if received_packet.parameter[0] == 0x03 {
							return Err(io::Error::new(io::ErrorKind::NotFound,"no destinations available"));
						} else {
							continue;
						}
					}
				},
			};
			if Local::now().timestamp_millis() > wait_start+self.time_tolerance_ms {
				return Err(io::Error::new(io::ErrorKind::NotFound,"no response"));
			}
		}
		match self.socket.set_read_timeout(original_timeout) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		return Ok(());
	}

	// transmits a subscription request packet. server will return 0x06 if
	// we are already subscribed, 0x02 if we were not subscribed but are now,
	// 0x15 if something's wrong (e.g. server full) or an unreadable packet
	// if we have the wrong pad file.
	pub fn subscribe(&mut self) -> Result<(),io::Error> {
		let nonce:u64 = rand::random::<u64>();
		let nonce_bytes:Vec<u8> = u64_to_bytes(&nonce).to_vec();
		match self.send_packet(&vec![0x02],&nonce_bytes) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		match self.get_response(&vec![0x02,0x06]) {
			Err(why) => {
				self.event_stream.push_back(Event::ClientSubscribeFailure {
					address:self.server_address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			}
			Ok(_) => (),
		};
		self.event_stream.push_back(Event::ClientSubscribe {
			address:self.server_address.clone(),
			timestamp:Local::now(),
		});
		self.subscribed = true;
		return Ok(());
	}

	// sends a cancellation of subscription to the server. server will return
	// 0x19 if it hears us.
	pub fn unsubscribe(&mut self) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x18],&vec![]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		match self.get_response(&vec![0x19]) {
			Err(why) => {
				self.event_stream.push_back(Event::ClientUnsubscribeFailure {
					address:self.server_address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			}
			Ok(_) => (),
		};
		self.event_stream.push_back(Event::ClientUnsubscribe {
			address:self.server_address.clone(),
			reason:String::from("subscription cancelled locally"),
			timestamp:Local::now(),
		});
		self.subscribed = false;
		return Ok(());
	}
	
	pub fn send_file(&mut self,file_path:&Path,routing_expression:&str) -> Result<(),io::Error> {
		let mut file = match File::open(&file_path) {
			Err(why) => return Err(why),
			Ok(file) => file,
		};
		let file_metadata = match file.metadata() {
			Err(why) => return Err(why),
			Ok(metadata) => metadata,
		};
		let mut parameter = vec![0x0E];
		parameter.append(&mut routing_expression.as_bytes().to_vec());
		let filename:String = match file_path.file_name() {
			None => return Err(io::Error::new(io::ErrorKind::NotFound,"could not extract filename from path")),
			Some(string) => string.to_string_lossy().to_string(),
		};
		let mut payload:Vec<u8> = Vec::new();
		payload.append(&mut u64_to_bytes(&file_metadata.len()).to_vec());
		payload.append(&mut filename.as_bytes().to_vec());
		match self.send_packet(&parameter,&payload) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		match self.get_response(&vec![0x06]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let sync_state:Option<Duration> = match self.socket.read_timeout() {
			Err(why) => return Err(why),
			Ok(state) => state,
		};
		match self.socket.set_read_timeout(Some(Duration::new(0,0))) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		parameter[0] = 0x0F;
		let mut file_buffer:[u8;400] = [0;400];
		let mut read_position:u64 = 0;
		loop {
			match file.seek(io::SeekFrom::Start(read_position)) {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
			let read_length:usize = match file.read(&mut file_buffer) {
				Err(why) => return Err(why),
				Ok(n) => n,
			};
			if read_length == 0 {
				break;
			}
			let mut payload:Vec<u8> = u64_to_bytes(&read_position).to_vec();
			payload.append(&mut file_buffer[0..read_length].to_vec());
			match self.send_packet(&parameter,&payload) {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
			read_position += read_length as u64;
			match self.get_packets() {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
		}
		match self.socket.set_read_timeout(sync_state) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		return Ok(());
	}

} // impl Client

pub struct Decrypt {
	pub message:Vec<u8>,
	pub timestamp:i64,
	pub valid:bool,
}

#[derive(Clone)]
pub struct Identity {
	pub tag:Vec<u8>,
	pub key:Vec<u8>,
	pub name:String,
	pub classes:Vec<String>,
}

pub fn load_identity_file(identity_path:&Path) -> Result<Identity,io::Error> {
	let mut identity_bytes:Vec<u8> = Vec::new();
	let mut identity_file = match File::open(&identity_path) {
		Err(why) => return Err(why),
		Ok(file) => file,
	};
	match identity_file.read_to_end(&mut identity_bytes) {
		Err(why) => return Err(why),
		Ok(_) => (),
	};
	let mut tag:Vec<u8> = vec![0;8];
	let mut key:Vec<u8> = vec![0;32];
	let mut name:String = String::new();
	let mut classes:Vec<String> = Vec::new();
	for line in identity_bytes.split(|c|c==&b'\n') {
		if line.len() > 16 && line[0] == b'I' {
			let mut shake = Keccak::new_shake256();
			shake.update(&line[1..16]);
			shake.finalize(&mut tag);
		}
		if line.len() > 64 && line[0] == b'K' {
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&line[1..64]);
			sha3.finalize(&mut key);
		}
		if line.len() > 1 && line[0] == b'@' {
			let mut new_name:String = String::from_utf8_lossy(&line[1..]).to_string();
			new_name = new_name.trim_matches('\r').to_owned();
			name = new_name;
		}
		if line.len() > 1 && line[0] == b'#' {
			let mut new_class:String = String::from_utf8_lossy(&line[1..]).to_string();
			new_class = new_class.trim_matches('\r').to_owned();
			classes.push(new_class);
		}
	}
	if tag == vec![0;8] ||key == vec![0;32] || name == String::new() || classes.len() == 0 {
		 return Err(io::Error::new(io::ErrorKind::InvalidData,"identity file is incomplete"));
	}
	return Ok(Identity {
		tag:tag,
		key:key,
		name:name,
		classes:classes,
	});
}

impl Identity {

	pub fn encrypt(&self,message:&Vec<u8>) -> Vec<u8> {
		let mut timestamped_message:Vec<u8> = message.clone();
		timestamped_message.append(&mut i64_to_bytes(&Local::now().timestamp_millis()).to_vec());
		let nonce:u64 = rand::random::<u64>();
		let nonce_bytes:[u8;8] = u64_to_bytes(&nonce);
		let overlay_size:usize = timestamped_message.len()+16;
		let mut overlay_bytes:Vec<u8> = vec![0;overlay_size];
		let mut shake = Keccak::new_shake256();
		shake.update(&nonce_bytes[..]);
		shake.update(&self.key[..]);
		shake.finalize(&mut overlay_bytes);
		let mut signature:[u8;16] = [0;16];
		let mut shake = Keccak::new_shake256();
		shake.update(&timestamped_message);
		shake.update(&overlay_bytes);
		shake.finalize(&mut signature);
		let mut signed_message = Vec::new();
		signed_message.append(&mut timestamped_message.clone());
		signed_message.append(&mut signature.to_vec());
		let mut bottle = vec![0;overlay_size];
		for x in 0..overlay_size {
			bottle[x] = signed_message[x] ^ overlay_bytes[x];
		}
		bottle.append(&mut nonce_bytes.to_vec());
		bottle.append(&mut self.tag.clone());
		return bottle;
	}

	pub fn decrypt(&self,bottle:&Vec<u8>) -> Decrypt {
		if bottle.len() < 40 {
			return Decrypt {
				message:Vec::new(),
				timestamp:0,
				valid:false,
			};
		}
		let mut nonce_bytes:[u8;8] = [0;8];
		nonce_bytes.copy_from_slice(&bottle[bottle.len()-16..bottle.len()-8]);
		let overlay_size = bottle.len()-16;
		let mut key_bytes:Vec<u8> = vec![0;overlay_size];
		let mut shake = Keccak::new_shake256();
		shake.update(&nonce_bytes[..]);
		shake.update(&self.key[..]);
		shake.finalize(&mut key_bytes);
		let mut signed_message = vec![0;overlay_size];
		for x in 0..overlay_size {
			signed_message[x] = bottle[x] ^ key_bytes[x];
		}
		let mut signature:[u8;16] = [0;16];
		let mut timestamp:[u8;8] = [0;8];
		signature.copy_from_slice(&signed_message[signed_message.len()-16..]);
		timestamp.copy_from_slice(&signed_message[signed_message.len()-24..signed_message.len()-16]);
		let timestamped_message:Vec<u8> = signed_message[0..signed_message.len()-16].to_vec();
		let message:Vec<u8> = timestamped_message[..timestamped_message.len()-8].to_vec();
		let mut correct_signature:[u8;16] = [0;16];
		let mut shake = Keccak::new_shake256();
		shake.update(&timestamped_message);
		shake.update(&key_bytes);
		shake.finalize(&mut correct_signature);
		return Decrypt {
			message:message,
			timestamp:bytes_to_i64(&timestamp),
			valid:(signature == correct_signature),
		};
	}

}

// subscription object for tracking subscribed clients. constructed only by the
// receive_packets method when it receives a valid but unrecognized message 
// (not intended to be constructed directly).
#[derive(Clone)]
pub struct Subscription {
	pub address:SocketAddr,																	// socket address of subscriber
	pub identity:Identity,
	pub uptime:i64,																					// time at which this subscription was created
	pub unacked_packets:HashMap<[u8;8],UnackedPacket>,			// packets that need to be resent if they aren't acknowledged
	pub delivery_failures:u64,															// number of times a packet delivery has failed
}

#[derive(Clone)]
pub struct ServerLink {
	pub address:SocketAddr,
	pub uptime:i64,
	pub unacked_packets:HashMap<[u8;8],UnackedPacket>,
}

// server object for holding server parameters and subscriptions.
pub struct Server {
	pub name:String,
	pub socket:UdpSocket,
	pub identities:HashMap<Vec<u8>,Identity>,
	pub identities_in_use:HashSet<Vec<u8>>,
	pub subscribers:HashMap<SocketAddr,Subscription>,
	pub linked_servers:HashMap<SocketAddr,ServerLink>,
	pub max_subscribers:usize,
	pub ban_points:HashMap<IpAddr,u64>,
	pub max_ban_points:u64,
	pub banned_addresses:HashSet<IpAddr>,
	pub recent_packets:VecDeque<[u8;8]>,
	pub max_recent_packets:usize,
	pub max_unsent_packets:usize,
	pub max_resend_tries:u64,
	pub max_resend_failures:u64,
	pub event_stream:VecDeque<Event>,
	pub receive_queue:VecDeque<Packet>,
	pub uptime:i64,
	pub synchronous:bool,
	pub time_tolerance_ms:i64,
	pub ack_fake_lag_ms:u64,
}

// server constructor, works very similarly to client constructor
pub fn new_server(name:&str,port:&u16) -> Result<Server,io::Error> {
	match UdpSocket::bind(&format!("[::]:{}",port)) {
		Err(why) => return Err(why),
		Ok(socket) => {
			let mut created_server = Server {
				name:name.to_owned(),
				socket:socket,
				subscribers:HashMap::new(),
				identities:HashMap::new(),
				identities_in_use:HashSet::new(),
				linked_servers:HashMap::new(),
				max_subscribers:1024,
				ban_points:HashMap::new(),
				max_ban_points:10,
				banned_addresses:HashSet::new(),
				recent_packets:VecDeque::new(),
				event_stream:VecDeque::new(),
				max_recent_packets:64,
				max_unsent_packets:32,
				max_resend_tries:3,
				max_resend_failures:1,
				receive_queue:VecDeque::new(),
				uptime:Local::now().timestamp_millis(),
				synchronous:true,
				time_tolerance_ms:3000,
				ack_fake_lag_ms:0,
			};
			created_server.event_stream.push_back(Event::ServerCreate {
				timestamp:Local::now(),
			});
			return Ok(created_server);
		},
	};
}

impl Server {

	pub fn load_identities(&mut self,identity_dir:&Path) -> Result<(),io::Error> {
		match create_dir_all(&identity_dir) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let dir_iterator = match read_dir(&identity_dir) {
			Err(why) => return Err(why),
			Ok(files) => files,
		};
		for dir_node in dir_iterator {
			if let Ok(dir_entry) = dir_node {
				let ftype = match dir_entry.file_type() {
					Err(_why) => continue,
					Ok(ft) => ft,
				};
				if ftype.is_file() {
					let file_path = dir_entry.path();
					let new_identity:Identity = match load_identity_file(&file_path.as_path()) {
						Err(why) => {
							self.event_stream.push_back(Event::IdentityLoadFailure {
								filename:format!("{}",&file_path.display()),
								reason:format!("{}",why),
								timestamp:Local::now(),
							});
							continue;
						},
						Ok(id) => id,
					};
					self.event_stream.push_back(Event::IdentityLoad {
						filename:format!("{}",&file_path.display()),
						name:new_identity.name.clone(),
						classes:new_identity.classes.clone(),
						tag:new_identity.tag.to_vec(),
						timestamp:Local::now(),
					});
					self.identities.insert(new_identity.tag.clone(),new_identity);
				}
			}
		}
		return Ok(());
	}

	pub fn decrypt_packet(&mut self,bottle:&Vec<u8>,source_address:&SocketAddr) -> Packet {
		let now:i64 = Local::now().timestamp_millis();
		let mut decrypted_bytes:Vec<u8> = Vec::new();
		let mut timestamp:i64 = 0;
		let mut message_valid:bool = false;
		let mut id_null:bool = false;
		let mut sender_bytes:Vec<u8> = Vec::new();
		let mut parameter_bytes:Vec<u8> = Vec::new();
		let mut payload_bytes:Vec<u8> = Vec::new();
		if bottle.len() >= 40 {
			let decryption:Decrypt;
			if let Some(identity) = self.identities.get(&bottle[bottle.len()-8..]) {
				decryption = identity.decrypt(&bottle);
				sender_bytes = format!("@{}/#{}",&identity.name,&identity.classes[0]).as_bytes().to_vec();
			} else {
				let null_identity = Identity { key:vec![0;32],tag:vec![0;8],name:String::new(),classes:vec![] };
				decryption = null_identity.decrypt(&bottle);
				id_null = true;
				self.event_stream.push_back(Event::NullDecrypt {
					address:source_address.clone(),
					timestamp:Local::now(),
				});
			}
			decrypted_bytes = decryption.message;
			timestamp = decryption.timestamp;
			message_valid = decryption.valid;
		}
		if decrypted_bytes.len() >= 2 {
			// by this point, decrypted_bytes consists of the entire decrypted packet, minus the timestamp, signature,
			// and nonce. everything from the end of the parameter string to the last byte is the payload.
			let sender_length:usize = decrypted_bytes[0] as usize;
			let parameter_length:usize = decrypted_bytes[sender_length+1] as usize;
			if sender_length+parameter_length+2 <= decrypted_bytes.len() {
				for scan_position in sender_length+2..sender_length+parameter_length+2 {
					parameter_bytes.push(decrypted_bytes[scan_position]);
				}
				for scan_position in sender_length+parameter_length+2..decrypted_bytes.len() {
					payload_bytes.push(decrypted_bytes[scan_position]);
				}
			}
		}
		if timestamp > now+self.time_tolerance_ms || timestamp < now-self.time_tolerance_ms {
			message_valid = false;
		}
		return Packet {
			raw:bottle.clone(),
			decrypted:decrypted_bytes,
			valid:message_valid,
			timestamp:timestamp,
			source:source_address.clone(),
			sender:sender_bytes,
			crypt_tag:bottle[bottle.len()-8..].to_vec(),
			crypt_null:id_null,
			parameter:parameter_bytes,
			payload:payload_bytes,
		}
	}

	// similar to client sync/async settings. synchronous (the default) means the server
	// will remain completely idle when there are no packets to process. this makes for 
	// a lighter overall load on low-power systems, but also prevents the server from
	// doing anything when there are no incoming packets.
	pub fn set_synchronous(&mut self) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(None) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = true;
				return Ok(());
			},
		};
	}

	// similar to client sync/async settings. asynchronous means the server will poll for
	// incoming packets, wait a specified interval, and then take a break to do other things
	// before coming back to look again. when no packets are incoming, the server will perform
	// other tasks once every timeout period.
	// setting the timeout very low may result in high idle load.
	pub fn set_asynchronous(&mut self,wait_time_ms:u64) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(Some(Duration::new(wait_time_ms/1000,(wait_time_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = false;
				return Ok(());
			},
		}
	}

	pub fn get_response(&mut self,target_parameters:&Vec<u8>,target_address:&SocketAddr) -> Result<(),io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		let wait_start:i64 = Local::now().timestamp_millis();
		let original_timeout:Option<Duration>;
		original_timeout = match self.socket.read_timeout() {
			Err(why) => return Err(why),
			Ok(t) => t,
		};
		match self.socket.set_read_timeout(Some(Duration::new((self.time_tolerance_ms/1000) as u64,(self.time_tolerance_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => {
						return Err(io::Error::new(io::ErrorKind::NotFound,"no response"));
					},
					_ => {
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					let received_packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
					let mut packet_hash:[u8;8] = [0;8];
					let mut sha3 = Keccak::new_sha3_256();
					sha3.update(&received_packet.raw);
					sha3.finalize(&mut packet_hash);
					if let Some(sub) = self.subscribers.get_mut(&source_address) {
						let _ = sub.unacked_packets.remove(&packet_hash);
					}
					if let Some(serv) = self.linked_servers.get_mut(&source_address) {
						let _ = serv.unacked_packets.remove(&packet_hash);
					}
					if received_packet.parameter.len() > 0 && &source_address == target_address {
						if target_parameters.contains(&received_packet.parameter[0]) {
							break;
						} else if received_packet.parameter[0] == 0x19 {
							return Err(io::Error::new(io::ErrorKind::InvalidData,"authorization rejected"));
						} else if received_packet.parameter[0] == 0x15 {
							return Err(io::Error::new(io::ErrorKind::ConnectionRefused,"operation refused"));
						} else if received_packet.parameter[0] == 0x03 {
							return Err(io::Error::new(io::ErrorKind::NotFound,"no destinations available"));
						} else {
							continue;
						}
					}
				},
			};
			if Local::now().timestamp_millis() > wait_start+self.time_tolerance_ms {
				return Err(io::Error::new(io::ErrorKind::NotFound,"no response"));
			}
		}
		match self.socket.set_read_timeout(original_timeout) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		return Ok(());
	}

	pub fn link_server(&mut self,remote_address:&SocketAddr,crypt_tag:&Vec<u8>) -> Result<(),io::Error> {
		let nonce:u64 = rand::random::<u64>();
		let nonce_bytes:Vec<u8> = u64_to_bytes(&nonce).to_vec();
		match self.send_packet(&vec![],&vec![0x02],&nonce_bytes,&crypt_tag,&remote_address) {
			Err(why) => {
				self.event_stream.push_back(Event::ServerLinkFailure {
					address:remote_address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		match self.get_response(&vec![0x02,0x06],&remote_address) {
			Err(why) => {
				self.event_stream.push_back(Event::ServerLinkFailure {
					address:remote_address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		self.linked_servers.insert(remote_address.clone(),ServerLink {
			address:remote_address.clone(),
			uptime:Local::now().timestamp_millis(),
			unacked_packets:HashMap::new(),
		});	
		self.event_stream.push_back(Event::ServerLink {
			address:remote_address.clone(),
			timestamp:Local::now(),
		});
		return Ok(());
	}

	// 
	pub fn unlink_server(&mut self,crypt_tag:Vec<u8>,remote_address:&SocketAddr) -> Result<(),io::Error> {
		match self.send_packet(&vec![],&vec![0x18],&vec![],&crypt_tag,&remote_address) {
			Err(why) => {
				self.event_stream.push_back(Event::ServerUnlinkFailure {
					address:remote_address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		for sub in self.linked_servers.clone().iter() {
			if sub.0 == remote_address {
				let _ = self.linked_servers.remove(&sub.0);
			}
		}
		self.event_stream.push_back(Event::ServerUnlink {
			address:remote_address.clone(),
			reason:String::from("link terminated locally"),
			timestamp:Local::now(),
		});
		return Ok(());
	}

	// encrypts and transmits a packet, much like the client version.
	pub fn send_packet(&mut self,sender:&Vec<u8>,parameter:&Vec<u8>,payload:&Vec<u8>,crypt_tag:&Vec<u8>,address:&SocketAddr) 
		-> Result<String,io::Error> {
		let mut message:Vec<u8> = Vec::new();
		message.push(sender.len() as u8);
		message.append(&mut sender.clone());
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let null_identity = Identity { key:vec![0;32],tag:vec![0;8],name:String::new(),classes:vec![] };
		let bottle:Vec<u8>;
		if let Some(identity) = self.identities.get(crypt_tag) {
			bottle = identity.encrypt(&message);
		} else {
			bottle = null_identity.encrypt(&message);
			self.event_stream.push_back(Event::NullEncrypt {
				address:address.clone(),
				timestamp:Local::now(),
			});
		}
		let mut recipient:String = String::new();
		if let Some(sub) = self.subscribers.get_mut(&address) {
			recipient = format!("@{}/#{}",sub.identity.name,sub.identity.classes[0]);
		}
		match self.socket.send_to(&bottle[..],&address) {
			Err(why) => {
				self.event_stream.push_back(Event::SendFailure {
					destination:recipient.clone(),
					address:address.clone(),
					reason:format!("{}",why),
					timestamp:Local::now(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		if parameter.len() > 0 && [0x0F,0x0E,b'>'].contains(&&parameter[0]) {
			let mut packet_hash:[u8;8] = [0;8];
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&bottle);
			sha3.finalize(&mut packet_hash);
			if let Some(sub) = self.subscribers.get_mut(&address) {
				sub.unacked_packets.insert(packet_hash.clone(),UnackedPacket {
					raw:bottle.clone(),
					decrypted:message.clone(),
					timestamp:Local::now().timestamp_millis(),
					tries:0,
					source:address.clone(),
					destination:address.clone(),
					recipient:recipient.as_bytes().to_vec(),
					parameter:parameter.clone(),
					payload:payload.clone(),
				});
			}
			self.event_stream.push_back(Event::SendMessage {
				destination:recipient.clone(),
				address:address.clone(),
				parameter:parameter.clone(),
				payload:payload.clone(),
				timestamp:Local::now(),
			});
			return Ok(bytes_to_hex(&packet_hash.to_vec()));
		} else {
			return Ok(String::new());
		}
	}
	
	// similar to the client version; sends a raw packet without modifying it. Will need to be pre-
	// encrypted through some other means, or the client will reject it.
	pub fn send_raw(&self,message:&Vec<u8>,address:&SocketAddr) -> Result<(),io::Error> {
		match self.socket.send_to(&message[..],&address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}
	
	pub fn get_packets(&mut self) -> Result<(),io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => break,
					io::ErrorKind::Interrupted => break,
					_ => {
						self.event_stream.push_back(Event::ReceiveFailure {
							reason:format!("{}",why),
							timestamp:Local::now(),
						});
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					// check bans immediately after receiving a packet, to minimize the impact of flooding
					if self.banned_addresses.contains(&source_address.ip()) {
						continue;
					}
					let mut current_ban_points:u64 = 0;
					if let Some(points) = self.ban_points.get(&source_address.ip()) {
						current_ban_points = points.clone()
					}
					if !self.ban_points.contains_key(&source_address.ip()) {
						self.ban_points.insert(source_address.ip(),0);
					}
					if current_ban_points > self.max_ban_points { 
						self.banned_addresses.insert(source_address.ip());
						continue;
					}
					let mut sender:String = String::new();
					if let Some(sub) = self.subscribers.get_mut(&source_address) {
						sender = format!("@{}/#{}",sub.identity.name,sub.identity.classes[0]);
					}
					if receive_length < 40 {
						self.ban_points.insert(source_address.ip(),current_ban_points+1);
						self.event_stream.push_back(Event::InvalidMessage {
							sender:sender.clone(),
							address:source_address.clone(),
							parameter:Vec::new(),
							payload:input_buffer[0..receive_length].to_vec(),
							reason:String::from("packet length too short"),
							timestamp:Local::now(),
						});
						continue;
					}
					let packet_crypt_tag:Vec<u8> = input_buffer[receive_length-8..receive_length].to_vec();
					let sender_identity:Identity;
					if let Some(id) = self.identities.clone().get(&packet_crypt_tag) {
						sender_identity = id.clone();
					} else {
						self.ban_points.insert(source_address.ip(),current_ban_points+1);
						self.event_stream.push_back(Event::UnknownSender {
							address:source_address.clone(),
							timestamp:Local::now(),
						});
						match self.send_packet(&vec![],&vec![0x15],&vec![],&vec![0;8],&source_address) {
							Err(why) => return Err(why),
							Ok(_) => (),
						};
						continue;
					}
					let received_packet:Packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
					if !self.subscribers.contains_key(&source_address) 
					&& !self.linked_servers.contains_key(&source_address) 
					&& received_packet.payload.len() >= 8 
					&& received_packet.parameter == vec![0x02] {
						if received_packet.valid && self.subscribers.len() < self.max_subscribers {
							self.subscribers.insert(source_address.clone(),Subscription {
								address:source_address.clone(),
								identity:sender_identity.clone(),
								uptime:Local::now().timestamp_millis(),
								unacked_packets:HashMap::new(),
								delivery_failures:0,
							});	
							self.identities_in_use.insert(sender_identity.tag.clone());
							match self.send_packet(&vec![],&vec![0x02],&vec![],&received_packet.crypt_tag,&source_address) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							self.event_stream.push_back(Event::ServerSubscribe {
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:source_address.clone(),
								timestamp:Local::now(),
							});
						} else {
							match self.send_packet(&vec![],&vec![0x15],&vec![],&received_packet.crypt_tag,&source_address) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							let mut reject_reason:&str = "unspecified reason";
							if !received_packet.valid {
								reject_reason = "signature invalid";
								if let Some(points) = self.ban_points.get_mut(&source_address.ip()) {
									*points += 1;
								}
							} else if self.subscribers.len() >= self.max_subscribers {
								reject_reason = "server full";
							}
							self.event_stream.push_back(Event::ServerSubscribeFailure{
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:source_address.clone(),
								reason:reject_reason.to_owned(),
								timestamp:Local::now(),
							});
						}
					}
					if received_packet.parameter.len() > 0 {
						match (received_packet.parameter[0],received_packet.payload.len()) {
							(0x06,8)|(0x06,16)|(0x03,16) => {
								let mut acked_hash:[u8;8] = [0;8];
								acked_hash.copy_from_slice(&received_packet.payload[..8]);
								let mut ack_origin:Option<SocketAddr> = None;
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									match sub.unacked_packets.remove(&acked_hash) {
										None => (),
										Some(packet) => {
											ack_origin = Some(packet.source.clone());
										},
									};
								}
								let mut ack_matches:u64 = 0;
								if received_packet.payload.len() == 16 {
									let mut match_count_bytes:[u8;8] = [0;8];
									match_count_bytes.copy_from_slice(&received_packet.payload[8..]);
									ack_matches = bytes_to_u64(&match_count_bytes);
									if let Some(origin) = ack_origin {
										match self.send_raw(&received_packet.raw,&origin) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
								self.event_stream.push_back(Event::Acknowledge {
									sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
									address:source_address.clone(),
									hash:acked_hash.to_vec(),
									matches:ack_matches,
									timestamp:Local::now(),
								});
							},
							(0x06,_) => {
								self.event_stream.push_back(Event::Acknowledge {
									sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
									address:source_address.clone(),
									hash:Vec::new(),
									matches:0,
									timestamp:Local::now(),
								});
							},
							(0x02,8) => {
								match self.send_packet(&vec![],&vec![0x06],&vec![],&received_packet.crypt_tag,&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
							},
							(0x18,0) => {
								if let Some(cancelled_sub) = self.subscribers.remove(&source_address) {
									let _ = self.identities_in_use.remove(&cancelled_sub.identity.tag);
								}
								match self.send_packet(&vec![],&vec![0x19],&vec![],&received_packet.crypt_tag,&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
								self.event_stream.push_back(Event::ServerSubscribe {
									sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
									address:source_address.clone(),
									timestamp:Local::now(),
								});
							},
							(b'>',_) => {
								if received_packet.valid {
									self.event_stream.push_back(Event::ReceiveMessage {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										parameter:received_packet.parameter.clone(),
										payload:received_packet.payload.clone(),
										timestamp:Local::now(),
									});
									self.receive_queue.push_back(received_packet);
								} else {
									self.event_stream.push_back(Event::InvalidMessage {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										parameter:received_packet.parameter.clone(),
										payload:received_packet.payload.clone(),
										reason:String::from("signature invalid"),
										timestamp:Local::now(),
									});
								}
							},
							(_,_) => (),
						}; // match message[0]
					} // if message.len > 0
				}, // recvfrom ok
			}; // match recvfrom
			if self.synchronous {
				break;
			}
		}
		return Ok(());
	}

	pub fn resend_unacked(&mut self) -> Result<(),io::Error> {
		let now:i64 = Local::now().timestamp_millis();
		for sub in self.subscribers.clone().values() {
			// retransmit packets that haven't been acknowledged and were last sent a while ago.
			if sub.unacked_packets.len() > self.max_unsent_packets {
				if let Some(mut list_sub) = self.subscribers.get_mut(&sub.address) {
					list_sub.unacked_packets.clear();
				}
				if let Some(cancelled_sub) = self.subscribers.remove(&sub.address) {
					let _ = self.identities_in_use.remove(&cancelled_sub.identity.tag);
				}
				match self.send_packet(&vec![],&vec![0x19],&vec![],&sub.identity.tag,&sub.address) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				let client_name:String = format!("@{}/#{}",&sub.identity.name,&sub.identity.classes[0]);
				self.event_stream.push_back(Event::ServerUnsubscribe {
					sender:client_name.clone(),
					address:sub.address.clone(),
					reason:String::from("maximum send queue length exceeded"),
					timestamp:Local::now(),
				});
				continue;
			}
			if sub.delivery_failures > self.max_resend_failures {
				if let Some(cancelled_sub) = self.subscribers.remove(&sub.address) {
					let _ = self.identities_in_use.remove(&cancelled_sub.identity.tag);
				}
				match self.send_packet(&vec![],&vec![0x19],&vec![],&sub.identity.tag,&sub.address) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				let client_name:String = format!("@{}/#{}",&sub.identity.name,&sub.identity.classes[0]);
				self.event_stream.push_back(Event::ServerUnsubscribe {
					sender:client_name.clone(),
					address:sub.address.clone(),
					reason:String::from("maximum resend failure count exceeded"),
					timestamp:Local::now(),
				});
				continue;
			}
			for unacked_packet in sub.unacked_packets.iter() {
				let packet_hash:&[u8;8] = &unacked_packet.0;
				let packet_bottle:&Vec<u8> = &unacked_packet.1.raw;
				let packet_timestamp:&i64 = &unacked_packet.1.timestamp;
				let packet_tries:&u64 = &unacked_packet.1.tries;
				// if the packet's timestamp is a while ago, resend it.
				if *packet_timestamp < now-self.time_tolerance_ms {
					match self.send_raw(&packet_bottle,&sub.address) {
						Err(why) => return Err(why),
						Ok(_) => (),
					};
					// after resending a packet, update its timestamp in the original subscriber list.
					if let Some(list_sub) = self.subscribers.get_mut(&sub.address) {
						if packet_tries < &self.max_resend_tries {
							if let Some(list_packet) = list_sub.unacked_packets.get_mut(packet_hash) {
								list_packet.tries += 1;
								list_packet.timestamp = Local::now().timestamp_millis();
							}
							self.event_stream.push_back(Event::DeliveryRetry {
								destination:String::from_utf8_lossy(&unacked_packet.1.recipient).to_string(),
								address:sub.address.clone(),
								parameter:unacked_packet.1.parameter.clone(),
								payload:unacked_packet.1.payload.clone(),
								timestamp:Local::now(),
							});
						} else {
							list_sub.unacked_packets.remove(packet_hash);
							list_sub.delivery_failures += 1;
							self.event_stream.push_back(Event::DeliveryFailure {
								destination:String::from_utf8_lossy(&unacked_packet.1.recipient).to_string(),
								address:sub.address.clone(),
								parameter:unacked_packet.1.parameter.clone(),
								payload:unacked_packet.1.payload.clone(),
								reason:String::from("maximum resend failure count exceeded"),
								timestamp:Local::now(),
							});
						}			
					}
				}
			}
		}
		return Ok(());
	}

	pub fn relay_packet(&mut self,packet:&Packet) -> Result<(),io::Error> {
		if !packet.valid {
			return Err(io::Error::new(io::ErrorKind::InvalidData,"cannot relay invalid packet"));
		}
		if packet.parameter.len() < 1 {
			return Err(io::Error::new(io::ErrorKind::InvalidData,"cannot relay packet with missing parameter"));
		}
		let mut packet_hash:[u8;8] = [0;8];
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&packet.raw);
		sha3.finalize(&mut packet_hash);
		if self.recent_packets.contains(&packet_hash) {
			self.event_stream.push_back(Event::HaltedMessage {
				sender:String::from_utf8_lossy(&packet.sender).to_string(),
				address:packet.source.clone(),
				parameter:packet.parameter.clone(),
				payload:packet.payload.clone(),
				timestamp:Local::now(),
			});
			return Ok(());
		}
		let send:bool = packet.payload.len() > 0;
		let mut number_matched:u64 = 0;
		for server_address in self.linked_servers.clone().keys() {
			if &packet.source != server_address && packet.parameter.len() >= 1 && [0x0F,0x0E,b'>'].contains(&&packet.parameter[0]) {
				match self.send_packet(&packet.sender,&packet.parameter,&packet.payload,&packet.crypt_tag,&server_address) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				if packet.parameter[0] == b'>' {
					self.event_stream.push_back(Event::RoutedMessage {
						destination:String::from_utf8_lossy(&packet.sender).to_string(),
						address:packet.source.clone(),
						parameter:packet.parameter.clone(),
						payload:packet.payload.clone(),
						timestamp:Local::now(),
					});
				} else if packet.parameter[0] == 0x0E {
					self.event_stream.push_back(Event::RoutedFile {
						destination:String::from_utf8_lossy(&packet.sender).to_string(),
						address:packet.source.clone(),
						parameter:packet.parameter.clone(),
						filename:String::from_utf8_lossy(&packet.payload).to_string(),
						timestamp:Local::now(),
					});
				}
			}
		}
		for sub in self.subscribers.clone().values() {
			let mut subscriber_identifiers:String = String::new();
			subscriber_identifiers.push_str(&format!("@{} ",&sub.identity.name));
			for class in sub.identity.classes.iter() {
				subscriber_identifiers.push_str(&format!("#{} ",&class));
			}
			if packet.source != sub.address && packet.parameter.len() >= 1 && [0x0F,0x0E,b'>'].contains(&&packet.parameter[0])
				&& (wordmatch(&String::from_utf8_lossy(&packet.parameter[1..]).to_string(),&subscriber_identifiers) 
				|| sub.identity.classes.contains(&"supervisor".to_owned())) {
				if send {
					match self.send_packet(&packet.sender,&packet.parameter,&packet.payload,&sub.identity.tag,&sub.address) {
						Err(why) => return Err(why),
						Ok(_) => (),
					};
					let recipient:String = format!("@{}/#{}",&sub.identity.name,&sub.identity.classes[0]);
					if packet.parameter[0] == b'>' {
						self.event_stream.push_back(Event::RoutedMessage {
							destination:recipient,
							address:sub.address.clone(),
							parameter:packet.parameter.clone(),
							payload:packet.payload.clone(),
							timestamp:Local::now(),
						});
					} else if packet.parameter[0] == 0x0E {
						self.event_stream.push_back(Event::RoutedFile {
							destination:recipient,
							address:sub.address.clone(),
							parameter:packet.parameter.clone(),
							filename:String::from_utf8_lossy(&packet.payload).to_string(),
							timestamp:Local::now(),
						});
					}
					self.recent_packets.push_back(packet_hash.clone());
					while self.recent_packets.len() > self.max_recent_packets {
						let _ = self.recent_packets.pop_front();
					}
					if let Some(mut listed_sub) = self.subscribers.get_mut(&sub.address) {
						let recipient:String = format!("@{}/#{}",listed_sub.identity.name,listed_sub.identity.classes[0]);
						listed_sub.unacked_packets.insert(packet_hash.clone(),UnackedPacket {
							raw:packet.raw.clone(),
							decrypted:packet.payload.clone(),
							timestamp:Local::now().timestamp_millis(),
							tries:0,
							source:packet.source.clone(),
							destination:listed_sub.address.clone(),
							recipient:recipient.as_bytes().to_vec(),
							parameter:packet.parameter.clone(),
							payload:packet.payload.clone(),
						});
					}
				}	
				number_matched += 1;
			}
			let mut ack_payload:Vec<u8> = Vec::new();
			ack_payload.append(&mut packet_hash.to_vec());
			if send {
				ack_payload.append(&mut u64_to_bytes(&1).to_vec());
				match self.send_packet(&vec![],&vec![0x06],&ack_payload,&packet.crypt_tag,&packet.source) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
			} else {
				ack_payload.append(&mut u64_to_bytes(&number_matched).to_vec());
				sleep(Duration::new(self.ack_fake_lag_ms/1000,(self.ack_fake_lag_ms as u32)%1000));
				match self.send_packet(&vec![],&vec![0x03],&ack_payload,&packet.crypt_tag,&packet.source) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
			}
		}
		if !send {
			self.event_stream.push_back(Event::TestMessage {
				sender:String::from_utf8_lossy(&packet.sender).to_string(),
				address:packet.source.clone(),
				parameter:packet.parameter.clone(),
				matches:number_matched,
				timestamp:Local::now(),
			});
		} else if number_matched == 0 {
			self.event_stream.push_back(Event::DeadEndMessage {
				sender:String::from_utf8_lossy(&packet.sender).to_string(),
				address:packet.source.clone(),
				parameter:packet.parameter.clone(),
				payload:packet.payload.clone(),
				timestamp:Local::now(),
			});
		} 
		return Ok(());
	}

} // impl Server
