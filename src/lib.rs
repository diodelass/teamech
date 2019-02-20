// Teamech v 0.12.1 November 2018
// rustc v. 1.31.1
// License: AGPL v3

// Editor Recommendations
// - Font type: monospace
// - Tab width: 2 chars
// - Window width: 160 chars

/*
-- What we're working on now --

Problem:
Multipacket transmissions should stop when there are no recipients available or all have aborted the receive operation.

Plan: 
Server keeps track of all transmissions.
Server stops relaying packets from a transmission to clients that have previously nakked the transmission.
If all matching clients nak the transmission, then the server returns 0x03 and the transmitting client stops transmitting.

Done So Far:
- server now has a structure to keep track of transmissions

*/

/*
-- Feature Outline --

Functionality														Implemented

I. Network
	A. UDP																		[X]
		1. Sending															[X]
		2. Receiving														[X]
		3. WAN Links/Holepunching								[-]
	B. Addresses															[X]
		1. IPv4																	[X]
		2. IPv6																	[X]
		3. DNS resolution												[-]
	C. Bulk data/file transfers								[X]
		1. Transmission													[X]
		2. Reception														[X]
II. Server																		
	A. Connections														[X]
		1. Acceptance														[X]
		2. Cancellation													[X]
			a. Upon request												[X]
			b. Upon absence												[X]
		3. Banning															[X]
		4. Identifiers													[X]
			a. Names (unique)											[X]
				i. Setting													[X]
				ii. Changing												[-]
			b. Classes (nonunique)								[X]
				i. Setting													[X]
				ii. Unsetting												[-]
	B. Relaying																[X]
		1. To all clients												[X]
		2. To specific clients									[X]
		3. To sets of clients										[X]
		4. To other servers											[-]
		5. Handling acknowledgements						[X]
			a. Resending													[X]
			b. Relaying acks back to source				[X]
	C. Server-Server Links										[X]
		1. Opening															[X] 
		2. Closing															[X]
III. Client																	
	A. Connecting															[X]
		1. Opening connection										[X]
		2. Closing connection										[X]
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

/* Overview of Control Codes
0x01 - START OF HEADING - Unassigned
0x02 - START OF TEXT - Connection request
0x03 - END OF TEXT - Match test response
0x04 - END OF TRANSMISSION - Connected client list response
0x05 - ENQUIRY - Connected client list request
0x06 - ACKNOWLEDGE - Acknowledge
0x07 - BELL
0x08 - BACKSPACE
0x09 - CHARACTER TABULATION
0x0A - LINE FEED
0x0B - LINE TABULATION
0x0C - FORM FEED
0x0D - CARRIAGE RETURN
0x0E - SHIFT OUT - Supervisory disconnect notification
0x0F - SHIFT IN - Supervisory connect notification
0x10 - DATA LINK ESCAPE - Unassigned
0x11 - DEVICE CONTROL ONE - Server link request
0x12 - DEVICE CONTROL TWO - Remote connect
0x13 - DEVICE CONTROL THREE - Remote disconnect
0x14 - DEVICE CONTROL FOUR - Unassigned
0x15 - NEGATIVE ACKNOWLEDGE - Refusal
0x16 - SYNCHRONOUS IDLE - Unassigned
0x17 - END OF TRANSMISSION BLOCK - Unassigned
0x18 - CANCEL - Connection cancellation
0x19 - END OF MEDIUM - Connection dismissal
0x1A - SUBSTITUTE - Unassigned
0x1B - ESCAPE - Unassigned
0x1C - FILE SEPARATOR - Request to start bulk transfer
0x1D - GROUP SEPARATOR - Clearance to start bulk transfer
0x1E - RECORD SEPARATOR - Bulk transfer segment
0x1F - UNIT SEPARATOR - Unassigned
*/

extern crate tiny_keccak;
use tiny_keccak::Keccak;

extern crate time;
use time::{Timespec,Tm,now_utc,strftime};

use std::io::prelude::*;
use std::io;
use std::fs::{File,read_dir,create_dir_all};
use std::path::Path;
use std::collections::{VecDeque,HashMap,HashSet};
use std::time::Duration;
use std::net::{UdpSocket,SocketAddr,IpAddr,Ipv4Addr};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash,Hasher};

fn print_time(now:&Tm) -> String {
	let mut micros:String = format!("{}",now.tm_nsec/1_000);
	while micros.len() < 6 {
		micros = format!("0{}",micros);
	}
	return format!("{}.{}Z",strftime("%Y-%m-%dT%H:%M:%S",&now).unwrap(),micros);
}

// These functions convert between arrays of eight bytes and 64-bit ints.
// They are used for creating and parsing numerical data from received bytes.
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
fn bytes_to_i64(bytes:&[u8]) -> i64 {
	if bytes.len() < 8 {
		return 0;
	}
	let mut number:i64 = 0;
	for x in 0..8 {
		number += (bytes[x] as i64) << (8*x)
	}
	return number;
}
fn bytes_to_u64(bytes:&[u8]) -> u64 {
	if bytes.len() < 8 {
		return 0;
	}
	let mut number:u64 = 0;
	for x in 0..8 {
		number += (bytes[x] as u64) << (8*x)
	}
	return number;
}

fn internal_hash(bytes:&[u8]) -> Vec<u8> {
	// uses SipHash, Rust's current default hasher
	let mut hasher = DefaultHasher::new();
	bytes.hash(&mut hasher);
	return u64_to_bytes(&hasher.finish()).to_vec();
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

fn milliseconds_now() -> i64 {
	let now:Timespec = now_utc().to_timespec();
	return now.sec*1000 + (now.nsec as i64)/1000000;
}

// converts bytes into a hex string in the form xx.xx.xx.xx.
fn bytes_to_hex(v:&[u8]) -> String {
	let mut result:String = String::from("");
	for x in 0..v.len() {
		if v[x] == 0x00 {
			result.push_str(&format!("00"));
		} else if v[x] < 0x10 {
			result.push_str(&format!("0{:x}",v[x]));
		} else {
			result.push_str(&format!("{:x}",v[x]));
		}
		if x < v.len()-1 {
			result.push_str(".");
		}
	}
	return result;
}

// given bytes, produces a hex string of at most the first two bytes.
// used instead of bytes_to_hex() for creating human-readable short identifiers.
fn bytes_to_tag(v:&[u8]) -> String {
	if v.len() > 2 {
		return bytes_to_hex(&v[..2]);
	} else {
		return bytes_to_hex(&v);
	}
}

// given some bytes, produces either a UTF-8 decoding or, if the decoding fails,
// a hex string.
fn view_bytes(v:&[u8]) -> String {
	if v.len() == 0 {
		return String::new();
	}
	if v[0] <= 0x1F {
		return bytes_to_hex(&v);
	}
	match String::from_utf8(v.to_vec()) {
		Err(_) => return bytes_to_hex(&v),
		Ok(string) => return string,
	};
}

// This function accepts a boolean expression in the form `(foo|bar)&baz` and determines 
// if it matches a string of words in the form `foo bar baz`
// edge cases:
// - an empty pattern will always return true
// - a malformed or unparseable pattern will return false
// - words containing boolean operators cannot be matched and should not be included
fn wordmatch(pattern:&str,input:&str) -> bool {
	if pattern == "" {
		// handle true-returning edge cases first, for speed
		return true;
	}
	let paddedinput:&str = &format!(" {} ",input);
	if paddedinput.contains(&format!(" {} ",pattern)) {
		return true;
	}
	let ops:Vec<&str> = vec!["/","!","&","|","^","(",")"];
	let mut spacedpattern:String = String::from(pattern);
	let mut boolpattern:String = String::new();
	for c in ops.iter() {
		// first, pad all the operators with spaces to make them come up as their own elements
		// when the string is split on whitespace.
		spacedpattern = spacedpattern.replace(c,&format!(" {} ",c));
	}
	for element in spacedpattern.clone().split_whitespace() {
		// replace all the terms of the expression with "1" or "0" depending on whether they 
		// individually match the input.
		let paddedelement:&str = &format!(" {} ",element);
		if ops.contains(&element) {
			boolpattern.push_str(&element);
		} else {
			if paddedinput.contains(&paddedelement) {
				boolpattern.push_str("1");
			} else {
				boolpattern.push_str("0");
			}
		}
	}
	if bool_eval(&boolpattern) == Some(true) {
		return true;
	} else {
		return false;
	}
}

// helper function for wordmatch(), handling actual expression evaluation
fn bool_eval(exp:&str) -> Option<bool> {
	let mut operators:Vec<char> = Vec::new();
	let mut values:Vec<bool> = Vec::new();
	let exp_chars:Vec<char> = exp.chars().collect();
	for c in exp_chars.iter() {
		match c {
			' ' => (),
			'(' => (),
			'&'|'/'|'|'|'^'|'!' => operators.push(*c),
			'1'|'0' => match operators.last() {
				Some('!') => {
					match c {
						'1' => values.push(false),
						'0' => values.push(true),
						_ => continue,
					};
					let _ = operators.pop();
				},
				_ => match c {
					'1' => values.push(true),
					'0' => values.push(false),
					_ => (),
				},
			},
			')' => {
				let operator:char = match operators.pop() {
					Some(c) => c,
					_ => break,
				};
				let value1:bool = match values.pop() {
					Some(b) => b,
					_ => break,
				};
				let value2:bool = match values.pop() {
					Some(b) => b,
					_ => {
						values.push(value1);
						break;
					},
				};
				values.push(match operator {
					'&' => match (value1,value2) {
						(true,true) => true,
						(true,false) => false,
						(false,true) => false,
						(false,false) => false,
					},
					'|'|'/' => match (value1,value2) {
						(true,true) => true,
						(true,false) => true,
						(false,true) => true,
						(false,false) => false,
					},
					'^' => match (value1,value2) {
						(true,true) => false,
						(true,false) => true,
						(false,true) => true,
						(false,false) => false,
					},
					_ => break,
				});
			},
			_ => (),
		};
	}
	while values.len() >= 2 && operators.len() >= 1 {
		if let (Some(value1),Some(value2),Some(operator)) = (values.pop(),values.pop(),operators.pop()) {
			values.push(match operator {
				'&'|'/' => match (value1,value2) {
					(true,true) => true,
					(true,false) => false,
					(false,true) => false,
					(false,false) => false,
				},
				'|' => match (value1,value2) {
					(true,true) => true,
					(true,false) => true,
					(false,true) => true,
					(false,false) => false,
				},
				'^' => match (value1,value2) {
					(true,true) => false,
					(true,false) => true,
					(false,true) => true,
					(false,false) => false,
				},
				_ => break,
			});
		}
	}
	if values.len() == 1 {
		return Some(values[0]);
	} else {
		return None;
	}
}

// The primary method by which Teamech data is passed from the library functions to 
// the implementation is by the event stream. Calling certain library functions will
// add data to the even stream queue, which can be emptied by implementation functions.
pub enum Event {
	Acknowledge {
		// server or client sent back an acknowledgement to something we transmitted.
		sender:String,
		address:SocketAddr,
		hash:Vec<u8>,
		matches:u64,
		timestamp:Tm,
	},
	Refusal {
		// server or client has refused to respond to something transmitted to it, e.g. because
		// the request was malformed, unknown, or forbidden.
		sender:String,
		address:SocketAddr,
		hash:Vec<u8>,
		timestamp:Tm,
	},
	ServerCreate {
		// server object instantiated.
		address:SocketAddr,
		timestamp:Tm,
	},
	ClientCreate {
		// client object instantiated.
		address:SocketAddr,
		timestamp:Tm,
	},
	ServerConnect {
		// we're a server, and a client just connected to us.
		sender:String,
		address:SocketAddr,
		timestamp:Tm,
	},
	ClientConnect {
		// we're a client, and we just connected to a server.
		sender:String,
		address:SocketAddr,
		timestamp:Tm,
	},
	RemoteConnect {
		// we're a server, and we just got word that a client connected to a server elsewhere in the network.
		sender:String,
		server:String,
		timestamp:Tm,
	},
	RemoteDisconnect {
		// we're a server, and we just got word that a client disconnected from a server elsewhere on the network.
		sender:String,
		server:String,
		timestamp:Tm,
	},
	ServerConnectFailure {
		// we're a server, and the connection process for a client just failed for some reason.
		sender:String,
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ClientConnectFailure {
		// we're a client, and the connection process for a client just failed for some reason.
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ServerDisconnect {
		// we're a server, and a client has just been disconnected.
		sender:String,
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ClientDisconnect {
		// we're a client, and we've just been disconnected.
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ClientDisconnectFailure {
		// we're a client, and something went wrong while disconnecting.
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ServerLinkSend {
		// we're a server, and we're attempting to connect to another server.
		address:SocketAddr,
		timestamp:Tm,
	},
	ServerLinkReceive {
		// we're a server, and another server has connected to us.
		sender:String,
		address:SocketAddr,
		timestamp:Tm,
	},
	ServerUnlinkSend {
		// we're a server, and we're terminating a link to another server.
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ServerUnlinkReceive {
		// we're a server, and we've received a termination notice for this connection.
		sender:String,
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	ReceivePacket {
		// we've just received some kind of packet.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		hash:Vec<u8>,
		timestamp:Tm,
	},
	ReceiveMessage {
		// the packet we just received is  a message.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		hash:Vec<u8>,
		timestamp:Tm,
	},
	ReceiveFailure {
		// we've tried to receive a packet, but failed.
		reason:String,
		timestamp:Tm,
	},
	SendPacket { 
		// we've just transmitted a packet of some kind.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		hash:Vec<u8>,
		timestamp:Tm,
	},
	SendMessage {
		// we've transmitted a packet containing a message.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		hash:Vec<u8>,
		timestamp:Tm,
	},
	SendFailure {
		// we tried to send a packet, but it failed.
		destination:String,
		address:SocketAddr,
		reason:String,
		timestamp:Tm,
	},
	BeginSendTransmission {
		destination:String,
		size:usize,
		id:Vec<u8>,
		timestamp:Tm,
	},
	EndSendTransmission {
		destination:String,
		size:usize,
		id:Vec<u8>,
		timestamp:Tm,
	},
	FailedSendTransmission {
		destination:String,
		size:usize,
		id:Vec<u8>,
		reason:String,
		timestamp:Tm,
	},
	BeginReceiveTransmission {
		sender:String,
		size:usize,
		id:Vec<u8>,
		timestamp:Tm,
	},
	EndReceiveTransmission {
		sender:String,
		size:usize,
		data:Vec<u8>,
		id:Vec<u8>,
		timestamp:Tm,
	},
	TestMessage {
		// we're a server and we've just received a packet that has a routing expression, but no payload.
		// this means that it's a test packet that shouldn't actually be relayed.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		matches:u64,
		timestamp:Tm,
	},
	TestResponse {
		// we've received a response to a test packet.
		sender:String,
		address:SocketAddr,
		hash:Vec<u8>,
		matches:u64,
		timestamp:Tm,
	},
	RoutedMessage {
		// we're a server and we've relayed a packet that was sent by a client.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:Tm,
	},
	InvalidMessage {
		// we've received a message that isn't of the expected structure or has a bad signature.
		sender:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		reason:String,
		timestamp:Tm,
	},
	NullDecrypt {
		// we've decrypted a packet using the null key, which isn't secure. 
		// this is done when two nodes need to talk to each other, but don't have any keys in common.
		address:SocketAddr,
		timestamp:Tm,
	},
	NullEncrypt {
		// we've encrypted a packet using the null key, which isn't secure.
		address:SocketAddr,
		timestamp:Tm,
	},
	DeliveryRetry {
		// we're a server and we're trying again to deliver a packet to a client.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		timestamp:Tm,
	},
	DeliveryFailure {
		// we're a server and we're giving up trying to deliver a message to a client who isn't responding.
		destination:String,
		address:SocketAddr,
		parameter:Vec<u8>,
		payload:Vec<u8>,
		reason:String,
		timestamp:Tm,
	},
	ClientListRequest {
		// we're a server and a client is trying to get a list of connections.
		sender:String,
		address:SocketAddr,
		timestamp:Tm,
	},
	ClientListResponse {
		// we're a server and we're answering a client's connector list request.
		sender:String,
		address:SocketAddr,
		payload:String,
		timestamp:Tm,
	},
	ClientListEnd {
		// we're a server or a client and this is the end of the client list.
		sender:String,
		address:SocketAddr,
		timestamp:Tm,
	},
	IdentityLoad {
		// we've successfully loaded an identity from a file.
		filename:String,
		name:String,
		classes:Vec<String>,
		tag:Vec<u8>,
		timestamp:Tm,
	},
	IdentityLoadFailure {
		// we've failed to load an identity from a file.
		filename:String,
		reason:String,
		timestamp:Tm,
	},
	UnknownSender {
		// someone tried to send us a message, but their identity tag matches none we have on file.
		address:SocketAddr,
		timestamp:Tm,
	},
}

impl Event {

	// formats the event as a human-readable string that can be printed to the console and/or written to log files.
	pub fn to_string(&self) -> String {
		match self {
			Event::Acknowledge {timestamp,hash,sender,address,matches} => {
				if matches > &0 {
					return format!("[{}] ack [{}] - {} [{}] ({})",print_time(&timestamp),bytes_to_tag(&hash),sender,address,matches);
				} else {
					return format!("[{}] ack [{}] - {} [{}]",print_time(&timestamp),bytes_to_tag(&hash),sender,address);
				}
			},
			Event::Refusal {timestamp,hash,sender,address} => {
				return format!("[{}] nak [{}] - {} [{}]",print_time(&timestamp),bytes_to_tag(&hash),sender,address);
			},
			Event::ServerCreate {timestamp,address} => {
				return format!("[{}] Server initialized on {}.",print_time(&timestamp),address);
			},
			Event::ClientCreate {timestamp,address} => {
				return format!("[{}] Client initialized on {}.",print_time(&timestamp),address);
			},
			Event::ServerConnect {timestamp,sender,address} => {
				return format!("[{}] Connection opened by {} [{}]",print_time(&timestamp),sender,address);
			},
			Event::ServerConnectFailure {timestamp,sender,address,reason} => {
				return format!("[{}] Rejected connection request from {} [{}]: {}",print_time(&timestamp),sender,address,reason);
			},
			Event::ServerDisconnect {timestamp,sender,address,reason} => {
				return format!("[{}] Connection closed for {} [{}] ({})",print_time(&timestamp),sender,address,reason);
			},
			Event::ClientConnect {timestamp,sender,address} => {
				return format!("[{}] Connected to server {} at [{}]",print_time(&timestamp),sender,address);
			},
			Event::ClientConnectFailure {timestamp,address,reason} => {
				return format!("[{}] Failed to connect to server at [{}]: {}",print_time(&timestamp),address,reason);
			},
			Event::ClientDisconnect {timestamp,address,reason} => {
				return format!("[{}] Disconnected from server at [{}]: {}",print_time(&timestamp),address,reason);
			},
			Event::ClientDisconnectFailure {timestamp,address,reason} => {
				return format!("[{}] Failed to disconnect from server at [{}]: {}",print_time(&timestamp),address,reason);
			},
			Event::RemoteConnect {timestamp,sender,server} => {
				return format!("[{}] Remote client {} has connected to server {}",print_time(&timestamp),sender,server);
			}
			Event::RemoteDisconnect {timestamp,sender,server} => {
				return format!("[{}] Remote client {} has disconnected from server {}",print_time(&timestamp),sender,server);
			}
			Event::ServerLinkSend {timestamp,address} => {
				return format!("[{}] {} <- Establishing server-to-server link",print_time(&timestamp),address);
			},
			Event::ServerLinkReceive {timestamp,sender,address} => {
				return format!("[{}] {} [{}] -> Received establishment of server-to-server link",print_time(&timestamp),sender,address);
			},
			Event::ServerUnlinkSend {timestamp,reason,address} => {
				return format!("[{}] {} <- Closing server-to-server link ({})",print_time(&timestamp),address,reason);
			},
			Event::ServerUnlinkReceive {timestamp,sender,reason,address} => {
				return format!("[{}] {} [{}] -> Received closure of server-to-server link ({})",print_time(&timestamp),sender,address,reason);
			},
			Event::ReceivePacket {timestamp,sender,address,parameter,payload,hash} => {
				return format!("[{}] recv({} [{}]): [{}] [{}] {}",print_time(&timestamp),sender,address,bytes_to_tag(&hash),
					view_bytes(&parameter),view_bytes(&payload));
			},
			Event::ReceiveMessage {timestamp,sender,address,parameter,payload,hash} => {
				return format!("[{}] {} [{}] -> [{}] [{}] {}",print_time(&timestamp),sender,address,bytes_to_tag(&hash),
					view_bytes(&parameter),view_bytes(&payload));
			},
			Event::ReceiveFailure {timestamp,reason} => {
				return format!("[{}] Could not receive packet: {}",print_time(&timestamp),reason);
			},
			Event::SendPacket {timestamp,destination,address,parameter,payload,hash} => {
				return format!("[{}] send({} [{}]): [{}] [{}] {}",print_time(&timestamp),destination,address,
					bytes_to_tag(&hash),view_bytes(&parameter),view_bytes(&payload));
			},
			Event::SendMessage {timestamp,destination,address,parameter,payload,hash} => {
				return format!("[{}] {} [{}] <- [{}] [{}] {}",print_time(&timestamp),destination,address,
					bytes_to_tag(&hash),view_bytes(&parameter),view_bytes(&payload));
			},
			Event::SendFailure {timestamp,destination,address,reason} => {
				return format!("[{}] Could not send packet to {} [{}]: {}",print_time(&timestamp),destination,address,reason);
			},
			Event::BeginSendTransmission {timestamp,destination,size,id} => {
				return format!("[{}] Sending transmission [{}] ({} blocks) to {}",print_time(&timestamp),view_bytes(&id),size,destination);
			},
			Event::EndSendTransmission {timestamp,destination,size,id} => {
				return format!("[{}] Finished sending transmission [{}] ({} blocks) to {}",print_time(&timestamp),view_bytes(&id),size,destination);
			},
			Event::FailedSendTransmission {timestamp,destination,size,id,reason} => {
				return format!("[{}] Failed to send transmission [{}] ({} blocks) to {}: {}",print_time(&timestamp),view_bytes(&id),size,destination,reason);
			},
			Event::BeginReceiveTransmission {timestamp,sender,size,id} => {
				return format!("[{}] Receiving transmission [{}] ({} blocks) from {}",print_time(&timestamp),view_bytes(&id),size,sender);
			},
			Event::EndReceiveTransmission {timestamp,sender,size,data:_,id} => {
				return format!("[{}] Finished receiving [{}] ({} blocks) from {}",print_time(&timestamp),view_bytes(&id),size,sender);
			},
			Event::TestMessage {timestamp,sender,address,parameter,matches} => {
				return format!("[{}] {} [{}] -> Match test: [{}] [matches {}]",print_time(&timestamp),sender,address,
					view_bytes(&parameter),matches);
			},
			Event::TestResponse {timestamp,sender,address,hash:_,matches} => {
				return format!("[{}] Match test response from {} [{}]: matches {}",print_time(&timestamp),sender,address,matches);
			},
			Event::RoutedMessage {timestamp,parameter,payload,destination,address} => {
				return format!("[{}] Relay: [{}] {} -> {} [{}]",print_time(&timestamp),
					view_bytes(&parameter),view_bytes(&payload),destination,address);
			},
			Event::InvalidMessage {timestamp,reason,sender,address,parameter,payload} => {
				return format!("[{}] [{}] {} [{}] -> [{}] {}",print_time(&timestamp),reason,sender,address,
					view_bytes(&parameter),view_bytes(&payload));
			},
			Event::DeliveryRetry {timestamp,parameter,payload,destination,address} => {
				return format!("[{}] [resending] [{}] {} -> {} [{}]",print_time(&timestamp),
					view_bytes(&parameter),view_bytes(&payload),destination,address);
			},
			Event::DeliveryFailure {timestamp,reason,parameter,payload,destination,address} => {
				return format!("[{}] [delivery failed: {}] [{}] {} -> {} [{}]",print_time(&timestamp),reason,
					view_bytes(&parameter),view_bytes(&payload),destination,address);
			},
			Event::ClientListRequest {timestamp,sender,address} => {
				return format!("[{}] client list requested by {} [{}]",print_time(&timestamp),sender,address);
			},
			Event::ClientListResponse {timestamp,sender:_,address:_,payload} => {
				return format!("[{}] client list - {}",print_time(&timestamp),payload);
			},
			Event::ClientListEnd {timestamp,sender,address} => {
				return format!("[{}] end of client list from {} [{}]",print_time(&timestamp),sender,address);
			},
			Event::IdentityLoad {timestamp,filename,name,classes,tag} => {
				return format!("[{}] found identity at {}: @{}/#{} [{}]",print_time(&timestamp),filename,name,classes[0],bytes_to_tag(&tag));
			},
			Event::IdentityLoadFailure {timestamp,filename,reason} => {
				return format!("[{}] failed to open identity file at {}: {}",print_time(&timestamp),filename,reason);
			},
			Event::NullEncrypt {timestamp,address} => {
				return format!("[{}] WARNING: sending unsecured message to {} due to missing keys!",print_time(&timestamp),address);
			},
			Event::NullDecrypt {timestamp,address} => {
				return format!("[{}] WARNING: receiving unsecured message from {} due to missing keys!",print_time(&timestamp),address);
			},
			Event::UnknownSender {timestamp,address} => {
				return format!("[{}] Alert: no identity found for message from {}",print_time(&timestamp),address);
			},
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
	pub hash:Vec<u8>,				// truncated sha3 hash of the raw packet
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
	pub timestamp:i64,						// when packet was last sent
	pub tries:u64,								// number of times this packet has had sending attempted
	pub source:SocketAddr,				// sender's socket address
	pub destination_hash:Vec<u8>,	// the hash of this packet as it is when sent to its destination
	pub origin_hash:Vec<u8>,			// the hash of the packet as it was when it was encrypted by its original sender
	pub destination:SocketAddr,		// recipient socket address
	pub sender:Vec<u8>,						// sender's identifier (@name/#class)
	pub recipient:Vec<u8>,				// recipient's identifier (@name/#class)
	pub parameter:Vec<u8>,				// message parameter (e.g. routing expression)
	pub payload:Vec<u8>,					// message payload
}

struct ReceivingTransmission {
	id:Vec<u8>,
	blocks_received:Vec<Vec<u8>>,
	blocks_needed:Vec<usize>,
	sender:Vec<u8>,
}

struct SendingTransmission {
	id:Vec<u8>,
	blocks:VecDeque<Vec<u8>>,
	length:usize,
	position:usize,
	routing_expression:Vec<u8>,
}

pub struct TransmissionStatus {
	pub id:Vec<u8>,
	pub length:usize,
	pub	current:usize,
	pub percent:u8,
	pub remote:String,
}

// object representing a Teamech client, with methods for sending and receiving packets.
pub struct Client {
	receiving_transmissions:HashMap<Vec<u8>,ReceivingTransmission>,	// contains the multi-packet transfers currently being received by the client.
	waiting_sending_transmissions:HashMap<Vec<u8>,SendingTransmission>, // transmissions that have not yet been cleared to send by the server
	sending_transmissions:VecDeque<SendingTransmission>,						// contains the multi-packet transfers currently being sent by the client.
	socket:UdpSocket,																								// local socket for transceiving data
	last_number_matched:VecDeque<([u8;8],u64)>,											// tracks ack match-count reporting
	unacked_packets:HashMap<Vec<u8>,UnackedPacket>,									// packets that need to be resent if they aren't acknowledged
	recent_packets:VecDeque<Vec<u8>>,																// hashes of packets that were recently seen, to merge double-sends
	pub address:SocketAddr,																					// this client's local address
	pub server_address:SocketAddr,																	// address of server we're connected to
	pub identity:Identity,																					// this client's identity
	pub connected:bool,																							// are we connected?
	pub event_stream:VecDeque<Event>,																// log of events produced by the client
	pub max_recent_packets:usize,																		// max number of recent packet hashes to store
	pub max_resend_tries:u64,																				// maximum number of tries to resend a packet before discarding it
	pub max_transmission_length:usize,															// maximum acceptible number of bytes in an incoming transmission (hint: set below mem limit)
	pub time_tolerance_ms:i64,																			// maximum time difference a packet can have from now
	pub simultaneous_transmissions:bool,														// whether or not multi-packet transmissions should be sent sequentially or simultaneously.
}

pub fn new_client(identity_path:&Path,server_address:&IpAddr,remote_port:u16,local_port:u16) -> Result<Client,io::Error> {
	let server_socket_address:SocketAddr = SocketAddr::new(*server_address,remote_port);
	let new_identity:Identity = match load_identity_file(&identity_path) {
		Err(why) => return Err(why),
		Ok(id) => id,
	};
	let local_bind_address:&str;
	if server_address.is_ipv6() {
		local_bind_address = "[::]";
	} else {
		local_bind_address = "0.0.0.0";
	}
	match UdpSocket::bind(&format!("{}:{}",&local_bind_address,&local_port)) {
		Err(why) => return Err(why),
		Ok(socket) => {
			let addr = socket.local_addr().unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)),0));
			let mut created_client = Client {
				socket:socket,
				address:addr.clone(),
				server_address:server_socket_address,
				event_stream:VecDeque::new(),
				last_number_matched:VecDeque::new(),
				connected:false,
				unacked_packets:HashMap::new(),
				recent_packets:VecDeque::new(),
				receiving_transmissions:HashMap::new(),
				waiting_sending_transmissions:HashMap::new(),
				sending_transmissions:VecDeque::new(),
				max_recent_packets:32,
				max_resend_tries:3,
				max_transmission_length:4294967295,
				identity:new_identity,
				time_tolerance_ms:3000,
				simultaneous_transmissions:true,
			};
			match created_client.set_recv_wait(1000) {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
			created_client.event_stream.push_back(Event::ClientCreate {
				address:addr,
				timestamp:now_utc(),
			});
			return Ok(created_client);
		},
	};
}

impl Client {

	// Set the duration of the socket timeout in microseconds. Longer delay will result in lower idle processor use,
	// but will reduce the rate at which other tasks are polled and executed.
	// About 1 ms (1000 us) is a decent starting point.
	pub fn set_recv_wait(&mut self,wait_time_us:u64) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(Some(Duration::new(wait_time_us/1000000,((wait_time_us%1000000)*1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn decrypt_packet(&mut self,bottle:&Vec<u8>,source_address:&SocketAddr) -> Packet {
		let now:i64 = milliseconds_now();
		let mut decrypted_bytes:Vec<u8> = Vec::new();
		let mut timestamp:i64 = 0;
		let mut message_valid:bool = false;
		let mut crypt_null:bool = false;
		let mut sender_bytes:Vec<u8> = Vec::new();
		let mut parameter_bytes:Vec<u8> = Vec::new();
		let mut payload_bytes:Vec<u8> = Vec::new();
		let mut hash_bytes:Vec<u8> = vec![0;8];
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
						timestamp:now_utc(),
					});
				}
			} else {
				hash_bytes = internal_hash(&bottle);
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
		}
		if timestamp > now+self.time_tolerance_ms || timestamp < now-self.time_tolerance_ms {
			message_valid = false;
		}
		return Packet {
			raw:bottle.clone(),
			decrypted:decrypted_bytes,
			hash:hash_bytes,
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

	pub fn get_event(&mut self) -> Result<Option<Event>,io::Error> {
		if let Some(event) = self.event_stream.pop_front() {
			return Ok(Some(event));
		}
		match self.process_packets() {
			Err(why) => return Err(why),
			Ok(_) => return Ok(self.event_stream.pop_front()),
		};
	}

	pub fn process_packets(&mut self) -> Result<(),io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		let mut recv_count:usize = 0;
		loop {
			recv_count += 1;
			if recv_count > 10000 || self.event_stream.len() > 1000 {
				// if we're processing a huge volume of packets at once, occasionally take a break
				// to allow other functions to run.
				break;
			}
			if let Some(mut transmission) = self.sending_transmissions.pop_front() {
				let mut parameter:Vec<u8> = vec![0x1E];
				parameter.append(&mut transmission.id.clone());
				parameter.append(&mut u64_to_bytes(&(transmission.position as u64)).to_vec());
				if let Some(block) = transmission.blocks.pop_front() {
					match self.send_packet(&parameter,&block) {
						Err(why) => return Err(why),
						Ok(_) => (),
					};
				}
				if transmission.blocks.len() > 0 {
					transmission.position = transmission.length-transmission.blocks.len();
					if self.simultaneous_transmissions {
						self.sending_transmissions.push_back(transmission);
					} else {
						self.sending_transmissions.push_front(transmission);
					}
				} else {
					self.event_stream.push_back(Event::EndSendTransmission {
						destination:String::from_utf8_lossy(&transmission.routing_expression).to_string(),
						size:transmission.length,
						id:transmission.id.clone(),
						timestamp:now_utc(),
					});
				}
			}
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => break,
					io::ErrorKind::Interrupted => break,
					_ => {
						self.event_stream.push_back(Event::ReceiveFailure {
							reason:format!("{}",why),
							timestamp:now_utc(),
						});
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					if source_address == self.server_address {
						let received_packet:Packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
						self.event_stream.push_back(Event::ReceivePacket {
							sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
							address:received_packet.source.clone(),
							parameter:received_packet.parameter.clone(),
							payload:received_packet.payload.clone(),
							hash:received_packet.hash.clone(),
							timestamp:now_utc(),
						});
						if self.recent_packets.contains(&received_packet.hash) {
							return Ok(());
						} else {
							self.recent_packets.push_back(received_packet.hash.clone());
							while self.recent_packets.len() > self.max_recent_packets {
								self.recent_packets.pop_front();
							}
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
									let _ = self.unacked_packets.remove(&acked_hash.to_vec());
									if received_packet.parameter[0] == 0x03 {
										self.event_stream.push_back(Event::TestResponse {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:source_address.clone(),
											matches:number_matched,
											hash:acked_hash.to_vec(),
											timestamp:now_utc(),
										});
									} else {
										self.event_stream.push_back(Event::Acknowledge {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:source_address.clone(),
											matches:number_matched,
											hash:acked_hash.to_vec(),
											timestamp:now_utc(),
										});
									}
								},
								(0x06,8) => {
									self.event_stream.push_back(Event::Acknowledge {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:source_address.clone(),
										matches:0,
										hash:received_packet.payload.clone(),
										timestamp:now_utc(),
									});
								}
								(0x06,_) => {
									self.event_stream.push_back(Event::Acknowledge {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:source_address.clone(),
										matches:0,
										hash:Vec::new(),
										timestamp:now_utc(),
									});
								}
								(0x19,0) => {
									self.event_stream.push_back(Event::ClientDisconnect {
										address:source_address.clone(),
										reason:String::from("connection terminated by server"),
										timestamp:now_utc(),
									});
									if self.connected { 
										match self.connect() {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
								(0x02,0) => {
									self.event_stream.push_back(Event::ClientConnect {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:self.server_address.clone(),
										timestamp:now_utc(),
									});
								}
								(0x04,0) => {
									self.event_stream.push_back(Event::ClientListEnd {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										timestamp:now_utc(),
									});
									match self.send_packet(&vec![0x06],&received_packet.hash) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								},
								(0x04,_) => {
									self.event_stream.push_back(Event::ClientListResponse {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										payload:String::from_utf8_lossy(&received_packet.payload).to_string(),
										timestamp:now_utc(),
									});
									match self.send_packet(&vec![0x06],&received_packet.hash) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								},
								(0x15,_) => {
									self.event_stream.push_back(Event::Refusal {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										hash:received_packet.payload.to_vec(),
										timestamp:now_utc(),
									});
								},
								(0x0F,0) => {
									self.event_stream.push_back(Event::ServerConnect {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										timestamp:now_utc(),
									});
								},
								(0x0F,_) => {
									self.event_stream.push_back(Event::ServerConnectFailure {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										reason:String::from_utf8_lossy(&received_packet.payload).to_string(),
										timestamp:now_utc(),
									});
								},
								(0x0E,_) => {
									self.event_stream.push_back(Event::ServerDisconnect {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										reason:String::from_utf8_lossy(&received_packet.payload).to_string(),
										timestamp:now_utc(),
									});
								},
								(0x1C,16) => {
									let transmission_id:Vec<u8> = received_packet.payload[..8].to_vec();
									let transmission_length:usize = bytes_to_u64(&received_packet.payload[8..].to_vec()) as usize;
									if transmission_length*400 > self.max_transmission_length {
										match self.send_packet(&vec![0x15],&received_packet.hash) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
										continue;
									}
									self.event_stream.push_back(Event::BeginReceiveTransmission {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										size:transmission_length,
										id:transmission_id.clone(),
										timestamp:now_utc(),
									});
									self.receiving_transmissions.insert(transmission_id.clone(),ReceivingTransmission {
										id:transmission_id.clone(),
										blocks_received:vec![vec![];transmission_length],
										blocks_needed:(0..transmission_length).collect(),
										sender:received_packet.sender.clone(),
									});
								},
								(0x1D,8) => {
									let transmission = match self.waiting_sending_transmissions.remove(&received_packet.payload) {
										None => continue,
										Some(transmission) => transmission,
									};
									self.sending_transmissions.push_front(transmission);
								},
								(0x1E,_) => {
									let transmission_id:Vec<u8> = received_packet.parameter[1..9].to_vec();
									let transmission_position:usize = bytes_to_u64(&received_packet.parameter[9..].to_vec()) as usize;
									let mut this_transmission = match self.receiving_transmissions.remove(&transmission_id) {
										None => {
											match self.send_packet(&vec![0x15],&received_packet.hash) {
												Err(why) => return Err(why),
												Ok(_) => (),
											};
											continue;
										},
										Some(transmission) => transmission,
									};
									if transmission_position < this_transmission.blocks_received.len() {
										this_transmission.blocks_received[transmission_position] = received_packet.payload.clone();
										if let Ok(n) = this_transmission.blocks_needed.binary_search(&transmission_position) {
											this_transmission.blocks_needed.remove(n);
										}
										match self.send_packet(&vec![0x06],&received_packet.hash) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									} else {
										match self.send_packet(&vec![0x15],&received_packet.hash) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
									if this_transmission.blocks_needed.len() > 0 {
										self.receiving_transmissions.insert(this_transmission.id.clone(),this_transmission);
									} else {
										self.event_stream.push_back(Event::EndReceiveTransmission {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											size:this_transmission.blocks_received.len(),
											data:this_transmission.blocks_received.concat(),
											id:transmission_id.clone(),
											timestamp:now_utc(),
										});
									}
								},
								(b'>',_) => {
									self.event_stream.push_back(Event::ReceiveMessage {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										parameter:received_packet.parameter.clone(),
										payload:received_packet.payload.clone(),
										hash:received_packet.hash.clone(),
										timestamp:now_utc(),
									});
									if received_packet.parameter.len() >= 26 && received_packet.parameter[1] == 0x01 {
									}
								},
								(_,_) => {
									self.event_stream.push_back(Event::InvalidMessage {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										parameter:received_packet.parameter.clone(),
										payload:received_packet.payload.clone(),
										reason:String::from("unknown parameter"),
										timestamp:now_utc(),
									});
									match self.send_packet(&vec![0x15],&received_packet.hash.clone()) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								},
							};
						} else if !received_packet.valid {
							self.event_stream.push_back(Event::InvalidMessage {
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:received_packet.source.clone(),
								parameter:received_packet.parameter.clone(),
								payload:received_packet.payload.clone(),
								reason:String::from("signature invalid"),
								timestamp:now_utc(),
							});
							match self.send_packet(&vec![0x15],&received_packet.hash.clone()) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
						} else {
							self.event_stream.push_back(Event::InvalidMessage {
								sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
								address:received_packet.source.clone(),
								parameter:received_packet.parameter.clone(),
								payload:received_packet.payload.clone(),
								reason:String::from("parameter missing"),
								timestamp:now_utc(),
							});
						}
					}
				},
			};
		}
		return Ok(());
	}

	pub fn get_transmission_status(&self) -> (Vec<TransmissionStatus>,Vec<TransmissionStatus>) {
		let mut receiving:Vec<TransmissionStatus> = Vec::new();
		for transmission in self.receiving_transmissions.values() {
			let transmission_length_bytes = transmission.blocks_received.len()*400;
			let transmission_current_bytes = (transmission.blocks_received.len()-transmission.blocks_needed.len())*400;
			let percent = ((transmission_current_bytes*100)/transmission_length_bytes) as u8;
			receiving.push(TransmissionStatus {
				id:transmission.id.clone(),
				length:transmission_length_bytes,
				current:transmission_current_bytes,
				percent:percent,
				remote:String::from_utf8_lossy(&transmission.sender).to_string(),
			});
		}
		let mut sending:Vec<TransmissionStatus> = Vec::new();
		for transmission in self.sending_transmissions.iter() {
			let transmission_length_bytes = transmission.length*400;
			let transmission_current_bytes = transmission.position*400;
			let percent = ((transmission_current_bytes*100)/transmission_length_bytes) as u8;
			sending.push(TransmissionStatus {
				id:transmission.id.clone(),
				length:transmission_length_bytes,
				current:transmission_current_bytes,
				percent:percent,
				remote:String::from_utf8_lossy(&transmission.routing_expression).to_string(),
			});
		}
		return (sending,receiving);
	}

	pub fn transmit_data(&mut self,routing_expression:&Vec<u8>,data:&Vec<u8>) -> Result<(),io::Error> {
		// max UDP payload size: 508 bytes
		// teacrypt overhead: 32 bytes
		// multi-packet ordering information overhead: 16 bytes
		// parameter: 1 byte
		// absolute maximum transmission block size (with zero-length routing expression): 459 bytes
		// safety margin: 59 bytes
		// block size: 400 bytes
		let block_size:usize = 400;
		// previously we used a scheme that involved putting the routing expression on every packet,
		// meaning that the transmission block size was variable.
		// that was kind of silly. the current plan is to have the server store the routing expression
		// and reference it using the transmission ID. 
		// now packets have a fixed overhead: 8 bytes of ID and 8 bytes of block position.
		if routing_expression.len() >= block_size {
			return Err(io::Error::new(io::ErrorKind::InvalidData,"routing expression too long"));
		}
		let mut transmission_id:Vec<u8> = vec![0;8];
		match get_rand_bytes(&mut transmission_id) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let mut blocks:VecDeque<Vec<u8>> = VecDeque::with_capacity(1+data.len()/block_size);
		for block in data.chunks(block_size) {
			blocks.push_back(block.to_vec());
		}
		let transmission_length = blocks.len();
		self.waiting_sending_transmissions.insert(transmission_id.clone(),SendingTransmission {
			id:transmission_id.clone(),
			blocks:blocks,
			position:0,
			length:transmission_length,
			routing_expression:routing_expression.clone(),
		});
		let mut routing_parameter:Vec<u8> = vec![0x1C];
		routing_parameter.append(&mut routing_expression.clone());
		let mut transmission_specs:Vec<u8> = Vec::new();
		transmission_specs.append(&mut transmission_id.clone());
		transmission_specs.append(&mut u64_to_bytes(&(transmission_length as u64)).to_vec());
		match self.send_packet(&routing_parameter,&transmission_specs) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		self.event_stream.push_back(Event::BeginSendTransmission {
			destination:String::from_utf8_lossy(&routing_expression).to_string(),
			size:transmission_length,
			id:transmission_id,
			timestamp:now_utc(),
		});
		return Ok(())
	}

	// encrypts and transmits a payload of bytes to the server.
	pub fn send_packet(&mut self,parameter:&Vec<u8>,payload:&Vec<u8>) -> Result<Vec<u8>,io::Error> {
		let mut message:Vec<u8> = Vec::new();
		message.push(0x00); // sender markings are redundant for client-to-server packets
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let bottle = match self.identity.encrypt(&message) {
			Err(why) => return Err(why),
			Ok(bytes) => bytes,
		};
		match self.send_raw(&bottle) {
			Err(why) => {
				self.event_stream.push_back(Event::SendFailure {
					destination:String::from("server"),
					address:self.server_address.clone(),
					reason:format!("{}",why),
					timestamp:now_utc(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		let packet_hash:Vec<u8> = internal_hash(&bottle);
		if parameter.len() > 0 && [b'>'].contains(&&parameter[0]) {
			self.event_stream.push_back(Event::SendMessage {
				destination:String::from("server"),
				address:self.server_address.clone(),
				parameter:parameter.clone(),
				payload:payload.clone(),
				hash:packet_hash.clone(),
				timestamp:now_utc(),
			});
			self.unacked_packets.insert(packet_hash.clone(),UnackedPacket {
				timestamp:milliseconds_now(),
				tries:0,
				source:self.server_address.clone(),
				destination_hash:packet_hash.clone(),
				origin_hash:packet_hash.clone(),
				destination:self.server_address.clone(),
				sender:b"local".to_vec(),
				recipient:b"server".to_vec(),
				parameter:parameter.clone(),
				payload:payload.clone(),
			});
		}
		self.event_stream.push_back(Event::SendPacket {
			destination:String::from("server"),
			address:self.server_address.clone(),
			parameter:parameter.clone(),
			payload:payload.clone(),
			hash:packet_hash.clone(),
			timestamp:now_utc(),
		});
		return Ok(packet_hash.clone());
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
		let now:i64 = milliseconds_now();
		for unacked_packet in self.unacked_packets.clone().values() {
			// if the packet's timestamp is a while ago, resend it.
			if unacked_packet.timestamp+self.time_tolerance_ms < now {
				match self.send_packet(&unacked_packet.parameter,&unacked_packet.payload) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				if unacked_packet.tries < self.max_resend_tries {
					if let Some(list_packet) = self.unacked_packets.get_mut(&unacked_packet.destination_hash) {
						list_packet.tries += 1;
						list_packet.timestamp = milliseconds_now();
					}
					self.event_stream.push_back(Event::DeliveryRetry {
						destination:String::from_utf8_lossy(&unacked_packet.recipient).to_string(),
						address:self.server_address.clone(),
						parameter:unacked_packet.parameter.clone(),
						payload:unacked_packet.payload.clone(),
						timestamp:now_utc(),
					});
				} else {
					let _ = self.unacked_packets.remove(&unacked_packet.destination_hash);
					self.event_stream.push_back(Event::DeliveryFailure {
						destination:String::from_utf8_lossy(&unacked_packet.recipient).to_string(),
						address:self.server_address.clone(),
						parameter:unacked_packet.parameter.clone(),
						payload:unacked_packet.payload.clone(),
						reason:String::from("maximum number of resend attempts exceeded"),
						timestamp:now_utc(),
					});
				}
			}
		}
		return Ok(());
	}

	pub fn get_response(&mut self,target_parameters:&Vec<u8>) -> Result<Vec<u8>,io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		let wait_start:i64 = milliseconds_now();
		let original_timeout:Option<Duration>;
		original_timeout = match self.socket.read_timeout() {
			Err(why) => return Err(why),
			Ok(t) => t,
		};
		match self.socket.set_read_timeout(Some(Duration::new((self.time_tolerance_ms/1000) as u64,(self.time_tolerance_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let response_payload:Vec<u8>;
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
					let _ = self.unacked_packets.remove(&received_packet.hash);
					if received_packet.parameter.len() > 0 && source_address == self.server_address {
						if target_parameters.contains(&received_packet.parameter[0]) {
							response_payload = received_packet.payload.clone();
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
			if milliseconds_now() > wait_start+self.time_tolerance_ms {
				return Err(io::Error::new(io::ErrorKind::NotFound,"no response"));
			}
		}
		match self.socket.set_read_timeout(original_timeout) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		return Ok(response_payload);
	}

	// transmits a connection request packet. server will return 0x06 if
	// we are already connected, 0x02 if we were not connected but are now,
	// 0x15 if something's wrong (e.g. server full) or an unreadable packet
	// if we have the wrong pad file.
	pub fn connect(&mut self) -> Result<(),io::Error> {
		let mut nonce_bytes:Vec<u8> = vec![0;8];
		match get_rand_bytes(&mut nonce_bytes[..]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		match self.send_packet(&vec![0x02],&nonce_bytes) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		match self.get_response(&vec![0x02,0x06]) {
			Err(why) => {
				self.event_stream.push_back(Event::ClientConnectFailure {
					address:self.server_address.clone(),
					reason:format!("{}",why),
					timestamp:now_utc(),
				});
				return Err(why);
			}
			Ok(_) => (),
		};
		self.connected = true;
		return Ok(());
	}

	// sends a cancellation of connection to the server. server will return
	// 0x19 if it hears us.
	pub fn disconnect(&mut self) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x18],&vec![]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		match self.get_response(&vec![0x19]) {
			Err(why) => {
				self.event_stream.push_back(Event::ClientDisconnectFailure {
					address:self.server_address.clone(),
					reason:format!("{}",why),
					timestamp:now_utc(),
				});
				return Err(why);
			}
			Ok(_) => (),
		};
		self.event_stream.push_back(Event::ClientDisconnect {
			address:self.server_address.clone(),
			reason:String::from("connection cancelled locally"),
			timestamp:now_utc(),
		});
		self.connected = false;
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

// generates a packet for transmission, but does not transmit it.
fn gen_packet(sender:&Vec<u8>,parameter:&Vec<u8>,payload:&Vec<u8>,
crypt_tag:&Vec<u8>,identities:&HashMap<Vec<u8>,Identity>) -> Result<(Vec<u8>,Vec<u8>),io::Error> {
	let mut message:Vec<u8> = Vec::new();
	message.push(sender.len() as u8);
	message.append(&mut sender.clone());
	message.push(parameter.len() as u8);
	message.append(&mut parameter.clone());
	message.append(&mut payload.clone());
	let bottle:Vec<u8>;
	if let Some(identity) = identities.get(crypt_tag) {
		bottle = match identity.encrypt(&message) {
			Err(why) => return Err(why),
			Ok(bytes) => bytes,
		};
	} else {
		return Err(io::Error::new(io::ErrorKind::NotFound,"corresponding key not found"));
	}
	let packet_hash:Vec<u8> = internal_hash(&bottle);
	return Ok((packet_hash,bottle));
}

impl Identity {

	pub fn encrypt(&self,message:&Vec<u8>) -> Result<Vec<u8>,io::Error> {
		let mut timestamped_message:Vec<u8> = message.clone();
		timestamped_message.append(&mut i64_to_bytes(&milliseconds_now()).to_vec());
		let mut nonce_bytes:Vec<u8> = vec![0;8];
		match get_rand_bytes(&mut nonce_bytes[..]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
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
		return Ok(bottle);
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

// connection object for tracking connected clients. constructed only by the
// receive_packets method when it receives a valid but unrecognized message 
// (not intended to be constructed directly).
#[derive(Clone)]
pub struct ClientConnection {
	pub address:SocketAddr,																	// socket address of client
	pub identity:Identity,																	// identity object corresponding to this connection
	pub unacked_packets:HashMap<Vec<u8>,UnackedPacket>,			// packets that need to be resent if they aren't acknowledged
	pub delivery_failures:u64,															// number of times a packet delivery has failed
}

#[derive(Clone)]
pub struct ServerConnection {
	pub address:SocketAddr,																		// socket address of other server
	pub identity:Identity,																		// this server's identity object
	pub remote_connections:HashMap<String,RemoteConnection>,	// client connections which can be accessed through this server
	pub unacked_packets:HashMap<Vec<u8>,UnackedPacket>,				// packets that need to be resent if they aren't acknowledged
}

#[derive(Clone)]
pub struct RemoteConnection {
	pub name:String,																			// this client's unique name
	pub classes:Vec<String>,															// this client's classes
	pub unacked_packets:HashMap<Vec<u8>,UnackedPacket>,		// the packets awaiting acknowledgement by this client
}

struct ServerTransmission {
	id:Vec<u8>,																	// this transmission's unique identifier
	origin:SocketAddr,													// the address of the transmitting client
	routing_expression:String,									// the routing expression used to select receivers
	length:usize,																// the number of blocks in this transmission
	blocks_needed:Vec<usize>,										// the blocks that have not yet been relayed 
	failed_recipients:HashSet<SocketAddr>,			// the recipients of this transmission who match the routing expression but have rejected it
}

// server object for holding server parameters and connections.
pub struct Server {
	socket:UdpSocket,																									// this server's UDP socket
	identities_in_use:HashSet<Vec<u8>>,																// registered identities which are already assigned and not available to new connections
	names_in_use:HashSet<String>,																			// identity names that are in use and not available to new connections
	recent_packets_deque:VecDeque<Vec<u8>>,														// packets recently seen, for filtering replays
	recent_packets_set:HashSet<Vec<u8>>,															// same contents as recent_packets_deque, but can be constant-time indexed
	relaying_transmissions:HashMap<Vec<u8>,ServerTransmission>,				// transmissions being relayed by this server
	pub name:String,																									// this server's unique name
	pub address:SocketAddr,																						// this server's socket address
	pub identity:Identity,																						// this server's identity, for connecting to other servers
	pub identities:HashMap<Vec<u8>,Identity>,													// identities this server has on file
	pub client_connections:HashMap<SocketAddr,ClientConnection>,			// clients connected to this server
	pub server_connections:HashMap<SocketAddr,ServerConnection>,			// other servers connected to this server
	pub unacked_packets:HashMap<Vec<u8>,UnackedPacket>,								// global unacked packets that can be acked by any connection
	pub max_connections:usize,																				// the most connections this server will allow before rejecting new connections
	pub ban_points:HashMap<IpAddr,u64>,																// ledger of misbehavior counts for each known IP address
	pub max_ban_points:u64,																						// threshold number of misbehavior events before banning an address
	pub banned_addresses:HashSet<IpAddr>,															// addresses banned for misbehavior
	pub max_recent_packets:usize,																			// maximum size of the recent packet list
	pub max_unsent_packets:usize,																			// maximum number of accumulated unsent packets before terminating a client connection
	pub max_resend_tries:u64,																					// maximum number of times to retry delivery of a packet before giving up
	pub max_resend_failures:u64,																			// maximum number of failed deliveries before terminating a client connection
	pub event_stream:VecDeque<Event>,																	// stream of Event objects describing server status and packet contents
	pub time_tolerance_ms:i64,																				// most time in the future or past a packet's timestamp can be and still be valid
}

// server constructor, works very similarly to client constructor
pub fn new_server(identity_file:&Path,port:&u16) -> Result<Server,io::Error> {
	match UdpSocket::bind(&format!("[::]:{}",port)) {
		Err(why) => return Err(why),
		Ok(socket) => {
			let addr = socket.local_addr().unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0,0,0,0)),0));
			let mut server_events:VecDeque<Event> = VecDeque::new();
			server_events.push_back(Event::ServerCreate {
				address:addr,
				timestamp:now_utc(),
			});
			let server_identity = match load_identity_file(identity_file) {
				Err(why) => {
					server_events.push_back(Event::IdentityLoadFailure {
						filename:format!("{}",identity_file.display()),
						reason:format!("{}",why),
						timestamp:now_utc(),
					});
					Identity {
						tag:vec![0;8],
						key:vec![0;32],
						name:String::from("server"),
						classes:vec![String::from("server")],
					}
				},
				Ok(id) => id,
			};
			let mut created_server = Server {
				name:server_identity.name.to_owned(),
				address:addr.clone(),
				socket:socket,
				client_connections:HashMap::new(),
				server_connections:HashMap::new(),
				relaying_transmissions:HashMap::new(),
				unacked_packets:HashMap::new(),
				identity:server_identity.clone(),
				identities:HashMap::new(),
				identities_in_use:HashSet::new(),
				names_in_use:HashSet::new(),
				max_connections:1024,
				ban_points:HashMap::new(),
				max_ban_points:10,
				banned_addresses:HashSet::new(),
				recent_packets_deque:VecDeque::new(),
				recent_packets_set:HashSet::new(),
				event_stream:VecDeque::new(),
				max_recent_packets:1024,
				max_unsent_packets:32,
				max_resend_tries:3,
				max_resend_failures:1,
				time_tolerance_ms:3000,
			};
			match created_server.set_recv_wait(1000) {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
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
								timestamp:now_utc(),
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
						timestamp:now_utc(),
					});
					self.identities.insert(new_identity.tag.clone(),new_identity);
				}
			}
		}
		return Ok(());
	}

	pub fn decrypt_packet(&mut self,bottle:&Vec<u8>,source_address:&SocketAddr) -> Packet {
		let now:i64 = milliseconds_now();
		let mut decrypted_bytes:Vec<u8> = Vec::new();
		let mut timestamp:i64 = 0;
		let mut message_valid:bool = false;
		let mut id_null:bool = false;
		let mut sender_bytes:Vec<u8> = Vec::new();
		let mut parameter_bytes:Vec<u8> = Vec::new();
		let mut payload_bytes:Vec<u8> = Vec::new();
		let hash_bytes:Vec<u8> = internal_hash(&bottle);
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
					timestamp:now_utc(),
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
			hash:hash_bytes,
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

	pub fn set_recv_wait(&mut self,wait_time_us:u64) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(Some(Duration::new(wait_time_us/1000000,((wait_time_us%1000000)*1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		}
	}

	pub fn get_response(&mut self,target_parameters:&Vec<u8>,target_address:&SocketAddr) -> Result<Vec<u8>,io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		let wait_start:i64 = milliseconds_now();
		let original_timeout:Option<Duration>;
		original_timeout = match self.socket.read_timeout() {
			Err(why) => return Err(why),
			Ok(t) => t,
		};
		match self.socket.set_read_timeout(Some(Duration::new((self.time_tolerance_ms/1000) as u64,(self.time_tolerance_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		let response_payload:Vec<u8>;
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
					if let Some(con) = self.client_connections.get_mut(&source_address) {
						let _ = con.unacked_packets.remove(&received_packet.hash);
					}
					if received_packet.parameter.len() > 0 && &source_address == target_address {
						if target_parameters.contains(&received_packet.parameter[0]) {
							response_payload = received_packet.payload.clone();
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
			if milliseconds_now() > wait_start+self.time_tolerance_ms {
				return Err(io::Error::new(io::ErrorKind::NotFound,"no response"));
			}
		}
		match self.socket.set_read_timeout(original_timeout) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		return Ok(response_payload);
	}
	
	// Open a connection to a remote server which has our identity on file and whose identity we have on file.
	pub fn link_server(&mut self,remote_address:SocketAddr) -> Result<(),io::Error> {
		let server_id:Vec<u8> = format!("@{}/#server",self.name).as_bytes().to_vec();
		let server_address:SocketAddr = self.address.clone();
		let server_tag:Vec<u8> = self.identity.tag.clone();
		match self.send_packet(&server_id,&vec![0x11],&vec![],&server_tag,&remote_address) {
			Err(why) => return Err(why),
			Ok(hash) => {
				self.unacked_packets.insert(hash.clone(),UnackedPacket {
					timestamp:milliseconds_now(),
					tries:0,
					source:server_address,
					destination_hash:hash.clone(),
					origin_hash:hash.clone(),
					destination:remote_address.clone(),
					sender:server_id.clone(),
					recipient:Vec::new(),
					parameter:vec![0x11],
					payload:Vec::new(),
				});
			},
		};
		self.event_stream.push_back(Event::ServerLinkSend {
			address:remote_address.clone(),
			timestamp:now_utc(),
		});
		return Ok(());
	}

	pub fn unlink_server(&mut self,remote_address:SocketAddr) -> Result<(),io::Error> {
		let server_id:Vec<u8> = format!("@{}/#server",self.name).as_bytes().to_vec();
		let server_address:SocketAddr = self.address.clone();
		let server_tag:Vec<u8> = self.identity.tag.clone();
		match self.send_packet(&server_id,&vec![0x18],&vec![],&server_tag,&remote_address) {
			Err(why) => return Err(why),
			Ok(hash) => {
				self.unacked_packets.insert(hash.clone(),UnackedPacket {
					timestamp:milliseconds_now(),
					tries:0,
					source:server_address,
					destination_hash:hash.clone(),
					origin_hash:hash.clone(),
					destination:remote_address.clone(),
					sender:server_id.clone(),
					recipient:Vec::new(),
					parameter:vec![0x18],
					payload:Vec::new(),
				});
			},
		};
		self.server_connections.remove(&remote_address);
		self.event_stream.push_back(Event::ServerUnlinkSend {
			address:remote_address.clone(),
			reason:String::from("link terminated locally"),
			timestamp:now_utc(),
		});
		return Ok(());
	}

	// encrypts and transmits a packet, much like the client version.
	pub fn send_packet(&mut self,sender:&Vec<u8>,parameter:&Vec<u8>,payload:&Vec<u8>,
	crypt_tag:&Vec<u8>,address:&SocketAddr) -> Result<Vec<u8>,io::Error> {
		let mut message:Vec<u8> = Vec::new();
		message.push(sender.len() as u8);
		message.append(&mut sender.clone());
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let null_identity = Identity { key:vec![0;32],tag:vec![0;8],name:String::new(),classes:vec![] };
		let bottle:Vec<u8>;
		if let Some(identity) = self.identities.get(crypt_tag) {
			bottle = match identity.encrypt(&message) {
				Err(why) => return Err(why),
				Ok(bytes) => bytes,
			};
		} else {
			bottle = match null_identity.encrypt(&message) {
				Err(why) => return Err(why),
				Ok(bytes) => bytes,
			};
			self.event_stream.push_back(Event::NullEncrypt {
				address:address.clone(),
				timestamp:now_utc(),
			});
		}
		let mut recipient:String = String::new();
		if let Some(con) = self.client_connections.get(&address) {
			recipient = format!("@{}/#{}",con.identity.name,con.identity.classes[0]);
		} else if let Some(con) = self.server_connections.get(&address) {
			recipient = format!("@{}/#server",con.identity.name);
		}
		match self.socket.send_to(&bottle[..],&address) {
			Err(why) => {
				self.event_stream.push_back(Event::SendFailure {
					destination:recipient.clone(),
					address:address.clone(),
					reason:format!("{}",why),
					timestamp:now_utc(),
				});
				return Err(why);
			},
			Ok(_) => (),
		};
		let packet_hash:Vec<u8> = internal_hash(&bottle);
		self.event_stream.push_back(Event::SendPacket {
			destination:String::from("client"),
			address:address.clone(),
			parameter:parameter.clone(),
			payload:payload.clone(),
			hash:packet_hash.clone(),
			timestamp:now_utc(),
		});
		return Ok(packet_hash.clone());
	}
	
	// similar to the client version; sends a raw packet without modifying it. Will need to be pre-
	// encrypted through some other means, or the client will reject it.
	pub fn send_raw(&self,message:&Vec<u8>,address:&SocketAddr) -> Result<(),io::Error> {
		match self.socket.send_to(&message[..],&address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}
	
	pub fn get_event(&mut self) -> Result<Option<Event>,io::Error> {
		if let Some(event) = self.event_stream.pop_front() {
			return Ok(Some(event));
		}
		match self.process_packets() {
			Err(why) => return Err(why),
			Ok(_) => return Ok(self.event_stream.pop_front()),
		};
	}

	pub fn process_packets(&mut self) -> Result<(),io::Error> {
		let mut input_buffer:[u8;8192] = [0;8192];
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => break,
					io::ErrorKind::Interrupted => break,
					_ => {
						self.event_stream.push_back(Event::ReceiveFailure {
							reason:format!("{}",why),
							timestamp:now_utc(),
						});
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					// check bans immediately after receiving a packet, to minimize the impact of flooding
					if self.banned_addresses.contains(&source_address.ip()) {
						continue;
					}
					let mut packet_hash:Vec<u8> = internal_hash(&input_buffer[..receive_length]);
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
					if self.recent_packets_set.contains(&packet_hash) {
						continue;
					} else {
						self.recent_packets_deque.push_back(packet_hash.clone());
						self.recent_packets_set.insert(packet_hash.clone());
						while self.recent_packets_deque.len() > self.max_recent_packets {
							if let Some(removed_packet) = self.recent_packets_deque.pop_front() {
								self.recent_packets_set.remove(&removed_packet);
							}
						}
					}
					let mut sender:String = String::new();
					if let Some(con) = self.client_connections.get_mut(&source_address) {
						sender = format!("@{}/#{}",con.identity.name,con.identity.classes[0]);
					}
					if receive_length < 40 {
						self.ban_points.insert(source_address.ip(),current_ban_points+1);
						self.event_stream.push_back(Event::InvalidMessage {
							sender:sender.clone(),
							address:source_address.clone(),
							parameter:Vec::new(),
							payload:input_buffer[0..receive_length].to_vec(),
							reason:String::from("packet length too short"),
							timestamp:now_utc(),
						});
						continue;
					}
					let packet_crypt_tag:Vec<u8> = input_buffer[receive_length-8..receive_length].to_vec();
					let sender_identity:Identity;
					let server_id:Vec<u8> = format!("@{}/#server",self.name).as_bytes().to_vec();
					let server_address:SocketAddr = self.address.clone();
					let server_tag:Vec<u8> = self.identity.tag.clone();
					if let Some(id) = self.identities.clone().get(&packet_crypt_tag) {
						sender_identity = id.clone();
					} else {
						self.ban_points.insert(source_address.ip(),current_ban_points+1);
						self.event_stream.push_back(Event::UnknownSender {
							address:source_address.clone(),
							timestamp:now_utc(),
						});
						match self.send_packet(&server_id,&vec![0x15],&packet_hash,&vec![0;8],&source_address) {
							Err(why) => return Err(why),
							Ok(_) => (),
						};
						continue;
					}
					let received_packet:Packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
					self.event_stream.push_back(Event::ReceivePacket {
						sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
						address:received_packet.source.clone(),
						parameter:received_packet.parameter.clone(),
						payload:received_packet.payload.clone(),
						hash:received_packet.hash.clone(),
						timestamp:now_utc(),
					});
					if !self.client_connections.contains_key(&source_address) {
					// && received_packet.payload.len() >= 8 { 
					// && received_packet.parameter == vec![0x02] {
						if received_packet.valid && self.client_connections.len() < self.max_connections 
						&& !self.identities_in_use.contains(&sender_identity.tag) 
						&& !self.names_in_use.contains(&sender_identity.name) {
							self.client_connections.insert(source_address.clone(),ClientConnection {
								address:source_address.clone(),
								identity:sender_identity.clone(),
								unacked_packets:HashMap::new(),
								delivery_failures:0,
							});	
							for server in self.server_connections.clone().values() {
								for class in sender_identity.classes.iter() {
									let client_id_payload:Vec<u8> = format!("@{}/#{}",sender_identity.name,class).as_bytes().to_vec();
									match self.send_packet(&server_id,&vec![0x12],&client_id_payload,&server.identity.tag,&server.address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								}
							}
							self.identities_in_use.insert(sender_identity.tag.clone());
							self.names_in_use.insert(sender_identity.name.clone());
							match self.send_packet(&server_id,&vec![0x02],&vec![],&received_packet.crypt_tag,&source_address) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							let sender_id:String = String::from_utf8_lossy(&received_packet.sender).to_string();
							self.event_stream.push_back(Event::ServerConnect {
								sender:sender_id.clone(),
								address:source_address.clone(),
								timestamp:now_utc(),
							});
							let sender_addr_bytes:Vec<u8> = format!("{} [{}]",sender_id,source_address).as_bytes().to_vec();
							for con in self.client_connections.clone().values() {
								if con.identity.classes.contains(&String::from("supervisor")) && con.address != source_address {
									match self.send_packet(&sender_addr_bytes,&vec![0x0F],&vec![],&con.identity.tag,&con.address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								}
							}
						} else {
							match self.send_packet(&server_id,&vec![0x15],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							let mut reject_reason:&str = "unspecified reason";
							if !received_packet.valid {
								reject_reason = "signature invalid";
								if let Some(points) = self.ban_points.get_mut(&source_address.ip()) {
									*points += 1;
								}
							} else if self.client_connections.len() >= self.max_connections {
								reject_reason = "server full";
							} else if self.identities_in_use.contains(&sender_identity.tag) {
								reject_reason = "identity already in use";
							} else if self.names_in_use.contains(&sender_identity.name) {
								reject_reason = "name already in use";
							}
							let sender_id:String = String::from_utf8_lossy(&received_packet.sender).to_string();
							self.event_stream.push_back(Event::ServerConnectFailure {
								sender:sender_id.clone(),
								address:source_address.clone(),
								reason:reject_reason.to_owned(),
								timestamp:now_utc(),
							});
							let sender_addr_bytes:Vec<u8> = format!("{} [{}]",sender_id,source_address).as_bytes().to_vec();
							let reason_bytes:Vec<u8> = reject_reason.as_bytes().to_vec();
							for con in self.client_connections.clone().values() {
								if con.identity.classes.contains(&String::from("supervisor")) {
									match self.send_packet(&sender_addr_bytes,&vec![0x0F],&reason_bytes,&con.identity.tag,&con.address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								}
							}
						}
					}
					if received_packet.parameter.len() > 0 {
						match (received_packet.parameter[0],received_packet.payload.len()) {
							(0x06,8)|(0x15,8) => {
								let mut acked_hash:Vec<u8> = received_packet.payload[..8].to_vec();
								let mut ack_origin:Option<SocketAddr> = None;
								let mut ack_sender:Vec<u8> = server_id.clone();
								let mut ack_origin_hash:Vec<u8> = vec![0;8];
								if let Some(mut con) = self.client_connections.get_mut(&source_address) {
									if let Some(packet) = con.unacked_packets.remove(&acked_hash) {
										ack_origin = Some(packet.source.clone());
										ack_sender = packet.recipient.clone();
										ack_origin_hash = packet.origin_hash.clone();
									};
								} else if let Some(server) = self.server_connections.get_mut(&source_address) {
									let client_id:String = String::from_utf8_lossy(&received_packet.sender).to_string();
									let client_name:String = client_id.trim_matches('@').splitn(2,"/").collect::<Vec<&str>>()[0].to_owned();
									if let Some(remote_con) = server.remote_connections.get_mut(&client_name) {
										if let Some(packet) = remote_con.unacked_packets.remove(&acked_hash) {
											ack_origin = Some(packet.source.clone());
											ack_sender = packet.recipient.clone();
											ack_origin_hash = packet.origin_hash.clone();
										}
									}
								}
								if let Some(origin) = ack_origin {
									if origin != self.address {
										if let Some(con) = self.client_connections.clone().get(&origin) {
											match self.send_packet(&ack_sender,&received_packet.parameter,&ack_origin_hash,&con.identity.tag,&origin) {
												Err(why) => return Err(why),
												Ok(_) => (),
											};
										}
									}
								}
								match received_packet.parameter[0] {
									0x06 => self.event_stream.push_back(Event::Acknowledge {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:source_address.clone(),
										hash:acked_hash.to_vec(),
										matches:0,
										timestamp:now_utc(),
									}),
									0x15 => self.event_stream.push_back(Event::Refusal {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:source_address.clone(),
										hash:acked_hash.to_vec(),
										timestamp:now_utc(),
									}),
									_ => (),
								};
							},
							(0x06,_) => {
								self.event_stream.push_back(Event::Acknowledge {
									sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
									address:source_address.clone(),
									hash:Vec::new(),
									matches:0,
									timestamp:now_utc(),
								});
							},
							(0x15,_) => {
								self.event_stream.push_back(Event::Refusal {
									sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
									address:received_packet.source.clone(),
									hash:received_packet.payload.to_vec(),
									timestamp:now_utc(),
								});
							},
							(0x02,8) => {
								match self.send_packet(&server_id,&vec![0x06],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
							},
							(0x11,_) => {
								if let Some(server) = self.client_connections.remove(&source_address) {
									if server.identity.classes.contains(&String::from("server")) && received_packet.crypt_tag != vec![0;8] {
										self.server_connections.insert(source_address.clone(),ServerConnection {
											address:server.address.clone(),
											identity:server.identity.clone(),
											remote_connections:HashMap::new(),
											unacked_packets:server.unacked_packets.clone(),
										});
										self.event_stream.push_back(Event::ServerLinkReceive {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:source_address.clone(),
											timestamp:now_utc(),
										});
										if let Some(_) =  self.unacked_packets.remove(&received_packet.hash) {
											match self.send_packet(&server_id,&vec![0x06],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
												Err(why) => return Err(why),
												Ok(_) => (),
											};
										} else {
											match self.send_packet(&server_id,&vec![0x11],&vec![],&server_tag,&source_address) {
												Err(why) => return Err(why),
												Ok(hash) => {
													self.unacked_packets.insert(hash.clone(),UnackedPacket {
														timestamp:milliseconds_now(),
														tries:0,
														source:server_address.clone(),
														destination_hash:hash.clone(),
														origin_hash:hash.clone(),
														destination:source_address.clone(),
														sender:server_id.clone(),
														recipient:Vec::new(),
														parameter:vec![0x11],
														payload:Vec::new(),
													});
												},
											};
											self.event_stream.push_back(Event::ServerLinkSend {
												address:source_address.clone(),
												timestamp:now_utc(),
											});
										}
									} else {
										match self.send_packet(&server_id,&vec![0x15],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
							},
							(0x12,_) => {
								if self.server_connections.contains_key(&source_address) {
									match self.send_packet(&server_id,&vec![0x06],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								} else {
									match self.send_packet(&server_id,&vec![0x15],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								}
								let mut new_information:bool = false;
								if let Some(server) = self.server_connections.get_mut(&source_address) {
									let mut new_remote_connection:RemoteConnection = RemoteConnection {
										name:String::new(),
										classes:Vec::new(),
										unacked_packets:HashMap::new(),
									};
									let payload_string:String = String::from_utf8_lossy(&received_packet.payload).to_string();
									for payload_segment in payload_string.split("/") {
										if payload_segment.starts_with("@") {
											new_remote_connection.name = payload_segment.trim_matches('@').to_owned();
										} else if payload_segment.starts_with("#") {
											new_remote_connection.classes.push(payload_segment.trim_matches('#').to_owned());
										}
									}
									if let Some(existing_remote_connection) = server.remote_connections.get_mut(&new_remote_connection.name) {
										for class in new_remote_connection.classes.iter() {
											if !existing_remote_connection.classes.contains(&class) {
												existing_remote_connection.classes.push(class.to_owned());
												new_information = true;
											}
										}
									}
									if !server.remote_connections.contains_key(&new_remote_connection.name) {
										let main_class:String;
										if new_remote_connection.classes.len() > 0 {
											main_class = new_remote_connection.classes[0].clone();
										} else {
											main_class = String::new();
										}
										self.event_stream.push_back(Event::RemoteConnect {
											sender:format!("@{}/#{}",new_remote_connection.name,main_class),
											server:String::from_utf8_lossy(&received_packet.sender).to_string(),
											timestamp:now_utc(),
										});
										server.remote_connections.insert(new_remote_connection.name.clone(),new_remote_connection);
										new_information = true;
									}
								}
								if new_information {
									for server in self.server_connections.clone().values() {
										match self.send_packet(&received_packet.sender,&received_packet.parameter,
										&received_packet.payload,&server.identity.tag,&server.address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
							},
							(0x13,0) => {
								if self.server_connections.contains_key(&source_address) {
									match self.send_packet(&server_id,&vec![0x06],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								} else {
									match self.send_packet(&server_id,&vec![0x15],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								}
								let mut new_information:bool = false;
								if let Some(server) = self.server_connections.get_mut(&source_address) {
									let mut new_remote_connection:RemoteConnection = RemoteConnection {
										name:String::new(),
										classes:Vec::new(),
										unacked_packets:HashMap::new(),
									};
									let payload_string:String = String::from_utf8_lossy(&received_packet.payload).to_string();
									for payload_segment in payload_string.split("/") {
										if payload_segment.starts_with("@") {
											new_remote_connection.name = payload_segment.trim_matches('@').to_owned();
										} else if payload_segment.starts_with("#") {
											new_remote_connection.classes.push(payload_segment.trim_matches('#').to_owned());
										}
									}
									let main_class:String;
									if new_remote_connection.classes.len() == 0 {
										match server.remote_connections.remove(&new_remote_connection.name) {
											None => {
												main_class = String::new();
											},
											Some(con) => {
												if con.classes.len() > 0 {
													main_class = con.classes[0].clone();
												} else {
													main_class = String::new();
												}
												new_information = true;
											},
										};
									} else {
										main_class = new_remote_connection.classes[0].clone();
										if new_remote_connection.name.len() > 0 {
											if let Some(existing_remote_connection) = server.remote_connections.get_mut(&new_remote_connection.name) {
												let mut new_class_list:Vec<String> = Vec::new();
												for class in existing_remote_connection.classes.iter() {
													if !new_remote_connection.classes.contains(&class) {
														new_class_list.push(class.clone());
													}
												}
												if existing_remote_connection.classes != new_class_list {
													new_information = true;
													existing_remote_connection.classes = new_class_list;
												}
											}
										}
									}
									if new_information { 
										self.event_stream.push_back(Event::RemoteDisconnect {
											sender:format!("@{},#{}",new_remote_connection.name,main_class),
											server:String::from_utf8_lossy(&received_packet.sender).to_string(),
											timestamp:now_utc(),
										});
									}
								}
								if new_information {
									for server in self.server_connections.clone().values() {
										match self.send_packet(&received_packet.sender,&received_packet.parameter,&received_packet.payload,
										&server.identity.tag,&server.address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
							},
							(0x18,0) => {
								if let Some(cancelled_con) = self.client_connections.remove(&source_address) {
									self.identities_in_use.remove(&cancelled_con.identity.tag);
									self.names_in_use.remove(&cancelled_con.identity.name);
								} else if let Some(cancelled_server) = self.server_connections.remove(&source_address) {
									self.identities_in_use.remove(&cancelled_server.identity.tag);
									self.names_in_use.remove(&cancelled_server.identity.name);
								}
								match self.send_packet(&server_id,&vec![0x19],&vec![],&received_packet.crypt_tag,&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
								let sender_id:String = String::from_utf8_lossy(&received_packet.sender).to_string();
								self.event_stream.push_back(Event::ServerDisconnect {
									sender:sender_id.clone(),
									address:source_address.clone(),
									reason:String::from("connection terminated by remote client"),
									timestamp:now_utc(),
								});
								let sender_addr_bytes:Vec<u8> = format!("{} [{}]",sender_id,source_address).as_bytes().to_vec();
								let reason_bytes:Vec<u8> = b"connection terminated by remote client".to_vec();
								for con in self.client_connections.clone().values() {
									if con.identity.classes.contains(&String::from("supervisor")) {
										match self.send_packet(&sender_addr_bytes,&vec![0x0E],&reason_bytes,&con.identity.tag,&con.address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
							},
							(0x05,0) => {
								let client_connections_snapshot = self.client_connections.clone();
								if let Some(requesting_con) = client_connections_snapshot.get(&source_address) {
									if requesting_con.identity.classes.contains(&String::from("supervisor")) {
										self.event_stream.push_back(Event::ClientListRequest {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:received_packet.source.clone(),
											timestamp:now_utc(),
										});
										let mut sendfailures:u64 = 0;
										'itercons:for con in client_connections_snapshot.values() {
											'iterclasses:for class in con.identity.classes.iter() {
												'resend:loop {
													let payload_string:String = format!("@{}/#{} [{}]",&con.identity.name,&class,&con.address);
													match self.send_packet(&server_id,&vec![0x04],&payload_string.as_bytes().to_vec(),
													&received_packet.crypt_tag,&source_address) {
														Err(why) => return Err(why),
														Ok(_) => (),
													};
													self.event_stream.push_back(Event::ClientListResponse {
														sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
														address:received_packet.source.clone(),
														payload:payload_string.clone(),
														timestamp:now_utc(),
													});
													match self.get_response(&vec![0x06],&source_address) {
														Err(why) => match why.kind() {
															io::ErrorKind::NotFound => sendfailures += 1,
															_ => return Err(why),
														},
														Ok(_) => break 'resend,
													};
													if sendfailures > self.max_resend_failures {
														break 'itercons;
													}
												}
											}
										}
										match self.send_packet(&server_id,&vec![0x04],&vec![],&received_packet.crypt_tag,&source_address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
										self.event_stream.push_back(Event::ClientListEnd {
											sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
											address:received_packet.source.clone(),
											timestamp:now_utc(),
										});
									} else {
										match self.send_packet(&server_id,&vec![0x15],&received_packet.hash,&received_packet.crypt_tag,&source_address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
							},
							(0x1C,16) => {
								let received_id = received_packet.payload[..8].to_vec();
								let received_length = bytes_to_u64(&received_packet.payload[8..]) as usize;
								let routing_expression = String::from_utf8_lossy(&received_packet.parameter[1..]).to_string();
								self.relaying_transmissions.insert(received_id.clone(),ServerTransmission {
									id:received_id,
									origin:received_packet.source.clone(),
									length:received_length,
									routing_expression:routing_expression.clone(),
									blocks_needed:(0..received_length).collect(),
									failed_recipients:HashSet::new(),
								});
								match self.relay_packet(&routing_expression,&received_packet) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
							},
							(0x1E,_) => {
								
							},
							(b'>',_) => {
								if received_packet.valid && received_packet.parameter.len() >= 1 {
									let routing_expression = String::from_utf8_lossy(&received_packet.parameter[1..]).to_string();
									match self.relay_packet(&routing_expression,&received_packet) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
								} else {
									self.event_stream.push_back(Event::InvalidMessage {
										sender:String::from_utf8_lossy(&received_packet.sender).to_string(),
										address:received_packet.source.clone(),
										parameter:received_packet.parameter.clone(),
										payload:received_packet.payload.clone(),
										reason:String::from("signature invalid"),
										timestamp:now_utc(),
									});
								}
							},
							(_,_) => (),
						}; // match message[0]
					} // if message.len > 0
				}, // recvfrom ok
			}; // match recvfrom
		}
		return Ok(());
	}

	pub fn resend_unacked(&mut self) -> Result<(),io::Error> {
		let now:i64 = milliseconds_now();
		for con in self.client_connections.clone().values() {
			// retransmit packets that haven't been acknowledged and were last sent a while ago.
			if con.unacked_packets.len() > self.max_unsent_packets {
				if let Some(mut list_con) = self.client_connections.get_mut(&con.address) {
					list_con.unacked_packets.clear();
				}
				if let Some(cancelled_con) = self.client_connections.remove(&con.address) {
					self.identities_in_use.remove(&cancelled_con.identity.tag);
					self.names_in_use.remove(&cancelled_con.identity.name);
				}
				match self.send_packet(&vec![],&vec![0x19],&vec![],&con.identity.tag,&con.address) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				let client_name:String = format!("@{}/#{}",&con.identity.name,&con.identity.classes[0]);
				self.event_stream.push_back(Event::ServerDisconnect {
					sender:client_name.clone(),
					address:con.address.clone(),
					reason:String::from("maximum send queue length exceeded"),
					timestamp:now_utc(),
				});
				let sender_addr_bytes:Vec<u8> = format!("{} [{}]",client_name,con.address).as_bytes().to_vec();
				let reason_bytes:Vec<u8> = b"maximum send queue length exceeded".to_vec();
				for othercon in self.client_connections.clone().values() {
					if othercon.identity.classes.contains(&String::from("supervisor")) {
						match self.send_packet(&sender_addr_bytes,&vec![0x0E],&reason_bytes,&othercon.identity.tag,&othercon.address) {
							Err(why) => return Err(why),
							Ok(_) => (),
						};
					}
				}
				continue;
			}
			if con.delivery_failures > self.max_resend_failures {
				if let Some(cancelled_con) = self.client_connections.remove(&con.address) {
					self.identities_in_use.remove(&cancelled_con.identity.tag);
					self.names_in_use.remove(&cancelled_con.identity.name);
				}
				match self.send_packet(&vec![],&vec![0x19],&vec![],&con.identity.tag,&con.address) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				let client_name:String = format!("@{}/#{}",&con.identity.name,&con.identity.classes[0]);
				self.event_stream.push_back(Event::ServerDisconnect {
					sender:client_name.clone(),
					address:con.address.clone(),
					reason:String::from("maximum resend failure count exceeded"),
					timestamp:now_utc(),
				});
				let sender_addr_bytes:Vec<u8> = format!("{} [{}]",client_name,con.address).as_bytes().to_vec();
				let reason_bytes:Vec<u8> = b"maximum resend failure count exceeded".to_vec();
				for othercon in self.client_connections.clone().values() {
					if othercon.identity.classes.contains(&String::from("supervisor")) {
						match self.send_packet(&sender_addr_bytes,&vec![0x0E],&reason_bytes,&othercon.identity.tag,&othercon.address) {
							Err(why) => return Err(why),
							Ok(_) => (),
						};
					}
				}
				let now = milliseconds_now();
				for server in self.server_connections.values_mut() {
					for remote_con in server.remote_connections.values_mut() {
						for unacked in remote_con.unacked_packets.clone().iter() {
							if unacked.1.timestamp+self.time_tolerance_ms < now {
								remote_con.unacked_packets.remove(unacked.0);
							}
						}
					}
				}
				continue;
			}
			for unacked_packet in con.unacked_packets.clone().values() {
				// if the packet's timestamp is a while ago, resend it.
				if unacked_packet.timestamp+self.time_tolerance_ms < now {
					let resend_hash:Vec<u8> = match self.send_packet(&unacked_packet.sender,&unacked_packet.parameter,
					&unacked_packet.payload,&con.identity.tag,&con.address) {
						Err(why) => return Err(why),
						Ok(hash) => hash,
					};
					// after resending a packet, update its timestamp in the original connector list.
					if let Some(list_con) = self.client_connections.get_mut(&con.address) {
						if unacked_packet.tries < self.max_resend_tries {
							let mut new_tries:u64 = 0;
							if let Some(list_packet) = list_con.unacked_packets.remove(&unacked_packet.destination_hash) {
								new_tries = list_packet.tries;
							}
							if let Some(new_unack) = list_con.unacked_packets.get_mut(&resend_hash) {
								new_unack.tries = new_tries+1;
							}
							self.event_stream.push_back(Event::DeliveryRetry {
								destination:String::from_utf8_lossy(&unacked_packet.recipient).to_string(),
								address:con.address.clone(),
								parameter:unacked_packet.parameter.clone(),
								payload:unacked_packet.payload.clone(),
								timestamp:now_utc(),
							});
						} else {
							list_con.unacked_packets.remove(&unacked_packet.destination_hash);
							list_con.delivery_failures += 1;
							self.event_stream.push_back(Event::DeliveryFailure {
								destination:String::from_utf8_lossy(&unacked_packet.recipient).to_string(),
								address:con.address.clone(),
								parameter:unacked_packet.parameter.clone(),
								payload:unacked_packet.payload.clone(),
								reason:String::from("maximum resend failure count exceeded"),
								timestamp:now_utc(),
							});
						}			
					}
				}
			}
		}
		return Ok(());
	}

	pub fn relay_packet(&mut self,routing_expression:&str,packet:&Packet) -> Result<(),io::Error> {
		let server_id:Vec<u8> = format!("@{}/#server",self.name).as_bytes().to_vec();
		if !packet.valid {
			return Err(io::Error::new(io::ErrorKind::InvalidData,"cannot relay invalid packet"));
		}
		let identities = self.identities.clone();
		let mut dest_addresses:HashSet<SocketAddr> = HashSet::new();
		let mut outbound_packets:Vec<(Vec<u8>,Vec<u8>,SocketAddr)> = Vec::new();
		let mut match_count:u64 = 0;
		let send:bool = packet.payload.len() > 0;
		for server in self.server_connections.values_mut() {
			if server.address == packet.source {
				continue;
			}
			for remote_con in server.remote_connections.values_mut() {
				let mut con_identifiers:String = String::new();
				con_identifiers.push_str(&format!("@{} ",remote_con.name));
				for class in remote_con.classes.iter() {
					con_identifiers.push_str(&format!("#{} ",class));
				}
				let matched:bool = wordmatch(&routing_expression,&con_identifiers);
				if matched || remote_con.classes.contains(&String::from("supervisor")) {
					if let Ok((hash,bottle)) = gen_packet(&packet.sender,&packet.parameter,&packet.payload,&server.identity.tag,&identities) {
						if send {
							let recipient_string:String;
							if remote_con.classes.len() > 0 {
								recipient_string = format!("@{}/#{}",remote_con.name,remote_con.classes[0]);
							} else {
								recipient_string = format!("@{}",remote_con.name);
							}
							remote_con.unacked_packets.insert(hash.clone(),UnackedPacket {
								timestamp:packet.timestamp.clone(),
								tries:0,
								source:packet.source.clone(),
								destination_hash:hash.clone(),
								origin_hash:packet.hash.clone(),
								destination:server.address.clone(),
								sender:packet.sender.clone(),
								recipient:recipient_string.as_bytes().to_vec(),
								parameter:packet.parameter.clone(),
								payload:packet.payload.clone(),
							});
							if !dest_addresses.contains(&server.address) {
								outbound_packets.push((hash,bottle,server.address.clone()));
								dest_addresses.insert(server.address.clone());
							}
						}
					}
					if matched {
						match_count += 1;
					}
				}
			}
		}
		for client in self.client_connections.values_mut() {
			if client.address == packet.source {
				continue;
			}
			let mut con_identifiers:String = String::new();
			con_identifiers.push_str(&format!("@{} ",client.identity.name));
			for class in client.identity.classes.iter() {
				con_identifiers.push_str(&format!("#{} ",class));
			}
			let matched:bool = wordmatch(&routing_expression,&con_identifiers);
			if matched || client.identity.classes.contains(&String::from("supervisor")) {
				if let Ok((hash,bottle)) = gen_packet(&packet.sender,&packet.parameter,&packet.payload,&client.identity.tag,&identities) {
					if send {
						let source;
						if matched {
							source = packet.source.clone();
							match_count += 1;
						} else {
							source = self.address.clone();
						}
						client.unacked_packets.insert(hash.clone(),UnackedPacket {
							timestamp:packet.timestamp.clone(),
							tries:0,
							source:source,
							destination_hash:hash.clone(),
							origin_hash:packet.hash.clone(),
							destination:client.address.clone(),
							sender:packet.sender.clone(),
							recipient:format!("@{}/#{}",client.identity.name,client.identity.classes[0]).as_bytes().to_vec(),
							parameter:packet.parameter.clone(),
							payload:packet.payload.clone(),
						});
						outbound_packets.push((hash,bottle,client.address.clone()));
					}
				}
			}
		}
		let mut ack_payload:Vec<u8> = Vec::new();
		ack_payload.append(&mut packet.hash.clone());
		ack_payload.append(&mut u64_to_bytes(&match_count).to_vec());
		if send {
			for outbound_packet in outbound_packets.iter() {
				match self.send_raw(&outbound_packet.1,&outbound_packet.2) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
			}
			match self.send_packet(&server_id,&vec![0x06],&ack_payload,&packet.crypt_tag,&packet.source) {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
		} else {
			match self.send_packet(&server_id,&vec![0x03],&ack_payload,&packet.crypt_tag,&packet.source) {
				Err(why) => return Err(why),
				Ok(_) => (),
			};
		}
		return Ok(());
	}

} // impl Server
