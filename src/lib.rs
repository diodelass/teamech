// Teamech v 0.7.2 October 2018

/*
Feature Outline

Functionality														Implemented

I. Server																		[ ]
	A. Subscriptions													[ ]
		1. Acceptance														[X]
		2. Cancellation													[X]
			a. Upon request												[X]
			b. Upon absence												[X]
			c. Upon misbehavior										[ ]
		3. Banning															[ ]
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
		5. Handling acknowledgements						[ ]
			a. Resending													[ ]
	C. Server-Server Links										[X]
		1. Opening															[X] 
		2. Closing															[ ]
II. Client																	[ ]
	A. Subscribing														[ ]
		1. Opening subscription									[X]
		2. Closing subscription									[X]
		3. Responding to closure								[ ]
	B. Sending																[X]
	C. Receiving															[X]
III. Security																[X]
	A. Encryption															[X]
	B. Decryption															[X]
	C. Validation															[X]
	D. Incident Logs													[X]
IV. Logging																	[X]
	A. Log Events															[X]
	B. Log Event Classification								[X]

*/

extern crate rand;

extern crate tiny_keccak;
use tiny_keccak::Keccak;

extern crate chrono;
use chrono::prelude::*;

extern crate byteorder;
use byteorder::{LittleEndian,ReadBytesExt,WriteBytesExt};

use std::io::prelude::*;
use std::io;
use std::fs::File;
use std::collections::{VecDeque,HashMap};
use std::time::Duration;
use std::thread::sleep;
use std::net::{UdpSocket,SocketAddr};

// converts a signed 64-bit int into eight bytes
fn i64_to_bytes(number:&i64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	bytes.as_mut().write_i64::<LittleEndian>(*number).expect("failed to convert i64 to bytes");
	return bytes;
}

// converts an unsigned 64-bit int into eight bytes
fn u64_to_bytes(number:&u64) -> [u8;8] {
	let mut bytes:[u8;8] = [0;8];
	bytes.as_mut().write_u64::<LittleEndian>(*number).expect("failed to convert u64 to bytes");
	return bytes;
}

// converts eight bytes into a signed 64-bit int
fn bytes_to_i64(bytes:&[u8;8]) -> i64 {
	return bytes.as_ref().read_i64::<LittleEndian>().expect("failed to convert bytes to i64"); 
}

// converts eight bytes into an unsigned 64-bit int
fn bytes_to_u64(bytes:&[u8;8]) -> u64 {
	return bytes.as_ref().read_u64::<LittleEndian>().expect("failed to convert bytes to u64");
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

// object for handling encryption and decryption using Teacrypt.
// stores data from a pad file, and possesses member functions 
// which allow the pad to be used to encrypt and decrypt data.
pub struct Crypt {
	pub pad_path:String,
	pub pad_data:Vec<u8>,
	pub pad_length:usize,
}

// constructor for a Crypt object. opens a pad file, reads it into memory, and returns 
// a Crypt object containing the data.
// calling this function will cause the program's memory usage to quickly increase by
// the size of the pad file, and will block until the pad file has finished loading - 
// this would be a good time to let the user know that a long operation is about to 
// happen, especially if they are using a very large pad file and/or a slow disk.
// TODO: add runtime option to not load the pad file and instead always access it in-place.
// TODO: add support for raw block devices as pad files.
pub fn new_crypt(new_pad_path:&str) -> Result<Crypt,io::Error> {
	let mut new_pad_data:Vec<u8> = Vec::new();
	match File::open(&new_pad_path) {
		Err(why) => return Err(why),
		Ok(mut file) => match file.read_to_end(&mut new_pad_data) {
			Err(why) => return Err(why),
			Ok(nbytes) => {
				return Ok(Crypt {
					pad_path:new_pad_path.to_owned(),
					pad_data:new_pad_data,
					pad_length:nbytes,
				});
			},
		},
	};
}

impl Crypt {

	// generates a key of a specific length using a specific nonce (eight bytes
	// indicating where to start on the pad file). returns the requested key and
	// that key's corresponding secret seed.
	// this function doesn't need to be called directly to encrypt or decrypt data,
	// but remains public in case it is needed for any unconventional implementations.
	pub fn keygen(&self,nonce:&[u8;8],key_size:&usize) -> (Vec<u8>,Vec<u8>) {
		let mut seed:[u8;8] = [0;8];
		let mut seed_temp_1:[u8;8] = nonce.clone();
		let mut seed_temp_2:[u8;8] = [0;8];
		for x in 0..8 {
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&nonce.clone());
			sha3.update(&seed_temp_1);
			if x >= 1 {
				sha3.update(&[seed[x-1]]);
			}
			sha3.finalize(&mut seed_temp_2);
			seed_temp_1 = seed_temp_2;
			seed[x] = self.pad_data[(bytes_to_u64(&seed_temp_1) as usize)%self.pad_length];
		}
		let mut key_bytes:Vec<u8> = Vec::with_capacity(*key_size);
		let mut key_temp_1:[u8;8] = seed;
		let mut key_temp_2:[u8;8] = [0;8];
		for x in 0..*key_size {
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&seed);
			sha3.update(&key_temp_1);
			if x >= 1 {
				sha3.update(&[key_bytes[x-1]]);
			}
			sha3.finalize(&mut key_temp_2);
			key_temp_1 = key_temp_2;
			key_bytes.push(self.pad_data[(bytes_to_u64(&key_temp_1) as usize)%self.pad_length]);
		}
		return (key_bytes,seed.to_vec());
	}

	// uses the pad data (calling the keygen function) to encrypt provided data, providing
	// a sealed bottle which can be transmitted. unlike previous Teacrypt versions, this
	// implementation inserts a timestamp during encryption.
	pub fn encrypt(&self,message:&Vec<u8>) -> Vec<u8> {
		let mut timestamped_message:Vec<u8> = message.clone();
		timestamped_message.append(&mut i64_to_bytes(&Local::now().timestamp_millis()).to_vec());
		let nonce:u64 = rand::random::<u64>();
		let nonce_bytes:[u8;8] = u64_to_bytes(&nonce);
		let key_size:usize = timestamped_message.len()+8;
		let (key_bytes,seed) = self.keygen(&nonce_bytes,&key_size);
		let mut signature:[u8;8] = [0;8];
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&seed);
		sha3.update(&timestamped_message);
		sha3.update(&key_bytes);
		sha3.finalize(&mut signature);
		let mut signed_message = Vec::new();
		signed_message.append(&mut timestamped_message.clone());
		signed_message.append(&mut signature.to_vec());
		let mut bottle = Vec::new();
		for x in 0..key_size {
			bottle.push(signed_message[x] ^ key_bytes[x]);
		}
		bottle.append(&mut nonce_bytes.to_vec());
		return bottle;
	}
	
	// uses the pad data to decrypt and validate a provided bottle, producing the decrypted
	// data, the timestamp indicating when the message was encrypted, and a boolean flag
	// indicating whether or not the data validated successfully. 
	pub fn decrypt(&self,bottle:&Vec<u8>) -> (Vec<u8>,i64,bool) {
		if bottle.len() < 24 {
			return (Vec::new(),0,false);
		}
		let mut nonce_bytes:[u8;8] = [0;8];
		nonce_bytes.copy_from_slice(&bottle[bottle.len()-8..bottle.len()]);
		let key_size = bottle.len()-8;
		let encrypted_bytes:Vec<u8> = bottle[0..bottle.len()-8].to_vec();
		let (key_bytes,seed) = self.keygen(&nonce_bytes,&key_size);
		let mut signed_message = Vec::new();
		for x in 0..key_size {
			signed_message.push(encrypted_bytes[x] ^ key_bytes[x]);
		}
		let mut signature:[u8;8] = [0;8];
		let mut timestamp:[u8;8] = [0;8];
		signature.copy_from_slice(&signed_message[signed_message.len()-8..]);
		timestamp.copy_from_slice(&signed_message[signed_message.len()-16..signed_message.len()-8]);
		let timestamped_message:Vec<u8> = signed_message[0..signed_message.len()-8].to_vec();
		let message:Vec<u8> = timestamped_message[..timestamped_message.len()-8].to_vec();
		let mut correct_signature:[u8;8] = [0;8];
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&seed);
		sha3.update(&timestamped_message);
		sha3.update(&key_bytes);
		sha3.finalize(&mut correct_signature);
		return (message,bytes_to_i64(&timestamp),signature == correct_signature);
	}

} // impl Crypt

pub enum EventClass {
	Acknowledge,						// ack
	Create,									// client/server object created
	Subscribe,							// client/server subscription
	Unsubscribe,						// client/server cancellation
	ServerLink,							// current server initiated a link to another
	ServerLinkFailure,			// attempt to link to another server failed
	ReceiveMessage,					// message delivered to the current endpoint (e.g. client)
	ReceiveFailure,					// could not receive data
	SendMessage,						// message sent by the current endpoint
	SendFailure,						// could not send data
	DeadEndMessage,					// message that does not match any subscribed clients
	HaltedMessage,					// message that matches one recently relayed, and so was stopped
	TestMessage,						// message with no contents, used to test number of routing pattern matches
	RoutedMessage,					// message relayed to one or more matched clients
	GlobalMessage,					// message matching all clients
	InvalidMessage,					// message whose signature or timestamp did not validate
	DeliveryRetry,					// resend of message that was not acknowledged the first time it was sent
	DeliveryFailure,				// message was resent too many times with no acknowledgement, and has been given up on
	NameUpdate,							// client set or changed its name
	NameUpdateFailure,			// client tried to change its name to an invalid value
	ClassAdd,								// client added itself to a class
	ClassAddFailure,				// client tried to add an invalid class
	ClassRemove,						// client removed itself from a class
	ClassListRequest,				// client requested its class list
	ClassListResponse,			// server responded to class list request
	ClientListRequest,			// client requested the list of all connected clients
	ClientListResponse,			// server responded to client list request
}

pub struct Event {
	pub class:EventClass,										// EventClass specifier
	pub initiator_id:Vec<u8>,										// @name/#class of initiating endpoint
	pub initiator_address:Option<SocketAddr>,		// socket address of initiating endpoint
	pub parameter:Vec<u8>,											// event parameter (e.g. routing expression)
	pub contents:Vec<u8>,												// event contents (e.g. message payload)
	pub timestamp:i64,													// timestamp of event
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
	pub parameter:Vec<u8>,	// message parameter (e.g. routing expression)
	pub payload:Vec<u8>,		// message payload
}

// object representing a Teamech client, with methods for sending and receiving packets.
pub struct Client {
	pub socket:UdpSocket,																		// local socket for transceiving data
	pub server_address:SocketAddr,													// address of server we're subscribed to
	pub name:String,																				// our self-declared name
	pub classes:Vec<String>,																// our self-declared classes
	pub crypt:Crypt,																				// crypt object holding key data
	pub receive_queue:VecDeque<Packet>,											// incoming packets that need to be processed by the implementation
	pub event_log:VecDeque<Event>,
	pub unacked_packets:HashMap<[u8;8],(Vec<u8>,i64,u64)>,	// packets that need to be resent if they aren't acknowledged
	pub max_resend_tries:u64,																// maximum number of tries to resend a packet before discarding it
	pub uptime:i64,																					// time at which this client was created
	pub time_tolerance_ms:i64,															// maximum time difference a packet can have from now and still be considered valid
	pub synchronous:bool,																		// whether or not this client is synchronous
}

// client constructor, which takes a pad file path, a server address, and a local port
// number and produces a new client object. also calls the Crypt constructor.
pub fn new_client(pad_path:&str,server_address:SocketAddr,local_port:u16) -> Result<Client,io::Error> {
	let new_crypt:Crypt = match new_crypt(&pad_path) {
		Err(why) => return Err(why),
		Ok(crypt) => crypt,
	};
	match UdpSocket::bind(&format!("0.0.0.0:{}",local_port)) {
		Err(why) => return Err(why),
		Ok(socket) => {
			let mut created_client = Client {
				socket:socket,
				server_address:server_address,
				name:String::new(),
				classes:Vec::new(),
				receive_queue:VecDeque::new(),
				event_log:VecDeque::new(),
				unacked_packets:HashMap::new(),
				max_resend_tries:10,
				crypt:new_crypt,
				uptime:Local::now().timestamp_millis(),
				time_tolerance_ms:3000,
				synchronous:true,
			};
			created_client.event_log.push_back(Event {
				class:EventClass::Create,
				initiator_id:b"local".to_vec(),
				initiator_address:None,
				parameter:vec![],
				contents:vec![],
				timestamp:Local::now().timestamp_millis(),
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

	pub fn decrypt_packet(&self,bottle:&Vec<u8>,source_address:&SocketAddr) -> Packet {
		let now:i64 = Local::now().timestamp_millis();
		let mut decrypted_bytes:Vec<u8> = Vec::new();
		let mut timestamp:i64 = 0;
		let mut message_valid:bool = false;
		let mut sender_bytes:Vec<u8> = Vec::new();
		let mut parameter_bytes:Vec<u8> = Vec::new();
		let mut payload_bytes:Vec<u8> = Vec::new();
		if bottle.len() >= 24 {
			let decryption = self.crypt.decrypt(&bottle);
			decrypted_bytes = decryption.0;
			timestamp = decryption.1;
			message_valid = decryption.2;
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
					_ => return Err(why),
				},
				Ok((receive_length,source_address)) => {
					if source_address == self.server_address {
						let received_packet:Packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
						let mut packet_hash:[u8;8] = [0;8];
						let mut sha3 = Keccak::new_sha3_256();
						sha3.update(&input_buffer[..receive_length]);
						sha3.finalize(&mut packet_hash);
						if received_packet.valid {
							match self.send_packet(&vec![0x06],&packet_hash.to_vec()) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							self.event_log.push_back(Event {
								class:EventClass::ReceiveMessage,
								initiator_id:received_packet.sender.clone(),
								initiator_address:Some(received_packet.source.clone()),
								parameter:received_packet.parameter.clone(),
								contents:received_packet.payload.clone(),
								timestamp:received_packet.timestamp.clone(),
							});
						} else {
							match self.send_packet(&vec![0x15],&packet_hash.to_vec()) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							self.event_log.push_back(Event {
								class:EventClass::InvalidMessage,
								initiator_id:received_packet.sender.clone(),
								initiator_address:Some(received_packet.source.clone()),
								parameter:received_packet.parameter.clone(),
								contents:received_packet.payload.clone(),
								timestamp:received_packet.timestamp.clone(),
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
	pub fn send_packet(&mut self,parameter:&Vec<u8>,payload:&Vec<u8>) -> Result<(),io::Error> {
		let mut message:Vec<u8> = Vec::new();
		let mut primary_class:&str = "";
		if self.classes.len() > 0 {
			primary_class = &self.classes[0];
		}
		let mut sender:Vec<u8> = format!("@{}/#{}",&self.name,&primary_class).as_bytes().to_vec();
		message.push(sender.len() as u8);
		message.append(&mut sender);
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let bottle:Vec<u8> = self.crypt.encrypt(&message);
		match self.send_raw(&bottle) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		self.event_log.push_back(Event {
			class:EventClass::SendMessage,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:parameter.clone(),
			contents:payload.clone(),
			timestamp:Local::now().timestamp_millis(),
		});
		if parameter.len() > 0 && parameter[0] == b'>' {
			let mut packet_hash:[u8;8] = [0;8];
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&bottle);
			sha3.finalize(&mut packet_hash);
			self.unacked_packets.insert(packet_hash,(bottle,Local::now().timestamp_millis(),0));
		}
		return Ok(());
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
			let packet_contents:&Vec<u8> = &(unacked_packet.1).0;
			let packet_timestamp:&i64 = &(unacked_packet.1).1;
			let packet_tries:&u64 = &(unacked_packet.1).2;
			let current_packet_tries:u64 = *packet_tries+1;
			// if the packet's timestamp is a while ago, resend it.
			if *packet_timestamp < now-self.time_tolerance_ms {
				match self.send_raw(&packet_contents) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
				if current_packet_tries < self.max_resend_tries {
					self.unacked_packets.insert(packet_hash.clone(),(packet_contents.clone(),packet_timestamp.clone(),current_packet_tries));
					self.event_log.push_back(Event {
						class:EventClass::DeliveryRetry,
						initiator_id:b"local".to_vec(),
						initiator_address:None,
						parameter:packet_hash.to_vec(),
						contents:packet_contents.clone(),
						timestamp:packet_timestamp.clone(),
					});
				} else {
					self.unacked_packets.remove(packet_hash);
					self.event_log.push_back(Event {
						class:EventClass::DeliveryFailure,
						initiator_id:b"local".to_vec(),
						initiator_address:None,
						parameter:packet_hash.to_vec(),
						contents:packet_contents.clone(),
						timestamp:packet_timestamp.clone(),
					});
				}
			}
		}
		return Ok(());
	}

	// transmits a subscription request packet. server will return 0x06 if
	// we are already subscribed, 0x02 if we were not subscribed but are now,
	// 0x15 if something's wrong (e.g. server full) or an unreadable packet
	// if we have the wrong pad file.
	pub fn subscribe(&mut self) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x02],&vec![]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		self.event_log.push_back(Event {
			class:EventClass::Subscribe,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:vec![],
			contents:vec![],
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
	}

	// sends a cancellation of subscription to the server. server will return
	// 0x19 if it hears us.
	pub fn unsubcribe(&mut self) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x18],&vec![]) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		self.event_log.push_back(Event {
			class:EventClass::Unsubscribe,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:vec![],
			contents:vec![],
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
	}

	// updates the local 'name' (unique identifier) field in the client object, 
	// and also sends the new name to the server.
	pub fn set_name(&mut self,name:&str) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x01],&name.as_bytes().to_vec()) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		self.name = name.to_owned();
		self.event_log.push_back(Event {
			class:EventClass::NameUpdate,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:vec![],
			contents:name.as_bytes().to_vec(),
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
	}

	// adds an additional class (non-unique group identifier) to the local 
	// 'classes' field, and sends the new class to the server.
	pub fn add_class(&mut self,class:&str) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x11],&class.as_bytes().to_vec()) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		self.classes.push(class.to_owned());
		self.event_log.push_back(Event {
			class:EventClass::ClassAdd,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:vec![],
			contents:class.as_bytes().to_vec(),
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
	}

	// removes a class from the local 'classes' field, and sends the removal to
	// the server.
	pub fn remove_class(&mut self,class:&str) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x12],&class.as_bytes().to_vec()) {
			Err(why) => return Err(why),
			Ok(_) => (),
		};
		for n in (0..self.classes.len()).rev() {
			if &self.classes[n] == class {
				self.classes.remove(n);
			}
		}
		self.event_log.push_back(Event {
			class:EventClass::ClassRemove,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:vec![],
			contents:class.as_bytes().to_vec(),
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
	}

} // impl Client

// subscription object for tracking subscribed clients. constructed only by the
// receive_packets method when it receives a valid but unrecognized message 
// (not intended to be constructed directly).
#[derive(Clone)]
pub struct Subscription {
	pub address:SocketAddr,																	// socket address of subscriber
	pub name:String,																				// subscriber's self-declared name
	pub classes:Vec<String>,																// subscriber's self-declared classes
	pub uptime:i64,																					// time at which this subscription was created
	pub unacked_packets:HashMap<[u8;8],(Vec<u8>,i64,u64)>,	// packets that need to be resent if they aren't acknowledged
	pub delivery_failures:u64,
}

// server object for holding server parameters and subscriptions.
pub struct Server {
	pub name:String,
	pub socket:UdpSocket,
	pub subscribers:HashMap<SocketAddr,Subscription>,
	pub max_subscribers:usize,
	pub recent_packets:VecDeque<[u8;8]>,
	pub max_recent_packets:usize,
	pub max_unsent_packets:usize,
	pub max_resend_tries:u64,
	pub max_resend_failures:u64,
	pub event_log:VecDeque<Event>,
	pub crypt:Crypt,
	pub receive_queue:VecDeque<Packet>,
	pub uptime:i64,
	pub synchronous:bool,
	pub time_tolerance_ms:i64
}

// server constructor, works very similarly to client constructor
pub fn new_server(name:&str,pad_path:&str,port:u16) -> Result<Server,io::Error> {
	let new_crypt:Crypt = match new_crypt(&pad_path) {
		Err(why) => return Err(why),
		Ok(crypt) => crypt,
	};
	match UdpSocket::bind(&format!("0.0.0.0:{}",port)) {
		Err(why) => return Err(why),
		Ok(socket) => {
			let mut created_server = Server {
				name:name.to_owned(),
				socket:socket,
				subscribers:HashMap::new(),
				max_subscribers:1024,
				recent_packets:VecDeque::new(),
				event_log:VecDeque::new(),
				max_recent_packets:64,
				max_unsent_packets:32,
				max_resend_tries:10,
				max_resend_failures:10,
				crypt:new_crypt,
				receive_queue:VecDeque::new(),
				uptime:Local::now().timestamp_millis(),
				synchronous:true,
				time_tolerance_ms:3000,
			};
			created_server.event_log.push_back(Event {
				class:EventClass::Create,
				initiator_id:b"local".to_vec(),
				initiator_address:None,
				parameter:vec![],
				contents:vec![],
				timestamp:Local::now().timestamp_millis(),
			});
			return Ok(created_server);
		},
	};
}

impl Server {

	pub fn decrypt_packet(&self,bottle:&Vec<u8>,source_address:&SocketAddr) -> Packet {
		let now:i64 = Local::now().timestamp_millis();
		let mut decrypted_bytes:Vec<u8> = Vec::new();
		let mut timestamp:i64 = 0;
		let mut message_valid:bool = false;
		let mut sender_bytes:Vec<u8> = Vec::new();
		let mut parameter_bytes:Vec<u8> = Vec::new();
		let mut payload_bytes:Vec<u8> = Vec::new();
		if bottle.len() >= 24 {
			let decryption = self.crypt.decrypt(&bottle);
			decrypted_bytes = decryption.0;
			timestamp = decryption.1;
			message_valid = decryption.2;
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

	pub fn link_server(&mut self,remote_address:&SocketAddr) -> Result<(),io::Error> {
		let server_name:String = self.name.clone();
		let mut current_timeout:Option<Duration> = None;
		if let Ok(timeout) = self.socket.read_timeout() {
			current_timeout = timeout;
		}
		let send_fail = Event {
			class:EventClass::ServerLinkFailure,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:b"transmitting packet failed".to_vec(),
			contents:format!("{}",&remote_address).as_bytes().to_vec(),
			timestamp:Local::now().timestamp_millis(),
		};
		match self.socket.set_read_timeout(Some(
			Duration::new((self.time_tolerance_ms/1000) as u64,(self.time_tolerance_ms%1000) as u32))) {
			Err(why) => {
				self.event_log.push_back(send_fail);
				return Err(why);
			},
			Ok(_) => (),
		};
		match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),&vec![0x02],&vec![],&remote_address) {
			Err(why) => {
				self.event_log.push_back(send_fail);
				return Err(why);
			},
			Ok(_) => (),
		};
		let mut input_buffer:[u8;8192] = [0;8192];
		let wait_start:i64 = Local::now().timestamp_millis();
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => {
						self.event_log.push_back(Event {
							class:EventClass::ServerLinkFailure,
							initiator_id:b"local".to_vec(),
							initiator_address:None,
							parameter:b"no response".to_vec(),
							contents:format!("{}",&remote_address).as_bytes().to_vec(),
							timestamp:Local::now().timestamp_millis(),
						});
						return Err(io::Error::new(io::ErrorKind::NotFound,"no response from server"));
					},
					_ => {
						self.event_log.push_back(Event {
							class:EventClass::ServerLinkFailure,
							initiator_id:b"local".to_vec(),
							initiator_address:None,
							parameter:b"receiving response failed".to_vec(),
							contents:format!("{}",&remote_address).as_bytes().to_vec(),
							timestamp:Local::now().timestamp_millis(),
						});
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					let received_packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
					if received_packet.parameter.len() > 0 && &source_address == remote_address {
						match received_packet.parameter[0] {
							0x06 => break,
							0x02 => break,
							0x15 => {
								self.event_log.push_back(Event {
									class:EventClass::ServerLinkFailure,
									initiator_id:b"local".to_vec(),
									initiator_address:None,
									parameter:b"connection refused".to_vec(),
									contents:format!("{}",&remote_address).as_bytes().to_vec(),
									timestamp:Local::now().timestamp_millis(),
								});
								return Err(io::Error::new(io::ErrorKind::ConnectionRefused,"connection refused by server"));
							},
							_ => continue,
						}
					}
				},
			};
			if Local::now().timestamp_millis() > wait_start+self.time_tolerance_ms {
				self.event_log.push_back(Event {
					class:EventClass::ServerLinkFailure,
					initiator_id:b"local".to_vec(),
					initiator_address:None,
					parameter:b"no response".to_vec(),
					contents:format!("{}",&remote_address).as_bytes().to_vec(),
					timestamp:Local::now().timestamp_millis(),
				});
				return Err(io::Error::new(io::ErrorKind::NotFound,"no response from server"));
			}
		}
		match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),&vec![0x12],&b"server".to_vec(),
			&remote_address) {
			Err(why) => {
				self.event_log.push_back(send_fail);
				return Err(why);
			},
			Ok(_) => (),
		};
		match self.socket.set_read_timeout(current_timeout) {
			Err(why) => {
				self.event_log.push_back(send_fail);
				return Err(why);
			},
			Ok(_) => (),
		};
		self.event_log.push_back(Event {
			class:EventClass::ServerLink,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:vec![],
			contents:format!("{}",&remote_address).as_bytes().to_vec(),
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
	}

	// encrypts and transmits a packet, much like the client version.
	pub fn send_packet(&mut self,sender:&Vec<u8>,parameter:&Vec<u8>,payload:&Vec<u8>,address:&SocketAddr) 
		-> Result<(),io::Error> {
		let mut message:Vec<u8> = Vec::new();
		message.push(sender.len() as u8);
		message.append(&mut sender.clone());
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let bottle:Vec<u8> = self.crypt.encrypt(&message);
		match self.socket.send_to(&bottle[..],&address) {
			Err(why) => {
				self.event_log.push_back(Event {
					class:EventClass::SendFailure,
					initiator_id:b"local".to_vec(),
					initiator_address:None,
					parameter:vec![],
					contents:format!("{}",why).as_bytes().to_vec(),
					timestamp:Local::now().timestamp_millis(),
				});
				return Err(why);
			},
			Ok(_) => (),
		}
		if parameter.len() > 0 && parameter[0] == b'>' {
			let mut packet_hash:[u8;8] = [0;8];
			let mut sha3 = Keccak::new_sha3_256();
			sha3.update(&bottle);
			sha3.finalize(&mut packet_hash);
			if let Some(sub) = self.subscribers.get_mut(&address) {
				sub.unacked_packets.insert(packet_hash,(bottle,Local::now().timestamp_millis(),0));
			}
		}
		self.event_log.push_back(Event {
			class:EventClass::SendMessage,
			initiator_id:b"local".to_vec(),
			initiator_address:None,
			parameter:parameter.clone(),
			contents:payload.clone(),
			timestamp:Local::now().timestamp_millis(),
		});
		return Ok(());
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
					_ => {
						self.event_log.push_back(Event {
							class:EventClass::ReceiveFailure,
							initiator_id:b"local".to_vec(),
							initiator_address:None,
							parameter:vec![],
							contents:format!("{}",why).as_bytes().to_vec(),
							timestamp:Local::now().timestamp_millis(),
						});
						sleep(Duration::new(0,100));
						return Err(why);
					},
				},
				Ok((receive_length,source_address)) => {
					let server_name:String = self.name.clone();
					let received_packet:Packet = self.decrypt_packet(&input_buffer[..receive_length].to_vec(),&source_address);
					if !self.subscribers.contains_key(&source_address) {
						if received_packet.valid && self.subscribers.len() < self.max_subscribers {
							self.subscribers.insert(source_address.clone(),Subscription {
								address:source_address.clone(),
								name:String::new(),
								classes:Vec::new(),
								uptime:Local::now().timestamp_millis(),
								unacked_packets:HashMap::new(),
								delivery_failures:0,
							});	
							match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
								&vec![0x02],&vec![],&source_address) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							self.event_log.push_back(Event {
								class:EventClass::Subscribe,
								initiator_id:received_packet.sender.clone(),
								initiator_address:Some(source_address.clone()),
								parameter:b"accepted".to_vec(),
								contents:vec![],
								timestamp:Local::now().timestamp_millis(),
							});
						} else {
							match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
								&vec![0x15],&vec![],&source_address) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
							self.event_log.push_back(Event {
								class:EventClass::Subscribe,
								initiator_id:received_packet.sender.clone(),
								initiator_address:Some(source_address.clone()),
								parameter:b"rejected".to_vec(),
								contents:vec![],
								timestamp:Local::now().timestamp_millis(),
							});
						}
					}
					if received_packet.parameter.len() > 0 {
						match (received_packet.parameter[0],received_packet.payload.len()) {
							(0x06,8) => {
								let mut acked_hash:[u8;8] = [0;8];
								acked_hash.copy_from_slice(&received_packet.payload[..]);
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									let _ = sub.unacked_packets.remove(&acked_hash);
								}
								self.event_log.push_back(Event {
									class:EventClass::Acknowledge,
									initiator_id:received_packet.sender.clone(),
									initiator_address:Some(source_address.clone()),
									parameter:vec![],
									contents:acked_hash.to_vec(),
									timestamp:Local::now().timestamp_millis(),
								});
							},
							(0x06,_) => {
								self.event_log.push_back(Event {
									class:EventClass::Acknowledge,
									initiator_id:received_packet.sender.clone(),
									initiator_address:Some(source_address.clone()),
									parameter:vec![],
									contents:vec![],
									timestamp:Local::now().timestamp_millis(),
								});
							},
							(0x02,0) => (),
							(0x18,0) => {
								let _ = self.subscribers.remove(&source_address);
								match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
									&vec![0x19],&vec![],&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
								self.event_log.push_back(Event {
									class:EventClass::Unsubscribe,
									initiator_id:received_packet.sender.clone(),
									initiator_address:Some(source_address.clone()),
									parameter:vec![],
									contents:vec![],
									timestamp:Local::now().timestamp_millis(),
								});
							},
							(0x01,_) => {
								let new_name:String = String::from_utf8_lossy(&received_packet.payload).to_string();
								let mut name_valid:bool = true;
								for c in ['&','|',' ','!','^'].iter() {
									if new_name.contains(*c) {
										name_valid = false;
										break;
									}
								}
								if new_name.as_bytes().len() > 128 {
									name_valid = false;
								}
								if name_valid {
									if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
										sub.name = new_name.clone();
									}
									match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
										&vec![0x06],&vec![],&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
									self.event_log.push_back(Event {
										class:EventClass::NameUpdate,
										initiator_id:received_packet.sender.clone(),
										initiator_address:Some(source_address.clone()),
										parameter:vec![],
										contents:new_name.as_bytes().to_vec(),
										timestamp:Local::now().timestamp_millis(),
									});
								} else {
									match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
										&vec![0x15],&vec![],&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
									self.event_log.push_back(Event {
										class:EventClass::NameUpdateFailure,
										initiator_id:received_packet.sender.clone(),
										initiator_address:Some(source_address.clone()),
										parameter:vec![],
										contents:new_name.as_bytes().to_vec(),
										timestamp:Local::now().timestamp_millis(),
									});
								}
							},
							(0x11,_) => {
								let new_class:String = String::from_utf8_lossy(&received_packet.payload).to_string();
								let mut class_valid:bool = true;
								for c in ['&','|',' ','!','^'].iter() {
									if new_class.contains(*c) {
										class_valid = false;
										break;
									}
								}
								if new_class.as_bytes().len() > 128 {
									class_valid = false;
								}
								if class_valid {
									if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
										if !sub.classes.contains(&new_class) {
											sub.classes.push(new_class.clone());
										}
									}
									match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
										&vec![0x06],&vec![],&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
									self.event_log.push_back(Event {
										class:EventClass::ClassAdd,
										initiator_id:received_packet.sender.clone(),
										initiator_address:Some(source_address.clone()),
										parameter:vec![],
										contents:new_class.as_bytes().to_vec(),
										timestamp:Local::now().timestamp_millis(),
									});
								} else {
									match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
										&vec![0x15],&vec![],&source_address) {
										Err(why) => return Err(why),
										Ok(_) => (),
									};
									self.event_log.push_back(Event {
										class:EventClass::ClassAddFailure,
										initiator_id:received_packet.sender.clone(),
										initiator_address:Some(source_address.clone()),
										parameter:vec![],
										contents:new_class.as_bytes().to_vec(),
										timestamp:Local::now().timestamp_millis(),
									});
								}
							},
							(0x12,_) => {
								let deleted_class:String = String::from_utf8_lossy(&received_packet.payload).to_string();
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									for n in (0..sub.classes.len()).rev() {
										if sub.classes[n] == deleted_class {
											sub.classes.remove(n);
										}
									}
								}
								match self.send_packet(&format!("@{}/#server",&server_name).as_bytes().to_vec(),
									&vec![0x06],&vec![],&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
								self.event_log.push_back(Event {
									class:EventClass::ClassRemove,
									initiator_id:received_packet.sender.clone(),
									initiator_address:Some(source_address.clone()),
									parameter:vec![],
									contents:deleted_class.as_bytes().to_vec(),
									timestamp:Local::now().timestamp_millis(),
								});
							},
							(0x13,0) => {
								if let Some(mut sub) = self.subscribers.clone().get(&source_address) {
									self.event_log.push_back(Event {
										class:EventClass::ClassListRequest,
										initiator_id:received_packet.sender.clone(),
										initiator_address:Some(source_address.clone()),
										parameter:vec![],
										contents:vec![],
										timestamp:Local::now().timestamp_millis(),
									});
									for class in sub.classes.iter() {
										match self.send_packet(&vec![],&vec![0x13],&class.as_bytes().to_vec(),&source_address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
										self.event_log.push_back(Event {
											class:EventClass::ClassListResponse,
											initiator_id:received_packet.sender.clone(),
											initiator_address:Some(source_address.clone()),
											parameter:vec![],
											contents:class.as_bytes().to_vec(),
											timestamp:Local::now().timestamp_millis(),
										});
									}
								}
							}
							(b'>',_) => {
								let mut packet_hash:[u8;8] = [0;8];
								let mut sha3 = Keccak::new_sha3_256();
								sha3.update(&input_buffer[..receive_length]);
								sha3.finalize(&mut packet_hash);
								match self.send_packet(&vec![],&vec![0x06],&packet_hash.to_vec(),&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
								self.receive_queue.push_back(received_packet);
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
		for sub in self.subscribers.clone().iter() {
			// retransmit packets that haven't been acknowledged and were last sent a while ago.
			if sub.1.unacked_packets.len() > self.max_unsent_packets {
				if let Some(mut list_sub) = self.subscribers.get_mut(&sub.0) {
					list_sub.unacked_packets.clear();
				}
				if !sub.1.classes.contains(&"server".to_owned()) {
					self.subscribers.remove(&sub.0);
					continue;
				}
			}
			if sub.1.delivery_failures > self.max_resend_failures {
				if !sub.1.classes.contains(&"server".to_owned()) {
					self.subscribers.remove(&sub.0);
					continue;
				}
			}
			for unacked_packet in sub.1.unacked_packets.iter() {
				let packet_hash:&[u8;8] = &unacked_packet.0;
				let packet_contents:&Vec<u8> = &(unacked_packet.1).0;
				let packet_timestamp:&i64 = &(unacked_packet.1).1;
				let packet_tries:&u64 = &(unacked_packet.1).2;
				let current_tries:u64 = *packet_tries+1;
				// if the packet's timestamp is a while ago, resend it.
				if *packet_timestamp < now-self.time_tolerance_ms {
					match self.send_raw(&packet_contents,&sub.0) {
						Err(why) => return Err(why),
						Ok(_) => (),
					};
					// after resending a packet, update its timestamp in the original subscriber list.
					if let Some(list_sub) = self.subscribers.get_mut(&sub.0) {
						if current_tries < self.max_resend_tries {
							list_sub.unacked_packets.insert(packet_hash.clone(),(packet_contents.clone(),now.clone(),current_tries));
						} else {
							list_sub.unacked_packets.remove(packet_hash);
							list_sub.delivery_failures += 1;
						}			
					}
				}
			}
		}
		return Ok(());
	}

	pub fn relay_packet(&mut self,packet:&Packet) -> Result<(),io::Error> {
		if !packet.valid {
			self.event_log.push_back(Event {
				class:EventClass::InvalidMessage,
				initiator_id:packet.sender.clone(),
				initiator_address:Some(packet.source.clone()),
				parameter:packet.parameter.clone(),
				contents:packet.payload.clone(),
				timestamp:Local::now().timestamp_millis(),
			});
			return Ok(());
		}
		let mut packet_hash:[u8;8] = [0;8];
		let mut sha3 = Keccak::new_sha3_256();
		sha3.update(&packet.raw);
		sha3.finalize(&mut packet_hash);
		if self.recent_packets.contains(&packet_hash) {
			self.event_log.push_back(Event {
				class:EventClass::HaltedMessage,
				initiator_id:packet.sender.clone(),
				initiator_address:Some(packet.source.clone()),
				parameter:packet.parameter.clone(),
				contents:packet.payload.clone(),
				timestamp:Local::now().timestamp_millis(),
			});
			return Ok(());
		}
		let send:bool = packet.payload.len() > 0;
		let mut number_matched:u64 = 0;
		for sub in self.subscribers.clone().iter_mut() {
			let mut subscriber_identifiers:String = String::new();
			subscriber_identifiers.push_str(&format!("@{} ",&sub.1.name));
			for class in sub.1.classes.iter() {
				subscriber_identifiers.push_str(&format!("#{} ",&class));
			}
			if &packet.source != sub.0 && packet.parameter.len() >= 1 && packet.parameter[0] == b'>'
				&& (wordmatch(&String::from_utf8_lossy(&packet.parameter[1..]).to_string(),&subscriber_identifiers) 
				|| sub.1.classes.contains(&"supervisor".to_owned())
				|| sub.1.classes.contains(&"server".to_owned())) {
				if send {
					match self.send_raw(&packet.raw,&sub.0) {
						Err(why) => return Err(why),
						Ok(_) => (),
					};
					self.recent_packets.push_back(packet_hash.clone());
					if self.recent_packets.len() > self.max_recent_packets {
						let _ = self.recent_packets.pop_front();
					}
				}	
				number_matched += 1;
				if let Some(mut listed_sub) = self.subscribers.get_mut(&sub.0) {
					listed_sub.unacked_packets.insert(packet_hash.clone(),(packet.raw.clone(),packet.timestamp.clone(),0));
				}
			}
			if send {
				match self.send_packet(&vec![],&vec![0x06],&u64_to_bytes(&number_matched).to_vec(),&packet.source) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
			} else {
				match self.send_packet(&vec![],&vec![0x03],&u64_to_bytes(&number_matched).to_vec(),&packet.source) {
					Err(why) => return Err(why),
					Ok(_) => (),
				};
			}
		}
		if !send {
			self.event_log.push_back(Event {
				class:EventClass::TestMessage,
				initiator_id:packet.sender.clone(),
				initiator_address:Some(packet.source.clone()),
				parameter:packet.parameter.clone(),
				contents:packet.payload.clone(),
				timestamp:Local::now().timestamp_millis(),
			});
		} else if number_matched == 0 {
			self.event_log.push_back(Event {
				class:EventClass::DeadEndMessage,
				initiator_id:packet.sender.clone(),
				initiator_address:Some(packet.source.clone()),
				parameter:packet.parameter.clone(),
				contents:packet.payload.clone(),
				timestamp:Local::now().timestamp_millis(),
			});
		} else if packet.parameter.len() > 1 {
			self.event_log.push_back(Event {
				class:EventClass::RoutedMessage,
				initiator_id:packet.sender.clone(),
				initiator_address:Some(packet.source.clone()),
				parameter:packet.parameter.clone(),
				contents:packet.payload.clone(),
				timestamp:Local::now().timestamp_millis(),
			});
		} else {
			self.event_log.push_back(Event {
				class:EventClass::GlobalMessage,
				initiator_id:packet.sender.clone(),
				initiator_address:Some(packet.source.clone()),
				parameter:packet.parameter.clone(),
				contents:packet.payload.clone(),
				timestamp:Local::now().timestamp_millis(),
			});
		}
		return Ok(());
	}

} // impl Server
