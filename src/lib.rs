// Teamech v 0.7.1 September 2018

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
use std::net::{UdpSocket,SocketAddr};

// converts a collection of bytes into UTF-8 characters
fn bytes_to_chars(bytes:&Vec<u8>) -> Vec<char> {
	return String::from_utf8_lossy(&bytes).chars().collect::<Vec<char>>();
}

// converts a collection of UTF-8 characters into bytes
fn chars_to_bytes(chars:&Vec<char>) -> Vec<u8> {
	return chars.iter().collect::<String>().as_bytes().to_vec();
}

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

fn hash_bytes(input:&Vec<u8>) -> [u8;8] {
	let result:[u8;8] = [0;8];
	let mut sha3 = Keccak::new_sha3_256();
	sha3.update(&input);
	sha3.finalize(&mut result);
	return result;
}

// accepts a boolean expression in the form `(foo|bar)&baz` and determines if it matches a 
// string of words in the form `foo bar baz`
// edge cases:
// - an empty pattern will always return true
// - a malformed or unparseable pattern will return false
// - words containing boolean operators cannot be matched and should not be included
fn wordmatch(pattern:&str,input:&str) -> bool {
	if pattern == "" || input.contains(&pattern) {
		return true;
	}
	let paddedinput:&str = &format!(" {} ",input);
	let ops:Vec<&str> = vec!["!","&","|","^","(",")"];
	let mut fixedpattern:String = String::from(pattern);
	for c in ops.iter() {
		fixedpattern = fixedpattern.replace(c,&format!(" {} ",c));
	}
	for element in fixedpattern.clone().split_whitespace() {
		let paddedelement:&str = &format!(" {} ",element);
		if !ops.contains(&element) {
			if paddedinput.contains(&paddedelement) {
				fixedpattern = fixedpattern.replace(&element,"1");
			} else {
				fixedpattern = fixedpattern.replace(&element,"0");
			}
		}
	}
	fixedpattern = fixedpattern.replace(" ","");
	fixedpattern = fixedpattern.replace("/","&");
	loop {
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
	pad_path:String,
	pad_data:Vec<u8>,
	pad_length:usize,
}

// constructor for a Crypt object. opens a pad file, reads it into
// memory, and returns a Crypt object containing the data.
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
	raw:Vec<u8>,
	decrypted:Vec<u8>,
	valid:bool,
	timestamp:i64,
	source:SocketAddr,
	sender:Vec<u8>,
	parameter:Vec<u8>,
	payload:Vec<u8>,
}

// object representing a Teamech client, with methods for sending and receiving packets.
pub struct Client {
	socket:UdpSocket,
	server_address:SocketAddr,
	name:String,
	classes:Vec<String>,
	crypt:Crypt,
	receive_queue:VecDeque<Packet>,
	uptime:i64,
	last_activity:i64,
	synchronous:bool,
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
		Ok(socket) => return Ok(Client {
			socket:socket,
			server_address:server_address,
			name:String::new(),
			classes:Vec::new(),
			receive_queue:VecDeque::new(),
			crypt:new_crypt,
			uptime:Local::now().timestamp_millis(),
			last_activity:Local::now().timestamp_millis(),
			synchronous:false,
		}),
	};
}

impl Client {

	pub fn set_synchronous(&mut self) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(None) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = true;
				return Ok(());
			},
		};
	}

	pub fn set_asynchronous(&mut self,wait_time_ms:u64) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(Some(Duration::new(wait_time_ms/1000,(wait_time_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = false;
				return Ok(());
			},
		}
	}

	pub fn get_packets(&mut self) -> Result<(),io::Error> {
		let mut input_buffer:[u8;512] = [0;512];
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => break,
					_ => return Err(why),
				},
				Ok((receive_length,source_address)) => {
					if source_address == self.server_address {
						let bottle:Vec<u8> = input_buffer[..receive_length].to_vec();
						let mut decrypted_bytes:Vec<u8> = Vec::new();
						let mut timestamp:i64 = 0;
						let mut message_valid = false;
						let mut sender_bytes:Vec<u8> = Vec::new();
						let mut parameter_bytes:Vec<u8> = Vec::new();
						let mut payload_bytes:Vec<u8> = Vec::new();
						if receive_length >= 24 {
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
						if message_valid {
							match self.send_packet(&vec![0x06],&hash_bytes(&bottle).to_vec()) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
						} else {
							match self.send_packet(&vec![0x15],&hash_bytes(&bottle).to_vec()) {
								Err(why) => return Err(why),
								Ok(_) => (),
							};
						}
						self.receive_queue.push_back(Packet {
							raw:bottle,
							decrypted:decrypted_bytes,
							valid:message_valid,
							timestamp:timestamp,
							source:source_address,
							sender:sender_bytes,
							parameter:parameter_bytes,
							payload:payload_bytes,
						});
					}
				},
			};
			if self.synchronous {
				break;
			}
		}
		return Ok(());
	}

	pub fn send_packet(&self,parameter:&Vec<u8>,payload:&Vec<u8>) -> Result<(),io::Error> {
		let mut message:Vec<u8> = Vec::new();
		let mut primary_class:&str = "";
		if self.classes.len() > 0 {
			primary_class = &self.classes[0];
		}
		let mut sender:Vec<u8> = format!("@{}/#{}",&self.name,&primary_class).as_bytes().to_vec();
		if sender.len() > 240 || parameter.len() > 240 {
			return Err(io::Error::new(io::ErrorKind::InvalidData,"sender string too long"));
		}
		message.push(sender.len() as u8);
		message.append(&mut sender);
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let bottle:Vec<u8> = self.crypt.encrypt(&message);
		match self.socket.send_to(&bottle[..],&self.server_address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		}
	}
	
	pub fn send_raw(&self,message:&Vec<u8>) -> Result<(),io::Error> {
		match self.socket.send_to(&message[..],&self.server_address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn subscribe(&self) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x02],&vec![]) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn unsubcribe(&self) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x18],&vec![]) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn set_name(&self,name:&str) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x01],&name.as_bytes().to_vec()) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn add_class(&self,class:&str) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x11],&class.as_bytes().to_vec()) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn remove_class(&self,class:&str) -> Result<(),io::Error> {
		match self.send_packet(&vec![0x12],&class.as_bytes().to_vec()) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

} // impl Client

pub struct Subscription {
	address:SocketAddr,
	name:String,
	classes:Vec<String>,
	uptime:i64,
	unacked_packets:HashMap<[u8;8],Packet>,
}

pub struct Server {
	socket:UdpSocket,
	subscribers:HashMap<SocketAddr,Subscription>,
	crypt:Crypt,
	receive_queue:VecDeque<Packet>,
	log_queue:VecDeque<String>,
	uptime:i64,
	last_activity:i64,
	synchronous:bool,
	time_tolerance_ms:i64
}

pub fn new_server(pad_path:&str,port:u16) -> Result<Server,io::Error> {
	let new_crypt:Crypt = match new_crypt(&pad_path) {
		Err(why) => return Err(why),
		Ok(crypt) => crypt,
	};
	match UdpSocket::bind(&format!("0.0.0.0:{}",port)) {
		Err(why) => return Err(why),
		Ok(socket) => return Ok(Server {
			socket:socket,
			subscribers:HashMap::new(),
			crypt:new_crypt,
			receive_queue:VecDeque::new(),
			log_queue:VecDeque::new(),
			uptime:Local::now().timestamp_millis(),
			last_activity:Local::now().timestamp_millis(),
			synchronous:false,
			time_tolerance_ms:3000,
		}),
	};
}

impl Server {

	pub fn set_synchronous(&mut self) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(None) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = true;
				return Ok(());
			},
		};
	}

	pub fn set_asynchronous(&mut self,wait_time_ms:u64) -> Result<(),io::Error> {
		match self.socket.set_read_timeout(Some(Duration::new(wait_time_ms/1000,(wait_time_ms%1000) as u32))) {
			Err(why) => return Err(why),
			Ok(_) => {
				self.synchronous = false;
				return Ok(());
			},
		}
	}

	pub fn send_packet(&self,sender:&Vec<u8>,parameter:&Vec<u8>,payload:&Vec<u8>,address:&SocketAddr) 
		-> Result<(),io::Error> {
		if sender.len() > 240 || parameter.len() > 240 {
			return Err(io::Error::new(io::ErrorKind::InvalidData,"sender string too long"));
		}
		let mut message:Vec<u8> = Vec::new();
		message.push(sender.len() as u8);
		message.append(&mut sender.clone());
		message.push(parameter.len() as u8);
		message.append(&mut parameter.clone());
		message.append(&mut payload.clone());
		let bottle:Vec<u8> = self.crypt.encrypt(&message);
		match self.socket.send_to(&bottle[..],&address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		}
	}
	
	pub fn send_raw(&self,message:&Vec<u8>,address:&SocketAddr) -> Result<(),io::Error> {
		match self.socket.send_to(&message[..],&address) {
			Err(why) => return Err(why),
			Ok(_) => return Ok(()),
		};
	}

	pub fn log(&mut self,logline:&str) {
		let timestamp:DateTime<Local> = Local::now();
		let timestamp_millis:i64 = timestamp.timestamp_millis();
		let timestamp_str:String = timestamp.format("%Y-%m-%d %H:%M:%S%.6f").to_string();
		self.log_queue.push_back(format!("[{}][{}] {}",&timestamp_millis,&timestamp_str,&logline));
	}

	pub fn get_packets(&mut self) -> Result<(),io::Error> {
		let mut input_buffer:[u8;512] = [0;512];
		loop {
			match self.socket.recv_from(&mut input_buffer) {
				Err(why) => match why.kind() {
					io::ErrorKind::WouldBlock => break,
					_ => return Err(why),
				},
				Ok((receive_length,source_address)) => {
					let now:i64 = Local::now().timestamp_millis();
					let bottle:Vec<u8> = input_buffer[..receive_length].to_vec();
					let mut decrypted_bytes:Vec<u8> = Vec::new();
					let mut timestamp:i64 = 0;
					let mut message_valid:bool = false;
					let mut sender_bytes:Vec<u8> = Vec::new();
					let mut parameter_bytes:Vec<u8> = Vec::new();
					let mut payload_bytes:Vec<u8> = Vec::new();
					if receive_length >= 24 {
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
					if message_valid && !self.subscribers.contains_key(&source_address) {
						self.subscribers.insert(source_address.clone(),Subscription {
							address:source_address.clone(),
							name:String::new(),
							classes:Vec::new(),
							uptime:Local::now().timestamp_millis(),
							unacked_packets:HashMap::new(),
						});	
						match self.send_packet(&vec![],&vec![0x02],&vec![],&source_address) {
							Err(why) => return Err(why),
							Ok(_) => (),
						};
					}
					if parameter_bytes.len() > 0 {
						match (parameter_bytes[0],payload_bytes.len()) {
							(0x06,8) => {
								let mut acked_hash:[u8;8] = [0;8];
								acked_hash.copy_from_slice(&payload_bytes[..]);
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									let _ = sub.unacked_packets.remove(&acked_hash);
								}
							},
							(0x06,_) => (),
							(0x02,0) => (),
							(0x18,0) => {
								let _ = self.subscribers.remove(&source_address);
							},
							(0x01,_) => {
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									let new_name:String = String::from_utf8_lossy(&payload_bytes).to_string();
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
										sub.name = new_name;
									}
								}
							},
							(0x11,_) => {
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									let new_class:String = String::from_utf8_lossy(&payload_bytes).to_string();
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
									if class_valid && !sub.classes.contains(&new_class) {
										sub.classes.push(new_class);
									}
								}
							},
							(0x12,_) => {
								if let Some(mut sub) = self.subscribers.get_mut(&source_address) {
									let deleted_class:String = String::from_utf8_lossy(&payload_bytes).to_string();
									for n in (0..sub.classes.len()).rev() {
										if sub.classes[n] == deleted_class {
											sub.classes.remove(n);
										}
									}
								}
							},
							(0x13,0) => {
								if let Some(mut sub) = self.subscribers.get(&source_address) {
									for class in sub.classes.iter() {
										match self.send_packet(&vec![],&vec![0x13],&class.as_bytes().to_vec(),&source_address) {
											Err(why) => return Err(why),
											Ok(_) => (),
										};
									}
								}
							}
							(b'@',_) => {
								match self.send_packet(&vec![],&vec![0x06],&hash_bytes(&bottle).to_vec(),&source_address) {
									Err(why) => return Err(why),
									Ok(_) => (),
								};
								let payload_string:String = String::from_utf8_lossy(&payload_bytes).to_string();
								let parameter_string:String = String::from_utf8_lossy(&parameter_bytes).to_string();
								let mut sender_name:String = "unknown".to_owned();
								let mut sender_class:String = "unknown".to_owned();
								if let Some(sub) = self.subscribers.get(&source_address) {
									sender_name = sub.name.clone();
									if sub.classes.len() > 0 {
										sender_class = sub.classes[0].clone();
									}
								}
								let mut message_status:&str = "OK";
								if !message_valid {
									message_status = "INVALID";
								} else if timestamp > now+self.time_tolerance_ms {
									message_status = "FUTURE";
									message_valid = false;
								} else if timestamp < now-self.time_tolerance_ms {
									message_status = "OUTDATED";
									message_valid = false;
								}
								self.log(&format!("[{}] @{}/#{} -> {}",&message_status,&sender_name,&sender_class,&payload_string));
								self.receive_queue.push_back(Packet {
									raw:bottle,
									decrypted:decrypted_bytes,
									valid:message_valid,
									timestamp:timestamp,
									source:source_address,
									sender:sender_bytes,
									parameter:parameter_bytes,
									payload:payload_bytes,
								});
							},
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

	pub fn relay_packet(&self,packet:&Packet) -> Result<(),io::Error> {
		if !packet.valid {
			return Ok(());
		}
		let send:bool = packet.payload.len() > 0;
		let mut number_matched:u64 = 0;
		for sub in self.subscribers.iter() {
			let mut subscriber_identifiers:String = String::new();
			subscriber_identifiers.push_str(&format!("@{} ",&sub.1.name));
			for class in sub.1.classes.iter() {
				subscriber_identifiers.push_str(&format!("#{} ",&class));
			}
			if &packet.source != sub.0 
				&& (wordmatch(&String::from_utf8_lossy(&packet.parameter).to_string(),&subscriber_identifiers) 
				|| sub.1.classes.contains(&"supervisor".to_owned())) {
				if send {
					match self.send_raw(&packet.raw,&sub.0) {
						Err(why) => return Err(why),
						Ok(_) => (),
					};
				}
				number_matched += 1;
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
		return Ok(());
	}

} // impl Server
