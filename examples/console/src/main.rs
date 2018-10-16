static VERSION:&str = "0.9.0 October 2018";
static LOG_DIRECTORY:&str = ".teamech-logs/console";
static PROMPT:&str = "[teamech]~ ";
static BAR:char = '━';
static BARSTOP_LEFT:char = '┫';
static BARSTOP_RIGHT:char = '┣';

extern crate teamech;

extern crate pancurses;
use pancurses::*;

extern crate dirs;
use dirs::home_dir;

#[macro_use]
extern crate clap;

extern crate chrono;
use chrono::prelude::*;

use std::env::set_var;
use std::time::Duration;
use std::thread::sleep;
use std::process;
use std::fs;
use std::io::prelude::*;
use std::io;
use std::fs::File;
use std::path::{Path,PathBuf};
use std::collections::VecDeque;

struct WindowLogger {
	history:Vec<(String,String)>,
	window:Window,
	log_file_name:String,
	console_line:Vec<char>,
	line_history:Vec<Vec<char>>,
	history_position:usize,
	page_position:usize,
	line_position:usize,
	local_lines:VecDeque<Vec<u8>>,
	sent_lines:VecDeque<(String,usize)>,
}

fn new_windowlogger(log_file_name:&str) -> WindowLogger {
	return WindowLogger {
		history:Vec::new(),
		window:initscr(),
		log_file_name:log_file_name.to_owned(),
		console_line:Vec::new(),
		line_history:Vec::new(),
		history_position:0,
		page_position:0,
		line_position:0,
		local_lines:VecDeque::new(),
		sent_lines:VecDeque::new(),
	};
}

impl WindowLogger {

	// prints a line to the ncurses window - useful for condensing this common and lengthy invocation elsewhere.
	fn print(&mut self,line:&str) {
		self.history.push((line.to_owned(),String::new()));
		let mut lines:Vec<String> = Vec::new();
		let max_length:usize = (self.window.get_max_x() as usize)-8;
		let mut temp_line:String = line.to_owned();
		while temp_line.len() > max_length { 
			lines.push(temp_line[0..max_length].to_owned());
			temp_line = temp_line[max_length..temp_line.len()].to_owned();
		}
		lines.push(temp_line);
		lines.reverse();
		for newline in lines.iter() {
			self.window.mv(self.window.get_max_y()-2,0);
			self.window.clrtoeol();
			self.window.addstr(&newline);
			self.window.mv(0,0);
			self.window.insdelln(-1);
		}
		let title:String = format!("{}{} Teamech Console {} {}",&BAR,&BARSTOP_LEFT,&VERSION,&BARSTOP_RIGHT);
		self.window.mv(0,0);
		self.window.addstr(&title);
		if self.window.get_max_x() as usize > 21+&VERSION.len()+10 {
			for _x in 0..(self.window.get_max_x() as usize)-&VERSION.len()-21 {
				self.window.addstr(BAR.encode_utf8(&mut [0;4]));
			}
		}
		self.window.attrset(Attribute::Normal);
		self.window.mv(self.window.get_max_y()-2,0);
		self.window.clrtoeol();
		for _x in 0..self.window.get_max_x() {
			self.window.addstr(BAR.encode_utf8(&mut [0;4]));
		}
		self.window.attrset(Attribute::Normal);
		self.window.mv(self.window.get_max_y()-1,0);
		self.window.clrtoeol();
		self.window.addstr(&PROMPT);
		self.window.refresh();
	}

	fn print_left(&mut self,line:&str,position:usize) {
		if self.history.len() > position {
			self.history[position].1 = line.to_owned();
		}
		if (position as i32)-(self.history_position as i32) > 0 
			&& (position as i32)-(self.history_position as i32)-(self.history.len() as i32) < self.window.get_max_y()-2 {
			self.window.mv(
				self.window.get_max_y()-3+((position as i32)-(self.history.len() as i32)+1)+(self.history_position as i32),
				self.window.get_max_x()-(line.len() as i32)-1
			);
			self.window.clrtoeol();
			self.window.addstr(&line);
			self.window.attrset(Attribute::Normal);
			self.window.mv(self.window.get_max_y()-1,0);
			self.window.clrtoeol();
			self.window.mv(self.window.get_max_y(),0);
			self.window.clrtoeol();
			self.window.addstr(&PROMPT);
			for ch in self.console_line.iter() {
				self.window.addch(*ch);
			}
			self.window.refresh();
		}
	}

	// prints a line to the ncurses window and also logs it.
	fn log(&mut self,line:&str) {
		self.silent_log(&line);
		self.print(&format!("[{}] {}",Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),&line));
	}

	fn page(&mut self,page_position:&usize) {
		if self.window.get_max_y() < 3 {
			return;
		}
		let pagesize:usize = (self.window.get_max_y() as usize)-3;
		let pagebottom:usize; 
		if page_position <= &self.history.len() {
			pagebottom = self.history.len()-page_position;
		} else {
			return;
		}
		let pagetop:usize;
		if pagesize <= pagebottom {
			pagetop = pagebottom-pagesize;
		} else {
			pagetop = 0;
		}
		self.window.clear();
		let mut subhistorytmp:Vec<(String,String)> = self.history[pagetop..pagebottom].to_vec();
		if subhistorytmp.len() < pagesize {
			subhistorytmp.reverse();
			while subhistorytmp.len() < pagesize {
				subhistorytmp.push((String::new(),String::new()));
			}
			subhistorytmp.reverse();
		}
		let mut subhistory:Vec<(String,String)> = Vec::new();
		let maxlinelen:usize = (self.window.get_max_x() as usize)-7;
		while let Some(mut subline) = subhistorytmp.pop() {
			let mut tempstack:Vec<(String,String)> = Vec::new();
			while subline.0.len() > maxlinelen {
				tempstack.push((subline.0[0..maxlinelen].to_owned(),String::new()));
				subline.0 = subline.0[maxlinelen..subline.0.len()].to_owned();
			}
			tempstack.push(subline);
			tempstack.reverse();
			subhistory.append(&mut tempstack);
		}
		while subhistory.len() >= (self.window.get_max_y() as usize)-2 {
			let _ = subhistory.pop();
		}
		subhistory.reverse();
		let title:String = format!("{}{} Teamech Console {} {}",&BAR,&BARSTOP_LEFT,&VERSION,&BARSTOP_RIGHT);
		self.window.mv(0,0);
		self.window.addstr(&title);
		if self.window.get_max_x() as usize > VERSION.len()+21 {
			for _x in 0..(self.window.get_max_x() as usize)-VERSION.len()-21 {
				self.window.addstr(BAR.encode_utf8(&mut [0;4]));
			}
		}
		self.window.attrset(Attribute::Normal);
		for line in subhistory.iter() {
			self.window.clrtoeol();
			self.window.addstr(&line.0);
			self.window.mv(self.window.get_cur_y(),self.window.get_max_x()-(line.1.len() as i32)-1);
			self.window.addstr(&line.1);
			self.window.mv(self.window.get_cur_y()+1,0);
		}
		for _x in 0..self.window.get_max_x() {
			self.window.addstr(BAR.encode_utf8(&mut [0;4]));
		}
		self.window.attrset(Attribute::Normal);
		self.window.mv(self.window.get_max_y()-1,0);
		self.window.addstr(&PROMPT);
		self.window.refresh();
	}

	// Accepts a path to a log file, and writes a line to it, generating a human- and machine-readable log.
	fn log_to_file(&mut self,logstring:&str,timestamp:DateTime<Local>) -> Result<(),io::Error> {
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
		match writeln!(log_file,"[{}][{}] {}",timestamp.timestamp_millis(),timestamp.format("%Y-%m-%d %H:%M:%S").to_string(),&logstring) {
			Ok(_) => return Ok(()),
			Err(why) => return Err(why),
		};
	}

	// Error-handling wrapper for log_to_file() - rather than returning an error, prints the error
	// message to the console and returns nothing.
	fn silent_log(&mut self,logstring:&str) {
		let log_file_name:String = self.log_file_name.clone();
		let timestamp:DateTime<Local> = Local::now();
		match self.log_to_file(&logstring,timestamp) {
			Err(why) => {
				self.print(&format!("ERROR: Failed to write to log file at {}: {}",&log_file_name,why));
			},
			Ok(()) => (),
		};
	}

	fn handle_keys(&mut self) {
		match self.window.getch() { 
			Some(Input::Character(c)) => match c {
				'\x0A' => { // ENTER
					if self.page_position > 0 {
						self.page_position = 0;
						self.page(&0);
					}
					self.history_position = 0;
					if self.line_history.len() == 0 || self.line_history[self.line_history.len()-1] != self.console_line {
						self.line_history.push(self.console_line.clone());
					}
					if self.console_line.len() > 1 && self.console_line[0] == '`' {
						let mut rawbytes:Vec<u8> = vec![b'`'];
						let mut hexchars:Vec<char> = Vec::new();
						for ch in self.console_line[1..].iter() {
							if ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'].contains(&ch) {
								hexchars.push(*ch);
							}
						}
						for chs in hexchars.chunks(2) {
							let byte = match u8::from_str_radix(&chs.iter().collect::<String>(),16) {
								Err(_) => return (),
								Ok(x) => x,
							};
							rawbytes.push(byte);
						}
						self.local_lines.push_back(rawbytes);
					} else {
						self.local_lines.push_back(self.console_line.iter().collect::<String>().as_bytes().to_vec());
					}
					self.console_line = Vec::new();
					self.line_position = 0;
				},
				'\x7F'|'\x08' => { // DEL
					if self.line_position > 0 {
						let _ = self.console_line.remove(self.line_position-1); 
						self.window.mv(self.window.get_cur_y(),self.window.get_cur_x()-1);
						self.window.delch();
						self.line_position -= 1;
						self.window.refresh();
					}
				},
				'\x1B' => { // ESCAPE
					self.local_lines.push_back(b"/quit".to_vec());
				},
				c => {
					if self.line_position == self.console_line.len() {
						self.window.addstr(c.to_string());
						self.console_line.push(c);
					} else {
						self.window.insch(c);
						self.console_line.insert(self.line_position,c);
						self.window.mv(self.window.get_cur_y(),self.window.get_cur_x()+1);
					}
					self.line_position += 1;
					self.window.refresh();
				},
			},
			Some(Input::KeyBackspace) => {
				if self.line_position > 0 {
					let _ = self.console_line.remove(self.line_position-1); 
					self.line_position -= 1;
				}	
				while ((self.line_position+PROMPT.len()) as i32) < self.window.get_cur_x() {
					self.window.mv(self.window.get_cur_y(),self.window.get_cur_x()-1);
					self.window.delch();
					self.window.refresh();
				}
			}
			Some(Input::KeyUp) => {
				if self.history_position == 0 && self.console_line.len() > 0 {
					self.line_history.push(self.console_line.clone());
				}
				if self.history_position < self.line_history.len() {
					self.history_position += 1;
					self.console_line = self.line_history[self.line_history.len()-self.history_position].to_vec();
					self.window.mv(self.window.get_cur_y(),0);
					self.window.clrtoeol();
					self.window.addstr(&PROMPT);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
					self.line_position = self.console_line.len();
					self.window.refresh();
				}
			},
			Some(Input::KeyDown) => {
				if self.history_position > 1 {
					self.history_position -= 1;
					self.console_line = self.line_history[self.line_history.len()-self.history_position].to_vec();
				} else if self.console_line.len() > 0 {
					if self.history_position == 0 {
						self.line_history.push(self.console_line.clone());
					}
					self.console_line = Vec::new();
					self.history_position = 0;
				}
				self.window.mv(self.window.get_cur_y(),0);
				self.window.clrtoeol();
				self.window.addstr(&PROMPT);
				for ch in self.console_line.iter() {
					self.window.addch(*ch);
				}
				self.line_position = self.console_line.len();
				self.window.refresh();
			},
			Some(Input::KeyLeft) => {
				if self.line_position > 0 {
					self.line_position -= 1;
					if self.line_position < self.window.get_max_x() as usize {
						self.window.mv(self.window.get_cur_y(),self.window.get_cur_x()-1);
					}
				}
				self.window.refresh();
			},
			Some(Input::KeyRight) => {
				if self.line_position < self.console_line.len() as usize {
					self.line_position += 1;
					if self.line_position < self.window.get_max_x() as usize{
						self.window.mv(self.window.get_cur_y(),self.window.get_cur_x()+1);
					}
				}
				self.window.refresh();
			},
			Some(Input::KeyHome) => {
				self.window.mv(self.window.get_cur_y(),PROMPT.len() as i32);
				self.line_position = 0;
				self.window.refresh();
			},
			Some(Input::KeyEnd) => {
				if PROMPT.len()+self.line_position >= self.window.get_max_x() as usize {
					self.window.mv(self.window.get_cur_y(),self.window.get_max_x()-1);
				} else {
					self.window.mv(self.window.get_cur_y(),(PROMPT.len()+self.console_line.len()) as i32);
				}
				self.line_position = self.console_line.len();
				self.window.refresh();
			},
			Some(Input::KeyResize) => {
				let page_position_snapshot:usize = self.page_position;
				self.page(&page_position_snapshot);
				for ch in self.console_line.iter() {
					self.window.addch(*ch);
				}
			},
			Some(Input::KeyPPage)|Some(Input::KeySPrevious) => {
				if self.page_position < self.history.len()-10 {
					self.page_position += 10;
					let page_position_snapshot:usize = self.page_position;
					self.page(&page_position_snapshot);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
				} else {
					self.page_position = self.history.len();
					let page_position_snapshot:usize = self.page_position;
					self.page(&page_position_snapshot);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
				}
			},
			Some(Input::KeyNPage)|Some(Input::KeySNext) => {
				if self.page_position > 10 {
					self.page_position -= 10;
					let page_position_snapshot:usize = self.page_position;
					self.page(&page_position_snapshot);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
				} else {
					self.page_position = 0;
					self.page(&0);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
				}
			},
			Some(Input::KeySR) => { // Shift-Up
				if self.page_position < self.history.len() {
					self.page_position += 1;
					let page_position_snapshot:usize = self.page_position;
					self.page(&page_position_snapshot);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
				}
			}
			Some(Input::KeySF) => { // Shift-Down
				if self.page_position > 0 {
					self.page_position -= 1;
					let page_position_snapshot:usize = self.page_position;
					self.page(&page_position_snapshot);
					for ch in self.console_line.iter() {
						self.window.addch(*ch);
					}
				}
			}
			Some(x) => self.print(&format!("-!- unknown keypress: {:?}",x)),
			None => (),
		};
	}

} // impl WindowLogger

fn main() {
	let arguments = clap_app!(app =>
		(name: "Teamech Console")
		(version: VERSION)
		(author: "Ellie D.")
		(about: "Desktop console client for the Teamech protocol.")
		(@arg ADDRESS: +required "Remote address to contact.")
		(@arg PORT: +required "Remote port on which to contact the server.")
		(@arg PADFILE: +required "Pad file to use for encryption/decryption (must be same as server's).")
		(@arg name: -n --name +takes_value "Unique identifier to present to the server for routing.")
		(@arg class: -c --class +takes_value "Non-unique identifier to present to the server for routing.")
		(@arg localport: -p --localport +takes_value "UDP port to bind to locally (automatic if unset).")
		(@arg showhex: -h --showhex "Show hexadecimal values of messages (useful if working with binary messages).")
		(@arg ipv4: -o --ipv4 "Use IPv4 instead of IPv6.") 
	).get_matches();
	let client_name:&str = arguments.value_of("name").unwrap_or("human");
	let client_class:&str = arguments.value_of("class").unwrap_or("supervisor");
	'recovery:loop {
		set_var("ESCDELAY","0"); // force ESCDELAY to be 0, so we can quit the application with the ESC key without delay.
		let log_file_name:String = format!("{}-teamech-console.log",Local::now().format("%Y-%m-%dT%H:%M:%S").to_string());
		let mut window_logger = new_windowlogger(&log_file_name);
		start_color();
		use_default_colors();
		init_pair(1,14,COLOR_BLACK); // bars
		init_pair(2,14,COLOR_BLACK); // status codes
		window_logger.window.refresh(); // must be called every time the screen is to be updated.
		window_logger.window.keypad(true); // keypad mode, which is typical 
		window_logger.window.nodelay(true); // nodelay mode, which ensures that the window is actually updated on time
		noecho(); // prevent local echo, since we'll be handling that ourselves
		window_logger.window.mv(window_logger.window.get_max_y()-1,0); // go to the bottom left corner
		window_logger.window.refresh();
		// Print welcome messages
		window_logger.print(&format!("Teamech Console {}",&VERSION));
		window_logger.print("Press <Esc> to exit (or Ctrl-C to force exit).");
		window_logger.print("");
		window_logger.print(&format!("Using log file {} in ~/{}.",&log_file_name,&LOG_DIRECTORY));
		window_logger.print("");
		window_logger.print("Initializing client...");
		let mut client = match teamech::new_client(
			&arguments.value_of("PADFILE").unwrap_or(""), 
			&arguments.value_of("ADDRESS").unwrap_or(""),
			arguments.value_of("PORT").unwrap_or("6666").parse::<u16>().unwrap_or(6666),
			arguments.value_of("localport").unwrap_or("0").parse::<u16>().unwrap_or(0),
			!arguments.is_present("ipv4")) {
			Err(why) => {
				endwin();
				eprintln!("Failed to instantiate client: {}",why);
				process::exit(1);
			},
			Ok(client) => client,
		};
		client.send_provide_hashes = true;
		client.name = client_name.to_owned();
		client.classes.push(client_class.to_owned());
		window_logger.print("Client initialized.");
		let _ = client.set_asynchronous(10);
		match window_logger.log_to_file(&format!("Opened log file."),Local::now()) {
			Err(why) => {
				window_logger.print(&format!("WARNING: Could not open log file at {} - {}. Logs are currently NOT BEING SAVED!",
					&log_file_name,why));
			},
			Ok(_) => (),
		};
		'authtry:loop {
			window_logger.log(&format!("Trying to contact server at {}...",&client.server_address));
			match client.subscribe() {
				Err(why) => {
					window_logger.log(&format!("Failed to subscribe to server - {}.",why));
					sleep(Duration::new(5,0));
					continue 'authtry;
				},
				Ok(_) => (),
			};
			window_logger.log(&format!("Successfully contacted server at {}",&client.server_address));
			break;
		} // 'authtry
		'operator:loop {
			match client.get_packets() {
				Err(why) => {
					window_logger.log(&format!("Failed to get packets from server - {}. Restarting...",why));
					continue 'recovery;
				},
				Ok(_) => (),
			};
			while let Some(event) = client.event_log.pop_front() {
				match event.class {
					teamech::EventClass::NameUpdate => (),
					teamech::EventClass::ClassAdd => (),
					teamech::EventClass::ClassRemove => (),
					teamech::EventClass::TestResponse => { 
						if event.parameter.len() > 0 {
							let mut screen_line = 0;
							for entry in window_logger.sent_lines.iter() {
								if entry.0 == event.contents {
									screen_line = entry.1;
									break;
								}
							}
							window_logger.print_left(&format!("~[ {} ]",&event.parameter),screen_line);
						}
					},
					teamech::EventClass::Acknowledge => { 
						let mut screen_line = 0;
						for entry in window_logger.sent_lines.iter() {
							if entry.0 == event.contents {
								screen_line = entry.1;
								break;
							}
						}
						if event.parameter.len() > 0 {
							window_logger.print_left(&format!(" [ {} ]",&event.parameter),screen_line);
						}
					},
					teamech::EventClass::ClientSubscribe => {
						window_logger.log("Subscribed to server.");
						match client.set_name(&client_name) {
							Err(why) => {
								window_logger.log(&format!("-!- Failed to set client name - {}.",why));
							},
							Ok(_) => (),
						};
						match client.add_class(&client_class) {
							Err(why) => {
								window_logger.log(&format!("-!- Failed to set client class - {}.",why));
							},
							Ok(_) => (),
						};
					},
					_ => window_logger.print(&event.to_string()),
				};
			}
			window_logger.handle_keys();
			while let Some(line) = window_logger.local_lines.pop_front() {
				if line == b"/quit" {
					match client.send_packet(&vec![0x18],&vec![]) {
						Err(why) => window_logger.print(&format!("-!- Failed to send packet - {}.",why)),
						Ok(_) => (),
					};
					endwin();
					break 'recovery;
				}
				if line.len() > 1 && line[0] == b'`' {
					if line.len() > 2 {
						match client.send_packet(&vec![line[1]],&line[2..].to_vec()) {
							Err(why) => window_logger.print(&format!("-!- Failed to send packet - {}.",why)),
							Ok(_) => (),
						};
					} else {
						match client.send_packet(&vec![line[1]],&vec![]) {
							Err(why) => window_logger.print(&format!("-!- Failed to send packet - {}.",why)),
							Ok(_) => (),
						};
					}
				}	
				let mut packet_hash:String = String::new();
				if line.len() > 1 && line[0] == b'>' {
					let messageparts = line.splitn(2,|c| *c == b' ').collect::<Vec<&[u8]>>();
					if messageparts.len() == 1 {
						match client.send_packet(&messageparts[0].to_vec(),&vec![]) {
							Err(why) => window_logger.print(&format!("-!- Failed to send packet - {}.",why)),
							Ok(hash) => packet_hash = hash,
						};
					} else if messageparts.len() == 2 {
						match client.send_packet(&messageparts[0].to_vec(),&messageparts[1].to_vec()) {
							Err(why) => window_logger.print(&format!("-!- Failed to send packet - {}.",why)),
							Ok(hash) => packet_hash = hash,
						};
					}
				} else {
					match client.send_packet(&vec![b'>'],&line) {
						Err(why) => window_logger.print(&format!("-!- Failed to send packet - {}.",why)),
						Ok(hash) => packet_hash = hash,
					};
				}
				window_logger.sent_lines.push_back((packet_hash,window_logger.history.len()));
				while window_logger.sent_lines.len() > 64 {
					let _ = window_logger.sent_lines.pop_front();
				}
			}
			window_logger.window.refresh();
		} // 'operator
	} // 'recovery
} // fn main

