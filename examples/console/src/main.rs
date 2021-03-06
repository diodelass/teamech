static PROMPT:&str = "[teamech]~ ";
static VERSION:&str = "0.12.1 December 2018";

extern crate termion;
use termion::raw::{IntoRawMode,RawTerminal};
use termion::event::{Key,Event};
use termion::input::{TermRead,Events};
use termion::async_stdin;
use termion::cursor;
use termion::clear;
use termion::color::*;

extern crate teamech;

use std::io::prelude::*;
use std::io::{stdout,Stdout};
use std::time::Duration;
use std::thread::sleep;
use std::net::IpAddr;
//use std::fs::File;
use std::path::Path;
use std::fmt::Display;
use std::env::args;
use std::collections::HashMap;

struct Terminal {
	stdin_events: Events<termion::AsyncReader>,
	stdout: RawTerminal<Stdout>,
	cursor_xpos: u16,
	cursor_ypos: u16,
	consoleline: Vec<char>,
	consoleline_cursor_pos: u16,
	consoleline_history_forward: Vec<Vec<char>>,
	consoleline_history_backward: Vec<Vec<char>>,
	line_number: u64,
	saved_pos: (u16,u16),
}

fn init_term() -> Terminal {
	return Terminal {
		stdin_events: async_stdin().events(),
		stdout: stdout().into_raw_mode().expect("could not engage raw mode on stdout"),
		cursor_xpos: 1,
		cursor_ypos: 1,
		consoleline: Vec::new(),
		consoleline_cursor_pos: 0,
		consoleline_history_forward: Vec::new(),
		consoleline_history_backward: Vec::new(),
		line_number: 0,
		saved_pos: (1,1),
	};
}

#[allow(dead_code)]
impl Terminal {
	fn get_cursor_pos(&mut self) -> (u16,u16) {
		let _ = self.stdout.write("\x1b[6n".as_bytes());
		let _ = self.stdout.flush();
		sleep(Duration::from_micros(1000));
		for _ in 0..100 {
			if let Some(Event::Unsupported(v)) = self.get_event() {
				let event_string:String = String::from_utf8_lossy(&v).to_string();
				let coordinate_string:&str = event_string.trim_matches('\x1b').trim_matches('[').trim_matches('R');
				let coordinates:Vec<&str> = coordinate_string.split(';').collect::<Vec<&str>>();
				if coordinates.len() == 2 {
					let ypos:u16 = match coordinates[0].parse::<u16>() {
						Err(_) => {
							self.console_println(coordinate_string);
							1
						},
						Ok(n) => n,
					};
					let xpos:u16 = match coordinates[1].parse::<u16>() {
						Err(_) => {
							self.console_println(coordinate_string);
							1
						},
						Ok(n) => n,
					};
					return (xpos,ypos);
				}
			}
			sleep(Duration::from_micros(1000));
		}
		return (0,0);
	}
	fn print_coords_debug(&mut self) {
		let pos = (self.cursor_xpos,self.cursor_ypos);
		let lh = self.console_lineheight();
		let lr = self.console_linerow();
		let cl = self.consoleline.len();
		let cp = self.consoleline_cursor_pos;
		self.save_pos();
		self.move_to(1,1);
		self.ins_str(&format!("{},{} {},{} {},{}    ",pos.0,pos.1,lh,lr,cl,cp));
		self.restore_pos();
		let _ = self.stdout.flush();
	}
	fn get_event(&mut self) -> Option<Event> {
		if let Some(Ok(event)) = self.stdin_events.next() {
			return Some(event);
		} else {
			return None;
		}
	}
	fn ins_char(&mut self,c:char) {
		let size = self.get_size();
		let mut char_buffer:[u8;4] = [0;4];
		let byte_len = c.encode_utf8(&mut char_buffer).len();
		let _ = self.stdout.write(&char_buffer[0..byte_len]);
		if self.cursor_xpos >= size.0 {
			self.cursor_xpos = 1;
			if self.cursor_ypos < size.1 {
				self.cursor_ypos += 1;
			} else {
				let _ = self.stdout.write(b"\r\n");
			}
			let (x,y) = (self.cursor_xpos,self.cursor_ypos);
			self.move_to(x,y);
		} else {
			self.cursor_xpos += 1;
		}
	}
	fn ins_chars(&mut self,cs:&Vec<char>) {
		for c in cs.iter() {
			self.ins_char(*c);
		}
	}
	fn ins_str(&mut self,s:&str) {
		self.ins_chars(&s.chars().collect::<Vec<char>>());
	}
	fn ins_str_novis(&mut self,s:&str) {
		let _ = self.stdout.write(&s.as_bytes());
		let _ = self.stdout.flush();
	}
	fn move_left(&mut self,n:u16) {
		let size = self.get_size();
		let pos = (self.cursor_xpos,self.cursor_ypos);
		if pos.0 <= n {
			if pos.0 > 1 {
				let _ = self.stdout.write(&format!("{}",cursor::Left(pos.0-1)).as_bytes());
			}
			self.set_xpos(size.0);
			self.move_up(1);
			if pos.0 < n {
				let _ = self.stdout.write(&format!("{}",cursor::Left(n-pos.0)).as_bytes());
				self.cursor_xpos -= n-pos.0;
			}
		} else {
			let _ = self.stdout.write(&format!("{}",cursor::Left(n)).as_bytes());
			self.cursor_xpos -= n;
		}
		let _ = self.stdout.flush();
		sleep(Duration::from_millis(10));
	}
	fn move_right(&mut self,n:u16) {
		let size = self.get_size();
		let pos = (self.cursor_xpos,self.cursor_ypos);
		if pos.0+n > size.0 {
			if pos.0 < size.0 {
				let _ = self.stdout.write(&format!("{}",cursor::Right(size.0-pos.0)).as_bytes());
			}
			self.set_xpos(1);
			if pos.1 < size.1 {
				self.move_down(1);
			}
			if pos.0+n > size.0+1 {
				let _ = self.stdout.write(&format!("{}",cursor::Right(n-(size.0-pos.0)-1)).as_bytes());
				self.cursor_xpos += n-(size.0-pos.0);
			}
		} else {
			let _ = self.stdout.write(&format!("{}",cursor::Right(n)).as_bytes());
			self.cursor_xpos += n;
		}
	}
	fn move_down(&mut self,n:u16) {
		let _ = self.stdout.write(&format!("{}",cursor::Down(n)).as_bytes());
		let max_y = self.get_size().1;
		if self.cursor_ypos+n < max_y {
			self.cursor_ypos += n;
		} else {
			self.cursor_ypos = max_y;
		}
	}
	fn move_up(&mut self,n:u16) {
		let _ = self.stdout.write(&format!("{}",cursor::Up(n)).as_bytes());
		if self.cursor_ypos > n {
			self.cursor_ypos -= n;
		} else {
			self.cursor_ypos = 1;
		}
	}
	fn move_to(&mut self,x:u16,y:u16) {
		let _ = self.stdout.write(&format!("{}",cursor::Goto(x,y)).as_bytes());
		self.cursor_xpos = x;
		self.cursor_ypos = y;
	}
	fn set_xpos(&mut self,x:u16) {
		let ypos = self.cursor_ypos;
		self.move_to(x,ypos);
	}
	fn set_ypos(&mut self,y:u16) {
		let xpos = self.cursor_xpos;
		self.move_to(xpos,y);
	}
	fn save_pos(&mut self) {
		self.saved_pos = (self.cursor_xpos,self.cursor_ypos);
	}
	fn restore_pos(&mut self) {
		let saved_pos = self.saved_pos;
		self.move_to(saved_pos.0,saved_pos.1);
	}
	fn get_xpos(&self) -> u16 {
		return self.cursor_xpos;
	}
	fn get_ypos(&self) -> u16 {
		return self.cursor_ypos;
	}
	fn get_size(&self) -> (u16,u16) {
		return termion::terminal_size().expect("failed to get terminal size");
	}
	fn go_home(&mut self) {
		let max_y = self.get_size().1;
		self.move_to(1,max_y);
		self.cursor_xpos = 1;
		self.cursor_ypos = max_y;
		for _ in 1..self.console_lineheight() {
			self.move_up(1);
		}
	}
	fn clear_line(&mut self) {
		let _ = self.stdout.write(&format!("{}",clear::CurrentLine).as_bytes());
	}
	fn clear_to_eol(&mut self) {
		let _ = self.stdout.write(&format!("{}",clear::AfterCursor).as_bytes());
	}
	fn clear_window(&mut self) {
		let _ = self.stdout.write(&format!("{}",clear::All).as_bytes());
	}
	fn console_lineheight(&mut self) -> u16 {
		let line_len:u16 = (PROMPT.len() + self.consoleline.len()) as u16;
		let term_width:u16 = self.get_size().0;
		if term_width == 0 {
			return 1;
		}
		return (line_len + term_width - 1)/term_width;
	}
	fn console_linerow(&mut self) -> u16 {
		let term_width:u16 = self.get_size().0;
		let true_pos:u16 = self.consoleline_cursor_pos + PROMPT.len() as u16;
		if term_width == 0 {
			return 1;
		}
		return (true_pos + term_width - 1)/term_width;
	}
	fn console_set_prompt(&mut self) {
		self.console_end();
		for _ in 1..self.console_linerow() {
			self.clear_line();
			self.move_up(1);
		}
		self.clear_line();
		self.set_xpos(1);
		self.ins_str_novis(&format!("{}",Fg(Green)));
		self.ins_str(&PROMPT);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		let _ = self.stdout.flush();
	}
	fn console_ins_char(&mut self,c:char) {
		let mut cl:Vec<char> = self.consoleline.clone();
		let mut cl_pos:u16 = self.consoleline_cursor_pos;
		cl.insert(cl_pos as usize,c);
		cl_pos += 1;
		self.consoleline = cl.clone();
		if cl_pos == cl.len() as u16 {
			self.ins_char(c);
		} else {
			//self.console_set_prompt();
			self.ins_char(c);
			self.clear_to_eol();
			self.save_pos();
			for _ in self.console_linerow()..self.console_lineheight() {
				self.move_down(1);
				self.clear_line();
			}
			self.restore_pos();
			self.ins_chars(&cl[cl_pos as usize..].to_vec());
			self.move_left(cl.len() as u16 - cl_pos);
			//self.go_home();
			//self.move_right(PROMPT.len() as u16 + cl_pos);
		}
		self.consoleline_cursor_pos = cl_pos;
		let _ = self.stdout.flush();
	}
	fn console_feed(&mut self) -> String {
		let cl:Vec<char> = self.consoleline.clone();
		while let Some(line) = self.consoleline_history_forward.pop() {
			self.consoleline_history_backward.push(line);
		}
		if self.consoleline_history_backward.last() != Some(&cl) && cl.len() != 0 {
			self.consoleline_history_backward.push(cl.clone());
		}
		self.ins_str("\r\n");
		self.cursor_xpos = 1;
		if self.cursor_ypos < self.get_size().1 {
			self.cursor_ypos += 1;
		}
		self.consoleline = Vec::new();
		self.consoleline_cursor_pos = 0;
		self.console_set_prompt();
		let _ = self.stdout.flush();
		return cl.iter().collect::<String>();
	}
	fn console_println(&mut self,s:&str) {
		let cl:Vec<char> = self.consoleline.clone();
		for _ in 1..self.console_linerow() {
			self.clear_line();
			self.move_up(1);
		}
		self.clear_line();
		self.go_home();
		self.ins_str(&s);
		self.ins_str("\r\n");
		self.line_number += 1;
		self.console_set_prompt();
		self.ins_chars(&cl);
		self.go_home();
		self.move_right((cl.len()+PROMPT.len()) as u16);
		let _ = self.stdout.flush();
	}
	fn console_startl(&mut self,s:&str) {
		for _ in 1..self.console_linerow() {
			self.clear_line();
			self.move_up(1);
		}
		self.clear_line();
		self.go_home();
		self.ins_str(&s);
	}
	fn console_endl(&mut self) {
		let cl:Vec<char> = self.consoleline.clone();
		self.ins_str("\r\n");
		if self.cursor_ypos < self.get_size().1 {
			self.cursor_ypos += 1;
		}
		self.line_number += 1;
		self.console_set_prompt();
		self.ins_chars(&cl);
		self.go_home();
		self.move_right((cl.len()+PROMPT.len()) as u16);
		let _ = self.stdout.flush();
	}
	fn console_error(&mut self,s:&str) {
		self.console_startl("");
		self.ins_str_novis(&format!("{}",Fg(Red)));
		self.ins_str("-!- Error: ");
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str(&s);
		self.console_endl();
	}
	fn console_warning(&mut self,s:&str) {
		self.console_startl("");
		self.ins_str_novis(&format!("{}",Fg(Yellow)));
		self.ins_str("-!- Warning: ");
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str(&s);
		self.console_endl();
	}
	fn console_info(&mut self,s:&str) {
		self.console_startl("");
		self.ins_str_novis(&format!("{}",Fg(Cyan)));
		self.ins_str("-*- ");
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str(&s);
		self.console_endl();
	}
	fn console_version(&mut self) {
		self.console_startl("");
		self.ins_str_novis(&format!("{}",Fg(Green)));
		self.ins_str("Teamech Console ");
		self.ins_str_novis(&format!("{}",Fg(Blue)));
		self.ins_str(&VERSION);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.console_endl();
	}
	fn console_netevent(&mut self,date:&str,time:&str,contents:&str) {
		self.console_startl("[");
		self.ins_str_novis(&format!("{}",Fg(LightMagenta)));
		self.ins_str(&date);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str("] [");
		self.ins_str_novis(&format!("{}",Fg(LightBlue)));
		self.ins_str(&time);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str("] ");
		self.ins_str(&contents);
		self.console_endl();
	}
	fn console_netevent_color<T:Display>(&mut self,color:T,date:&str,time:&str,contents:&str) {
		self.console_startl("[");
		self.ins_str_novis(&format!("{}",Fg(LightMagenta)));
		self.ins_str(&date);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str("] [");
		self.ins_str_novis(&format!("{}",Fg(LightBlue)));
		self.ins_str(&time);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.ins_str("] ");
		self.ins_str_novis(&format!("{}",color));
		self.ins_str(&contents);
		self.ins_str_novis(&format!("{}",Fg(Reset)));
		self.console_endl();
	}
	fn console_backspace(&mut self) {
		if self.consoleline_cursor_pos > 0 {
			let _ = self.consoleline.remove(self.consoleline_cursor_pos as usize - 1);
			self.move_left(1);
			self.consoleline_cursor_pos -= 1;
			self.clear_to_eol();
			if self.consoleline_cursor_pos < self.consoleline.len() as u16 {
				let remaining_chars = &self.consoleline[self.consoleline_cursor_pos as usize..].to_vec();
				self.ins_chars(&remaining_chars);
				self.move_left(remaining_chars.len() as u16);
			}
		}
		let _ = self.stdout.flush();
	}
	fn console_del(&mut self) {
		let mut cl:Vec<char> = self.consoleline.clone();
		let cl_len:u16 = self.consoleline.len() as u16;
		let cl_pos:u16 = self.consoleline_cursor_pos;
		if cl_pos < cl_len {
			let _ = cl.remove(cl_pos as usize);
			self.consoleline = cl.clone();
			self.console_set_prompt();
			self.ins_chars(&cl);
			self.go_home();
			self.move_right(PROMPT.len() as u16 + cl_pos);
		}
		let _ = self.stdout.flush();
	}
	fn console_left(&mut self) {
		let cl_pos:u16 = self.consoleline_cursor_pos;
		if cl_pos > 0 {
			self.move_left(1);
			self.consoleline_cursor_pos -= 1;
		}
		let _ = self.stdout.flush();
	}
	fn console_right(&mut self) {
		let cl_pos:u16 = self.consoleline_cursor_pos;
		let cl_len:u16 = self.consoleline.len() as u16;
		if cl_pos < cl_len {
			self.move_right(1);
			self.consoleline_cursor_pos += 1;
		}
		let _ = self.stdout.flush();
	}
	fn console_home(&mut self) {
		let cl_pos:u16 = self.consoleline_cursor_pos;
		if cl_pos > 0 {
			//self.move_left(cl_pos);
			self.go_home();
			self.move_right(PROMPT.len() as u16);
			self.consoleline_cursor_pos = 0;
		}
		let _ = self.stdout.flush();
	}
	fn console_end(&mut self) {
		let cl_len:u16 = self.consoleline.len() as u16;
		let cl_pos:u16 = self.consoleline_cursor_pos;
		if cl_pos < cl_len {
			self.move_right(cl_len - cl_pos);
		}
		self.consoleline_cursor_pos = cl_len;
		let _ = self.stdout.flush();
	}
	fn console_history_prev(&mut self) {
		if let Some(line) = self.consoleline_history_backward.pop() {
			self.console_set_prompt();
			self.consoleline_history_forward.push(self.consoleline.clone());
			self.consoleline = line.clone();
			self.ins_chars(&line);
			self.consoleline_cursor_pos = line.len() as u16;
			let _ = self.stdout.flush();
		}
	}
	fn console_history_next(&mut self) {
		if let Some(line) = self.consoleline_history_forward.pop() {
			self.console_set_prompt();
			self.consoleline_history_backward.push(self.consoleline.clone());
			self.consoleline = line.clone();
			self.ins_chars(&line);
			self.consoleline_cursor_pos = line.len() as u16;
			let _ = self.stdout.flush();
		} else if self.consoleline.len() != 0 {
			self.console_set_prompt();
			self.consoleline_history_backward.push(self.consoleline.clone());
			self.consoleline = Vec::new();
			self.consoleline_cursor_pos = 0;
			let _ = self.stdout.flush();
		}
	}
}

fn main() {
	let env_args:Vec<String> = args().collect::<Vec<String>>();
	let valued_flags:Vec<char> = vec!['p','l'];
	let valued_switches:Vec<&str> = vec!["port","localport"];
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
	let too_many_arguments:bool = arguments.len() > 2;
	let too_few_arguments:bool = arguments.len() < 2;
	let unvalued_flags:bool = switches_seeking_values.len()+flags_seeking_values.len() > 0;
	if help_flag || too_many_arguments || too_few_arguments || unvalued_flags {
		if help_flag {
			println!("Teamech Console {}",VERSION);
			println!("Terminal client for the Teamech protocol");
			println!("Ellie D. Martin-Eberhardt");
		} else if too_many_arguments {
			println!("One or more of the specified arguments were not understood.");
		} else if too_few_arguments {
			println!("One or more required arguments were not provided.");
		} else if unvalued_flags {
			println!("One or more of the specified flags requires a value, but no value was found.");
		}
		println!("Usage:");
		println!("{} <ADDRESS> <IDENTITY FILE> [OPTIONS]",command);
		println!("Overview of options:");
		println!("ADDRESS: IP address of the remote server to connect to.");
		println!("IDENTITY FILE: Identity file to use for authentication (must correspond to a duplicate file registered on the server).");
		println!("-p, --port <number>: Remote UDP port number to connect to on the remote server.");
		println!("-l, --localport <number>: Local UDP port to use for sending and receiving data.");
		println!("-a --showraw: Show raw packet sends and receives in addition to relevant events.");
		println!("-v --verbose: Show all raw packet events and debugging information.");
		return;
	}
	// set up the terminal window
	let mut term = init_term();
	term.clear_window();
	term.go_home();
	term.console_set_prompt();
	term.console_version();
	// recovery: catches breaks from 'processor. break to quit the client. 
	'recovery:loop {
		// extract parameters from command line arguments
		let mut local_port_arg:&str = "0";
		if let Some(port) = flag_values.get(&'l') {
			local_port_arg = port;
		} else if let Some(port) = switch_values.get(&"localport") {
			local_port_arg = port;
		}
		let local_port:u16 = match local_port_arg.parse::<u16>() {
			Err(why) => {
				term.console_error("Failed to parse given port number as an integer. See --help for help.");
				term.console_error(&format!("{}",why));
				break 'recovery;
			},
			Ok(n) => n,
		};
		let mut remote_port_arg:&str = "3840";
		if let Some(port) = flag_values.get(&'p') {
			remote_port_arg = port;
		} else if let Some(port) = switch_values.get(&"port") {
			remote_port_arg = port;
		}
		let remote_port:u16 = match remote_port_arg.parse::<u16>() {
			Err(why) => {
				term.console_error("Failed to parse given port number as an integer. See --help for help.");
				term.console_error(&format!("{}",why));
				break 'recovery;
			},
			Ok(n) => n,
		};
		// it's okay to .expect this, instead of matching it, because clap is supposed to handle telling the user what's wrong if they miss
		// a required argument.
		let key_location:&Path = Path::new(arguments[1]);
		let address_field = arguments[0];
		let server_address:IpAddr = match address_field.parse::<IpAddr>() {
			Err(_why) => {
				term.console_error("Failed to parse target address: is this an IP address?");
				break 'recovery;
			},
			Ok(addr) => addr,
		};
		// instantiate the client
		let mut teamech_client = match teamech::new_client(&key_location,&server_address,remote_port,local_port) {
			Err(why) => {
				term.console_error(&format!("Failed to instantiate client: {}",why));
				break 'recovery;
			},
			Ok(client) => client,
		};
		match teamech_client.set_recv_wait(1000) {
			Err(why) => {
				term.console_error(&format!("teamech-console: could not set client read timeout: {}",why));
				break 'recovery;
			},
			Ok(_) => (),
		};
		term.console_info("Loaded identity info:");
		term.console_info(&format!("Name: @{}",teamech_client.identity.name));
		term.console_info(&format!("Classes: #{}",teamech_client.identity.classes.join(", #")));
		// initiate connection
		term.console_info(&format!("Attempting to contact server at {}:{}...",server_address,remote_port));
		match teamech_client.connect() {
			Err(why) => {
				term.console_error(&format!("Could not open connection to server ({}). Resetting connection...",why));
				for _ in 0..20 {
					sleep(Duration::new(0,100_000_000));
					if let Some(Event::Key(Key::Ctrl('c'))) = term.get_event() {
						break 'recovery;
					}
				}
				continue 'recovery;
			},
			Ok(_) => (),
		};
		//teamech_client.time_tolerance_ms = 60000;
		term.console_info("Server contacted successfully.");
		// processor loop. break to immediately reset the client without quitting.
		'processor:loop {
			match teamech_client.get_event() {
				Err(why) => {
					term.console_error(&format!("Could not receive packets ({}). Resetting connection...",why));
					for _ in 0..20 {
						sleep(Duration::new(0,100_000_000));
						if let Some(Event::Key(Key::Ctrl('c'))) = term.get_event() {
							break 'recovery;
						}
					}
					break 'processor;
				},
				Ok(Some(net_event)) => {
					// parse out the lines produced by to_string(), so that we can add colors ourselves
					let event_string:String = net_event.to_string();
					let date:&str;
					let time:&str;
					let event_text:&str;
					if event_string.splitn(2," ").count() == 2 {
						let timestamp:&str = event_string.splitn(2," ").collect::<Vec<&str>>()[0].trim_matches('[').trim_matches(']');
						if timestamp.splitn(2,"T").count() == 2 {
							date = timestamp.splitn(2,"T").collect::<Vec<&str>>()[0];
							time = timestamp.splitn(2,"T").collect::<Vec<&str>>()[1].trim_matches('Z');
						} else {
							date = timestamp;
							time = "";
						} 
						event_text = event_string.splitn(2," ").collect::<Vec<&str>>()[1];
					} else {
						date = "";
						time = "";
						event_text = &event_string;
					}
					let showraw:bool = switches.contains(&"showraw") || switches.contains(&"verbose") || flags.contains(&'a') || flags.contains(&'v');
					match net_event {
						teamech::Event::Acknowledge {timestamp:_,sender:_,address:_,hash:_,matches:_} => {
							term.console_netevent_color(Fg(Magenta),date,time,event_text);
						},
						teamech::Event::SendPacket {timestamp:_,destination:_,address:_,parameter,payload:_,hash:_} => if showraw {
							match parameter[..] {
								[0x06] => {
									term.console_netevent_color(Fg(Blue),date,time,event_text);
								},
								[0x15] => {
									term.console_netevent_color(Fg(Red),date,time,event_text);
								},
								_ => term.console_netevent_color(Fg(Cyan),date,time,event_text),
							};
						},
						teamech::Event::ReceivePacket {timestamp:_,sender:_,address:_,parameter,payload:_,hash:_} => if showraw {
							match parameter[..] {
								[0x06] => {
									term.console_netevent_color(Fg(Magenta),date,time,event_text);
								},
								[0x15] => {
									term.console_netevent_color(Fg(Red),date,time,event_text);
								},
								[0x03]|[0x04]|[0x05] => {
									term.console_netevent_color(Fg(Yellow),date,time,event_text);
								}
								_ => term.console_netevent_color(Fg(Yellow),date,time,event_text),
							};
						},
						teamech::Event::SendMessage {timestamp:_,destination:_,address:_,parameter:_,payload:_,hash:_} => {
							term.console_netevent_color(Fg(LightCyan),date,time,event_text);
						},
						teamech::Event::ReceiveMessage {timestamp:_,sender:_,address:_,parameter:_,payload:_,hash:_} => {
							term.console_netevent_color(Fg(LightYellow),date,time,event_text);
						},
						teamech::Event::Refusal {timestamp:_,sender:_,address:_,hash:_} => {
							term.console_netevent_color(Fg(LightRed),date,time,event_text);
						}
						_ => term.console_netevent(date,time,event_text),
					};
				},
				Ok(None) => (),
			};
			match teamech_client.resend_unacked() {
				Err(why) => {
					term.console_println(&format!("{}-!- Error:{} Could not retransmit packets ({}). Resetting connection...",Fg(Red),Fg(Reset),why));
					for _ in 0..20 {
						sleep(Duration::new(0,100_000_000));
						if let Some(Event::Key(Key::Ctrl('c'))) = term.get_event() {
							break 'recovery;
						}
					}
					break 'processor;
				},
				Ok(_) => (),
			};
			if let Some(key_event) = term.get_event() {
				match key_event {
					Event::Key(Key::Ctrl('c'))|Event::Key(Key::Ctrl('d')) => { // quit
						term.console_println(&format!("{}-*-{} Closing connection...",Fg(Cyan),Fg(Reset)));
						match teamech_client.disconnect() {
							Err(why) => {
								term.console_println(&format!("{}-!- Warning:{} Failed to disconnect from server before quitting ({}).",Fg(Yellow),Fg(Reset),why));
							},
							Ok(_) => {
								term.console_println(&format!("{}-*-{} Connection closed.",Fg(Cyan),Fg(Reset)));
							},
						};
						term.ins_str("\r\n");
						break 'recovery;
					},
					Event::Key(Key::Left) => {
						term.console_left();
					}
					Event::Key(Key::Right) => {
						term.console_right();
					},
					Event::Key(Key::Up) => {
						term.console_history_prev();
					},
					Event::Key(Key::Down) => {
						term.console_history_next();
					},
					Event::Key(Key::Home) => {
						term.console_home()
					},
					Event::Key(Key::End) => {
						term.console_end()
					},
					Event::Key(Key::Backspace) => {
						term.console_backspace();
					},
					Event::Key(Key::Delete) => {
						term.console_del();
					},
					Event::Key(Key::Insert) => {
						term.print_coords_debug();
						//term.console_set_prompt();
					}
					Event::Key(Key::Char(c)) => match c {
						'\n'|'\r' => { // enter key
							let transmit_line:String = term.console_feed();
							let parameter:&str;
							let payload:&str;
							if transmit_line.starts_with(">") {
								let line_split:Vec<&str> = transmit_line.splitn(2," ").collect::<Vec<&str>>();
								parameter = line_split[0];
								if line_split.len() > 1 {
									payload = line_split[1];
								} else {
									payload = "";
								}
							} else {
								if transmit_line == "?" {
									parameter = "\x05";
									payload = "";
								} else {
									parameter = ">";
									payload = &transmit_line;
								}
							}
							match teamech_client.send_packet(&parameter.as_bytes().to_vec(),&payload.as_bytes().to_vec()) {
								Err(why) => {
									term.console_error(&format!("Could not transmit packet ({}). Resetting connection...",why));
									sleep(Duration::new(1,0));
									continue 'recovery;
								},
								Ok(_) => (),
							};
						},
						_ => {
							term.console_ins_char(c);
						},
					},
					_ => (),
				};
			} // keyboard events
		} // 'processor
	} // 'recovery
} // main() 
