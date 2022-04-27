use std::env;
use std::fs;
use std::fs::File;
use std::io::{self, BufRead};
use std::process;
use regex::Regex;

const DEFAULT_ERROR: &str = "    Not found\n";

#[derive(Debug)]
struct Config{
    addr2line_path: String,
    readelf_path: String,
    elf_file : String,
    log_file : String,
    output_file : String,
}

#[derive(Debug)]
struct DebuggerVarilator{
    config :Config,
    output: String,
}

impl DebuggerVarilator {
    /**
     * Constructor.
     * 
     * @param addr2line_path: Path to the addr2line of the toolchain that built the elf. 
     * @param elf_file: Path to the elf.
     * @param log_file: Path to the file containing the log.
     * @param out_file: Path to the file that will receive the output.
     */
    fn new(addr2line_path: &str, elf_file : &str, log_file : &str, out_file : &str) -> DebuggerVarilator{
       let config = Config{
            addr2line_path: addr2line_path.to_string(),
            readelf_path: addr2line_path.to_string().replace("addr2line", "readelf"),
            elf_file: elf_file.to_string(),
            log_file: log_file.to_string(),
            output_file: out_file.to_string()
        };
        DebuggerVarilator {
            config: config,
            output : "".to_string()
        }
    }

    /**
     * Construct the object by parsing the command line arguments.
     * 
     * @param addr2line_path: Path to the addr2line of the toolchain that built the elf. 
     * @param args: A mutable iterator containing the command line arguments.
     */

    fn from_args(addr2line_path: &str, mut args: env::Args) -> Result<DebuggerVarilator, String>{
        let help = format!("\n\tUsage: {} <path/to/elf> <path/to/log> [path/to/output]", args.next().unwrap_or("Debugger".to_string()));
        
        let elf_file = match args.next() {
            Some(arg) => arg,
            None => return Err(format!("Didn't get a elf_file name{}", help)),
        };
        
        let log_file = match args.next() {
            Some(arg) => arg,
            None => return Err(format!("Didn't get the input log file{}", help)),
        };
        
        let output_file = args.next().unwrap_or(format!("parsed_{}", log_file));
        
        Ok(DebuggerVarilator::new (
            addr2line_path,
            &elf_file,
            &log_file,
            &output_file,
        ))
    }

    /**
     * Parse a log line to get the address and call the addr2line to return the source file.
     * 
     * @param disassembly_line: A string with a line from the log. 
     */
    fn get_src_file(&mut self, disassembly_line: &str) -> String {
        let address = match disassembly_line.split_whitespace().skip(2).next() {
            Some(addr) => addr,
            None => return String::from(DEFAULT_ERROR),
        };

        let res = process::Command::new(&self.config.addr2line_path)
            .arg("-e")
            .arg(&self.config.elf_file)
            .arg(&address)
            .output()
            .expect("Failed to execute addr2line");

        String::from_utf8(res.stdout).expect("stdout parsing error")
    }

    /**
     * Parse the output of the addr2line and return the code pointed at it.
     * 
     * @param src_info: addr2line output in the format <path/to/source>:<line>. 
     */
    fn get_src_line(&mut self, src_info: &str) -> String {
        let mut it = src_info.split(':');
        let filename = match it.next() {
            Some(name) => name,
            None => return String::from(DEFAULT_ERROR),
        };
        let line_number = match it.next() {
            Some(name) => name,
            None => return String::from(DEFAULT_ERROR),
        };
        let line_number = line_number.trim_end_matches('\n').parse::<usize>();

        if let Ok(number) = line_number {
            if let Ok(file) = File::open(&filename){
                for line in io::BufReader::new(file).lines().skip(number - 1){
                    if let Ok(l) = line {
                        return "    ".to_owned() + &l + "\n";
                    }
                }
            }
        }
        String::from(DEFAULT_ERROR)
    }

     /**
     * Load the log file content filtering out the lines with addresses out of the specified range.
     * 
     * @param start_addr: Range start address.
     * @param end_addr: Range end address.
     * @return a String with the file content, string error otherwise.
     */
    fn get_file_content(&mut self, start_addr:u32, end_addr:u32) -> Result<String, String>{
        let address_re = Regex::new(r"[\da-fA-F]+\s+[\da-fA-F]+\s+([\da-fA-F]+)\s+[\da-fA-F]+\s+\w+").unwrap();
        let mut res = String::from("");
        if let Ok(file) = File::open(&self.config.log_file){
            for line in io::BufReader::new(file).lines(){
                if let Ok(l) = line {
                    if let Some(cap) = address_re.captures(&l) {
                        let addr = u32::from_str_radix(&cap[1], 16).unwrap();
                        if start_addr < addr && end_addr > addr{
                            res += &(l + "\n");
                        }
                    }
                }
            }
        }
        Ok(res)
   }


     /**
     * Read the elf and return the start address and the size.
     * 
     * @return a tuple with the address and size and string error otherwise.
     */
   fn get_elf_addr_and_size(&mut self) -> Result<(u32,u32), String>{
       let res =  match process::Command::new(&self.config.readelf_path)
        .arg("-l")
        .arg(&self.config.elf_file)
        .output(){
            Ok(res) => res,
            _ => return Err(String::from("Failed to execute readelf"))
        };

        let res = match String::from_utf8(res.stdout){
            Ok(res) => res,
            _ => return Err(String::from("Failed to execute readelf"))
        };

         // Regex to parse the readelf -l output.
        let entry_point_re = Regex::new(r"Entry point\s0x([\da-fA-F]+)").unwrap();
        let load_re = Regex::new(r"LOAD\s+0x[\da-fA-F]+\s+0x[\da-fA-F]+\s+0x([\da-fA-F]+)\s+0x([\da-fA-F]+)\s+0x[\da-fA-F]+\s+").unwrap();
        let mut start_addr = std::u32::MAX;
        let mut size: u32 = 0;
        for line in res.lines(){
            if let Some(cap) = entry_point_re.captures(line) {
                start_addr = u32::from_str_radix(&cap[1], 16).unwrap(); 
            }
            else if let Some(cap) = load_re.captures(line) {
               let addr:u32 = u32::from_str_radix(&cap[1], 16).unwrap(); 
               size = u32::from_str_radix(&cap[2], 16).unwrap(); 
               if addr == start_addr & 0xFFFF0000 {
                   break;
               }
            }
        }
        Ok((start_addr, size))
   }
    
    /**
     * Process the log file by iterating through all lines.
     */
    fn run (&mut self) -> std::io::Result<()> {
        println!("Starting ...");
        let mut last_src_line = "".to_string();

        let (start_addr, size)  = self.get_elf_addr_and_size().expect("Error to get elf Address");
        let log_content = self.get_file_content(start_addr, start_addr + size).expect("Error to open the file");
        // let log_content = fs::read_to_string(&self.config.log_file).expect("Error to open the file");
        let total = log_content.lines().count();
        println!("File {} imported successfully", self.config.log_file);
        println!("Parsing it...");

        for (count, line) in log_content.lines().enumerate() {

            let src_file = self.get_src_file(line);
            // Skip this search if the current log line represents the same source line.
            if last_src_line != src_file {
                self.output.push_str("\n");

                let c_src_line = self.get_src_line(&src_file);

                self.output.push_str(&src_file);
                self.output.push_str(&c_src_line);
            }

            self.output.push_str(line);
            self.output.push_str("\n");
            last_src_line = src_file;

            print!("\rProgress:  {}%", count*100/total);
        }
        // Processing has finished, write the result to the output file.
        fs::write(&self.config.output_file, &self.output)?;
        println!("\nFinished\nOutput {} generated successfully", self.config.output_file);

        Ok(())
    }
}

fn main() -> std::io::Result<()>{

    let mut dv = DebuggerVarilator::from_args("/tools/riscv/bin/riscv32-unknown-elf-addr2line", env::args()).unwrap_or_else(|err| {
        eprintln!("Problem parsing arguments: {}", err);
        process::exit(1);
    });

    dv.run()
}
