use std::env;
use std::fs;
use std::process;

const DEFAULT_ERROR: &str = "    Not found\n";

#[derive(Debug)]
struct Config{
    addr2line_path: String,
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
        let line_number = line_number.trim_end_matches('\n').parse::<u32>();

        match line_number {
            Ok(number) => {
                let sed_exp = format!("{}!d", &number);
        
                let res = process::Command::new("sed")
                        .arg(&sed_exp)
                        .arg(&filename)
                        .output()
                        .expect("Failed to execute cat");
        
                let mut res = String::from_utf8(res.stdout).unwrap().trim_start().to_string();
                res.insert_str( 0, "    ");
                res
            }
            _ => String::from(DEFAULT_ERROR)
        }
    }
    
    /**
     * Process the log file by iterating through all lines.
     */
    fn run (&mut self) -> std::io::Result<()> {
        println!("Starting ...");
        let mut last_src_line = "".to_string();
        let log_content = fs::read_to_string(&self.config.log_file).expect("Error to open the file");
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
