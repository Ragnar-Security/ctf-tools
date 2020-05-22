// use pcap_parser::*;
// use pcap_parser::traits::PcapReaderIterator;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use std::fs::File;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let extension = get_extension_from_filename(file_path);
    if extension.eq("pcap") {

        let file_in = File::open(file_path).expect("Error opening file"); 
    
        let pcap_reader = PcapReader::new(file_in).unwrap();
    
        for pcap in pcap_reader {
            let pcap = pcap.unwrap();
            let pcap_header = pcap.header;
            println!("{:?}", pcap_header);
        }
    } else if extension.eq("pcapng") {
        let file_in = File::open(file_path).expect("Error opening file"); 
        
        let pcapng_reader = PcapNgReader::new(file_in).unwrap();
        
        for block in pcapng_reader {
            let block = block.unwrap();
            let parsed_block = block.parsed().unwrap();
        }
    }

}

fn get_extension_from_filename(filename: &str) -> &str{
    let mut position = 1; 
    if filename.chars().nth(0) == Some('.') {
        position = 2;
    }
    let split_string:Vec<&str> = filename.split(".").collect();
    let extension = split_string[position];
    return extension;
}