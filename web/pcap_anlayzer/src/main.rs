// use pcap_parser::*;
// use pcap_parser::traits::PcapReaderIterator;

mod pcap_functions;
mod packet_functions; 
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use std::fs::File;
use std::env;
extern crate clap;
use clap::{Arg,App};

/**
 *  Driver code for pcap_analyzer
 */
fn main() {
    let matches = App::new("pcap_analyzer")
                        .version("1.0")
                        .author("WittsEnd2 <contact@ragnarsecurity.com>")
                        .arg(Arg::with_name("file")
                            .help("PCAP or PCAPNG file to process")
                            .required(true)
                            .index(1))
                        .arg(Arg::with_name("transport_dump")
                            .short("d")
                            .long("transport_dump")
                            .takes_value(false)
                            .help("Prints all transport layer packets it receives"))
                        .arg(Arg::with_name("transport_info")
                            .short("t")
                            .long("transport_info")
                            .takes_value(false)
                            .help("Prints out metadata regarding the transport layer"))
                        .arg(Arg::with_name("ip_info")
                            .short("i")
                            .long("ip_header_info")
                            .takes_value(false)
                            .help("Prints all of the metadata for the ip headers in the packet"))
                        .get_matches();

    let file_path = matches.value_of("file").unwrap();
    println!("Analyzing pcap/pcapng file {}", file_path); 

    let extension = get_extension_from_filename(file_path); 
    println!("{:?}", extension);
    let file_in = File::open(file_path).expect("Error opening file"); 
    if matches.occurrences_of("transport_dump") > 0 {
        transport_dump(&file_in, extension)
    }
    if matches.occurrences_of("transport_info") > 0 {
        transport_info(&file_in, extension);
    }
    if matches.occurrences_of("ip_info") > 0 {
        ip_info(&file_in, extension);
    }

}

fn transport_dump(file_in:&std::fs::File, extension:&str) {
    if extension.eq("pcap") {        
        let pcap_reader = PcapReader::new(file_in).unwrap();
            
        for pcap in pcap_reader {
            let pcap = pcap.unwrap();
            let src_ip = pcap_functions::src_ip(&pcap);
            println!("{:?}", pcap_functions::get_transport_data(&pcap));
        }
    } else if extension.eq("pcapng") {
        let pcapng_reader = PcapNgReader::new(file_in).unwrap();
        for block in pcapng_reader {
            let block = block.unwrap();
            let parsed_block = block.parsed().unwrap();
        }
    }
}

fn transport_info(file_in:&std::fs::File, extension:&str) {
    if extension.eq("pcap") {
        let pcap_reader = PcapReader::new(file_in).unwrap();
        pcap_functions::transport_metadata(pcap_reader);         
    } else if extension.eq("pcapng") {
        let pcapng_reader = PcapNgReader::new(file_in). unwrap();
    }
}

fn ip_info(file_in:&std::fs::File, extension:&str) {
    if extension.eq("pcap") {
        let pcap_reader = PcapReader::new(file_in).unwrap();
        let ip_meta_data = pcap_functions::ip_metadata(pcap_reader);
        println!("{:?}", ip_meta_data); 
        
    } else if extension.eq("pcapng") {
        let pcapng_reader = PcapNgReader::new(file_in). unwrap();
    }
}

/** 
 * Retrieves the extension of the file found 
 */
fn get_extension_from_filename(filename: &str) -> &str{
    let position = filename.matches(".").count(); 
    let split_string:Vec<&str> = filename.split(".").collect();
    let extension = split_string[position];
    return extension;
}


