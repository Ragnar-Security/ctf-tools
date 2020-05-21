use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::env;


fn get_extension_from_filename(filename: &str) -> &str{
    let split_string:Vec<&str> = filename.split(".").collect();
    let extension = split_string[1];
    return extension;
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let file_path = &args[1];
    let extension = get_extension_from_filename(file_path);
    if extension.eq("pcap") || extension.eq("pcapng") {
        let file = File::open(file_path).unwrap();
        let mut num_blocks = 0; 
        if extension.eq("pcap") {
            let mut reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader Not Found");
            loop {
                match reader.next() {
                    Ok((offset, _block)) => {
                        println!("got new block");
                        num_blocks += 1;
                        reader.consume(offset);
                    },
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete) => {
                        reader.refill().unwrap();
                    },
                    Err(e) => panic!("error while reading: {:?}", e),
                }
            }
            println!("num_blocks: {}", num_blocks);
                 
        } else if extension.eq("pcapng") {
            let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
            loop {
                match reader.next() {
                    Ok((offset, _block)) => {
                        println!("got new block");
                        num_blocks += 1;
                        reader.consume(offset);
                    },
                    Err(PcapError::Eof) => break,
                    Err(PcapError::Incomplete) => {
                        reader.refill().unwrap();
                    },
                    Err(e) => panic!("error while reading: {:?}", e),
                }
            }
            println!("num_blocks: {}", num_blocks);
             
        }
    }
    // // if (extension == ".pcap" || extension == ".pcapng"){
    //     let file = File::open(file_path).unwrap();
    //     let mut num_blocks = 0;
    //     let mut reader;
    //     // if (extension == ".pcap") {
    //         reader = LegacyPcapReader::new(65536, file).expect("LegacyPcapReader");
    //     // } else {
    //         reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    //     // }
    //     loop {
    //         match reader.next() {
    //             Ok((offset, _block)) => {
    //                 println!("got new block");
    //                 num_blocks += 1;
    //                 reader.consume(offset);
    //             },
    //             Err(PcapError::Eof) => break,
    //             Err(PcapError::Incomplete) => {
    //                 reader.refill().unwrap();
    //             },
    //             Err(e) => panic!("error while reading: {:?}", e),
    //         }
    //     }        
    //     println!("num_blocks: {}", num_blocks);
    // }
}
