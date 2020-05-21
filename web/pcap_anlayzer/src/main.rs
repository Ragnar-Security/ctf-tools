use pcap_parser::*;
use pcap_parser::traits::PcapReaderIterator;
use std::fs::File;
use std::io::Read;
use std::env;


fn main() {
    let args: Vec<String> = env::args().collect();
    let path = &args[1];
    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
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
