use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::Block;
use std::string::String;
/**
 * Gets src ip from pcap_ng packet
 */
pub fn src_ng_ip(block: Block) -> String {
    let data = block.body;
    let mut ret_vec = Vec::new();
    for i in 26..=29 {
        ret_vec.push(data[i]);
    }
    let mut ret_str = String::new();
    let mut counter = 0; 
    for byte in ret_vec {
        let byte_str = byte.to_string();
        ret_str.push_str(&byte_str);
        if (counter != 3) {
            ret_str.push_str(".");
        }
        counter = counter+1;

    }
    return ret_str; 
}

/**
 * Get dst ip from pcap_ng packet
 */
pub fn dst_ng_ip(block:Block) -> String {
    let data = block.body;
    let mut ret_vec = Vec::new();
    for i in 30..=33 {
        ret_vec.push(data[i]);
    }
    let mut ret_str = String::new();
    let mut counter = 0; 
    for byte in ret_vec {
        let byte_str = byte.to_string();
        ret_str.push_str(&byte_str);
        if counter != 3 {
            ret_str.push_str(".");
        }
        counter = counter+1;

    }
    return ret_str;
}