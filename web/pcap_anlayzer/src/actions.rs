use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcap::Packet;
use pcap_file::pcapng::Block;
use std::string::String;

/**
 * Currently we are assuming that we are either looking at TCP/UDP packets.
 */

/**
 * Finds the SRC IP_Addr for the packet
 */
pub fn src_ip(packet: Packet, ng: bool) -> String {
    let data = packet.data;
    let mut retVec = Vec::new();
    for i in 26..=29 {
        retVec.push(data[i]);
    }
    let mut retStr = String::new();
    let mut counter = 0; 
    for byte in retVec {
        let byte_str = byte.to_string();
        retStr.push_str(&byte_str);
        if (counter != 3) {
            retStr.push_str(".");
        }
        counter = counter+1;

    }
    return retStr; 
}
/**
 * Finds the destingation IP_Addr for the packet
 */
pub fn dst_ip (packet: Packet, ng: bool) -> String{ 
    let data = packet.data;
    let mut retVec = Vec::new();
    for i in 30..=33 {
        retVec.push(data[i]);
    }
    let mut retStr = String::new();
    let mut counter = 0;
    for byte in retVec {
        let byte_str = byte.to_string();
        retStr.push_str(&byte_str);
        if (counter != 3) {
            
            retStr.push_str(".");
        }
        counter = counter + 1;
    }

    return retStr; 
}

/**
 * Gets src ip from pcap_ng packet
 */
pub fn src_ng_ip(block: Block) -> String {
    let data = block.body;
    let mut retVec = Vec::new();
    for i in 26..=29 {
        retVec.push(data[i]);
    }
    let mut retStr = String::new();
    let mut counter = 0; 
    for byte in retVec {
        let byte_str = byte.to_string();
        retStr.push_str(&byte_str);
        if (counter != 3) {
            retStr.push_str(".");
        }
        counter = counter+1;

    }
    return retStr; 
}

/**
 * Get dst ip from pcap_ng packet
 */
pub fn dst_ng_ip(block:Block) -> String {
    let data = block.body;
    let mut retVec = Vec::new();
    for i in 30..=33 {
        retVec.push(data[i]);
    }
    let mut retStr = String::new();
    let mut counter = 0; 
    for byte in retVec {
        let byte_str = byte.to_string();
        retStr.push_str(&byte_str);
        if (counter != 3) {
            retStr.push_str(".");
        }
        counter = counter+1;

    }
    return retStr;
}