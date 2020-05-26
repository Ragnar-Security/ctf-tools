use crate::packet_functions;
extern crate etherparse;
use pcap_file::pcap::PcapReader;
use pcap_file::pcap::Packet;
use std::string::String;
use std::io;
use std::result;
use std::fmt; 
use std::error::Error;
/**=[[V -PFG;]]
 * Currently we are assuming that we are either looking at TCP/UDP packets.
 */
#[derive(Debug)]
struct PacketTypeError {
    details: String
}

impl PacketTypeError {
    fn new(msg: &str) -> PacketTypeError {
       return PacketTypeError{details: msg.to_string()}; 
    }
}

impl fmt::Display for PacketTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,"{}",self.details)
    }
}

impl Error for PacketTypeError {
    fn description(&self) -> &str {
        return &self.details;
    }
}

struct PacketData {
    ethernet_header: Vec<u8>,
    ip_header: Vec<u8>,
    low_level_header: Vec<u8>,
    data: Vec<u8>
}

/**
 * Finds the SRC IP_Addr for the packet
 */
pub fn src_ip(packet: &Packet) -> String {
    let data = &packet.data;
    let mut ret_vec = Vec::new();
    for i in 26..=29 {
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
/**
 * Finds the destingation IP_Addr for the packet
 */
pub fn dest_ip (packet: &Packet) -> String{ 
    let data = &packet.data;
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
        counter = counter + 1;
    }

    return ret_str; 
}



fn split_packet(packet: &Packet) -> Result<(), PacketTypeError>{
    let data = &packet.data; 
    // if (data_type == -1) {
    //     return Err(PacketTypeError::new("Invalid Packet Type"));
    // } else {

    
        let mut split_packet:PacketData = PacketData {
            ethernet_header: Vec::new(),
            ip_header: Vec::new(),
            low_level_header: Vec::new(),
            data: Vec::new(),
        };
        
        
        let mut ip_type_bytes = Vec::new();
        for i in 0..13{
            if i < 13 { 
                split_packet.ethernet_header.push(data[i]);
                if i == 12 || i == 13 {
                    ip_type_bytes.push(data[i]); 
                }
            }            
        }
        let ip_type = packet_functions::ip_type(ip_type_bytes); 
        if ip_type != -1 {
            return Err(PacketTypeError::new("Invalid Packet Type"));
        }
        
        for i in 13..33 {
            split_packet.ip_header.push(data[i]);
        }
        let protocol_type = packet_functions::protocol_type(&split_packet.ip_header); 
        if protocol_type == 6 {
            data = packet_functions::read_tcp(packet, split_packet.data);
        } else if protocol_type == 17 {
            data = packet_functions::read_udp(packet);
        } else {
            println!("Unsupported packet reading format");
            return Err(PacketTypeError::new("Unsupported packet reading format"));
        }

        return Ok(());
    // }
}
