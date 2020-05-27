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

pub fn get_transport_data(packet: &Packet) -> std::option::Option<etherparse::TransportHeader>{
    let data = &packet.data;
    let packet_data = packet_functions::parse_headers(data, false).unwrap();
    let transport_layer = packet_data.transport;
    return transport_layer;
}

pub fn get_ip_data (packet: &Packet) -> std::option::Option<etherparse::IpHeader> {
    let data = &packet.data;
    let packet_data = packet_functions::parse_headers(data, false).unwrap();
    let ip_layer = packet_data.ip;
    return ip_layer
}

pub fn get_link_data (packet: &Packet) -> std::option::Option<etherparse::Ethernet2Header> {
    let data = &packet.data;
    let packet_data = packet_functions::parse_headers(data, false).unwrap();
    let link_layer = packet_data.link;
    return link_layer;
}


// pub fn split_packet(packet: &Packet) -> std::result::Result<etherparse::PacketHeaders<'_>, etherparse::ReadError>{
//     let data = &packet.data; 

//     let packet_data = packet_functions::parse_headers(data, false);

//     println!("{:?}", packet_data);

//     return packet_data;
// }
