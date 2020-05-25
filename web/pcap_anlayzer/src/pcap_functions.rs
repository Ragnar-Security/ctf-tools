use pcap_file::pcap::PcapReader;
use pcap_file::pcap::Packet;
use std::string::String;
use std::io;
use std::result;
use std::fmt; 
use std::error::Error;
/**
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

pub fn ip_type (packet: &Packet) -> i32 {
    let mut bytes = Vec::new();
    let data = &packet.data;
    for i in 12..13 {
        bytes.push(data[i]);
    }
    let mut return_value = -1; 
    match bytes[0]  {
        80 => match bytes[1] {
            00 => return_value = 0, //IPV4
            06 => return_value =  1, //ARP
            0x35 => return_value =  2, //RARP
            _ => return_value =  -1,
        },
        81 => match bytes[1] {
            00 => return_value =  4, //VLAN-tagged frame (IEEE 802.1Q)
            0x4c => return_value =  5, // SNMP
            _ => return_value =  -1,
        },
        86 => match bytes[1] {
            0xdd => return_value =  6, //IPV6
            _ => return_value =  -1,
        },
        88 => match bytes[1] {
            0x47 => return_value =  7, //MPLS Unicast
            0x48 => return_value =  8, //MPLS Multicast
            0x70 => return_value =  9, //Jumbo Frames
            0x8e => return_value =  10, //EAP over LAN (IEEE 802.1X)
            0xE5 => return_value =  11, //MAC Security (IEEE 802.1AE)
            0xF7 => return_value =  12, //Precision Tree Protocol (IEEE 1588)
            _ => return_value =  -1,
        },
        _ => return_value =  -1

    }
    return return_value;
} 

fn low_level_packet_type(packet: &Packet) -> u32 {
    
    return 0;
}

fn split_packet(packet: &Packet) -> Result<(), PacketTypeError>{
    let data = &packet.data; 
    let data_type = ip_type(&packet); 

    if (data_type == -1) {
        return Err(PacketTypeError::new("Invalid Packet Type"));
    } else {
        let mut packet:PacketData = PacketData {
            ethernet_header: Vec::new(),
            ip_header: Vec::new(),
            low_level_header: Vec::new(),
            data: Vec::new(),
        };
        let mut counter = 0;
        for &i in data.iter(){
            if counter < 13 { 
                packet.ethernet_header.push(i);
            }
            if counter < 33 {
                packet.ip_header.push(i);
            }
            match data_type {
                0 => {
                    
                },
                
            }
        }
        return Ok(());
    }
}
