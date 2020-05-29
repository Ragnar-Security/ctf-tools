use crate::packet_functions;
extern crate etherparse;
use pcap_file::pcap::PcapReader;
use pcap_file::pcap::Packet;
use std::string::String;
use std::any::type_name;
/**=[[V -PFG;]]
 * Currently we are assuming that we are either looking at TCP/UDP packets.
 */
#[derive(Debug)]
pub struct TransportMetadata {
    ports: Vec<u16>,
    sequence_nums: u32, 
    num_ports: u32, 
    num_protocols: u32,
    protocols: Vec<String>, 
}

#[derive(Debug)]
pub struct IpMetadata {
    ips: Vec<String>, 
    num_ips: u32
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

/**
 * Gathers metadata regarding the ip layer of the packet
 */
pub fn ip_metadata(reader: PcapReader<&std::fs::File>) -> std::option::Option<IpMetadata> {
    let mut ip_meta = IpMetadata {
        ips: Vec::new(),
        num_ips: 0,
    };
    for pcap in reader {
        let pcap = pcap.unwrap();
        let ip_data = get_ip_data(&pcap).unwrap();
        
        match ip_data {
            etherparse::IpHeader::Version4(header) => {
                let mut source_ip = String::new();
                let mut destination_ip = String::new();
                let mut counter = 0;
                for i in &header.source {
                    let i = i.to_string();
                    source_ip.push_str(&i); 
                    if counter != 3 {
                        source_ip.push_str(".");
                    }
                    counter = counter + 1; 
                }
                counter = 0;
                for i in &header.destination {
                    let i = i.to_string();
                    destination_ip.push_str(&i); 
                    if counter != 3 {
                        destination_ip.push_str(".");
                    }
                    counter = counter + 1; 
                }
                if !ip_meta.ips.contains(&source_ip) {
                    ip_meta.ips.push(source_ip);
                    ip_meta.num_ips = ip_meta.num_ips + 1;
                }

                if !ip_meta.ips.contains(&destination_ip) {
                    ip_meta.ips.push(destination_ip);
                    ip_meta.num_ips = ip_meta.num_ips + 1; 
                }
            }
            etherparse::IpHeader::Version6(header) => println!("{:?}", header), 
            _ => return std::option::Option::None, 
        }
    }
    return std::option::Option::from(ip_meta);
}
/**
 * Gathers metadata regarding the transport layer
 */
pub fn transport_metadata(reader: PcapReader<&std::fs::File>) {
    let mut transport_meta = TransportMetadata {
        ports: Vec::new(),
        sequence_nums: 0, 
        num_protocols: 0,
        num_ports: 0, 
        protocols: Vec::new(),

    };
    for pcap in reader {
        let protocol = String::from("UDP"); 
        let pcap = pcap.unwrap();
        let transport_data = get_transport_data(&pcap).unwrap();
        let transport_tcp = transport_data.clone().tcp();
        let transport_udp = transport_data.clone().udp();
        if transport_tcp != None {
            let transport_tcp = transport_tcp.unwrap();
            if !transport_meta.ports.contains(&transport_tcp.source_port) {
                transport_meta.ports.push(transport_tcp.source_port); 
                transport_meta.num_ports = transport_meta.num_ports + 1;
            }
            if !transport_meta.ports.contains(&transport_tcp.destination_port) {
                transport_meta.ports.push(transport_tcp.destination_port); 
                transport_meta.num_ports = transport_meta.num_ports + 1;
            }
            if !transport_meta.protocols.contains(&protocol) {
                transport_meta.protocols.push(protocol); 
                transport_meta.num_protocols = transport_meta.num_protocols + 1; 
            }  
        } else if transport_udp != None {
            let transport_udp = transport_udp.unwrap();
            if !transport_meta.ports.contains(&transport_udp.source_port) {
                transport_meta.ports.push(transport_udp.source_port); 
                transport_meta.num_ports = transport_meta.num_ports + 1;
            }
            if !transport_meta.ports.contains(&transport_udp.destination_port) {
                transport_meta.ports.push(transport_udp.destination_port); 
                transport_meta.num_ports = transport_meta.num_ports + 1;
            }
            if !transport_meta.protocols.contains(&protocol) {
                transport_meta.protocols.push(protocol); 
                transport_meta.num_protocols = transport_meta.num_protocols + 1; 
            }
        } else {
            println!("Is neither");
        }
    }
    println!("{:?}", transport_meta);
}

fn type_of<T>(_:T) -> &'static str{
    return type_name::<T>()
}
// pub fn split_packet(packet: &Packet) -> std::result::Result<etherparse::PacketHeaders<'_>, etherparse::ReadError>{
//     let data = &packet.data; 

//     let packet_data = packet_functions::parse_headers(data, false);

//     println!("{:?}", packet_data);

//     return packet_data;
// }
