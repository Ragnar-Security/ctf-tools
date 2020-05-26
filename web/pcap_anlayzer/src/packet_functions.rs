extern crate etherparse;

pub fn ip_type (ethernet_header: Vec<u8>) -> i32 {
    let mut return_value = -1; 
    match ethernet_header[0]  {
        80 => match ethernet_header[1] {
            00 => return_value = 0, //IPV4
            06 => return_value =  1, //ARP
            0x35 => return_value =  2, //RARP
            _ => return_value =  -1,
        },
        81 => match ethernet_header[1] {
            00 => return_value =  4, //VLAN-tagged frame (IEEE 802.1Q)
            0x4c => return_value =  5, // SNMP
            _ => return_value =  -1,
        },
        86 => match ethernet_header[1] {
            0xdd => return_value =  6, //IPV6
            _ => return_value =  -1,
        },
        88 => match ethernet_header[1] {
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

pub fn protocol_type(ip_header: &Vec<u8>) -> u8 {
    return ip_header[10];
}