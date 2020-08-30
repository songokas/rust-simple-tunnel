use packet::ip::Protocol;
use packet::{ip, tcp, Error};
use packet::{Packet, PacketMut};
use std::net::Ipv4Addr;
use tun::{configure, DeviceAsync};

pub fn get_traffic_ip(
    pkt: &ip::v4::Packet<Vec<u8>>,
    interface_ip: &Ipv4Addr,
) -> Option<(Ipv4Addr, u16)>
{
    let mut local_port = 0;
    if pkt.protocol() == Protocol::Tcp {
        let tcp = tcp::Packet::new(pkt.payload()).ok()?;
        local_port = if &pkt.source() == interface_ip {
            tcp.source()
        } else {
            tcp.destination()
        };
    }

    let traffic_ip = if &pkt.source() == interface_ip {
        pkt.destination()
    } else {
        pkt.source()
    };
    Some((traffic_ip, local_port))
}

pub fn create_tunnel(name: &str, ip: &Ipv4Addr) -> DeviceAsync
{
    let mut config = configure();

    let ips: [u8; 4] = ip.octets();
    config
        .name(name)
        .address((ips[0], ips[1], ips[2], ips[3]))
        .netmask((255, 255, 255, 0))
        .up();

    tun::create_as_async(&config).expect("Unable to create tunnel. Please use root or sudo")
}

pub fn create_packet<T: std::convert::AsRef<[u8]>>(
    packet: &ip::v4::Packet<T>,
    interface_ip: &Ipv4Addr,
    forward_ip: &Ipv4Addr,
) -> Result<ip::v4::Packet<Vec<u8>>, Error>
{
    let mut new_packet = ip::v4::Packet::new(packet.as_ref().to_vec())?;

    let mut tcp_checksum_change = 0;
    if &packet.source() == interface_ip {
         new_packet.checked().set_source(forward_ip.clone())?;
        tcp_checksum_change = -1;
     } else if &packet.destination() == forward_ip {
         new_packet.checked().set_destination(interface_ip.clone())?;
        tcp_checksum_change = 1;
     }

     if packet.protocol() == Protocol::Tcp {
        let (_, tcp_payload) = new_packet.split_mut();
        if let Ok(mut tcp) = tcp::Packet::new(tcp_payload) {
            //@TODO find out why tcp.update_checksum does not work
            if tcp_checksum_change == -1 {
               tcp.set_checksum(tcp.checksum() - 1)?;
           } else if tcp_checksum_change == 1 {
                tcp.set_checksum(tcp.checksum() + 1)?;
            }
        }
    }

    // requires bug fix for tcp checksum in the library
    // if &packet.source() == interface_ip {
    //     new_packet.checked().set_source(forward_ip.clone())?;
    // } else if &packet.destination() == forward_ip {
    //     new_packet.checked().set_destination(interface_ip.clone())?;
    // }

    // if packet.protocol() == Protocol::Tcp {
    //     let packet_temp = new_packet.to_owned();
    //     if let Ok(mut tcp) = tcp::Packet::new(new_packet.payload_mut()) {
    //         let ip = ip::Packet::from(&packet_temp);
    //         tcp.update_checksum(&ip).unwrap();
    //     }
    // }
    Ok(new_packet)
}

#[cfg(test)]
mod tests
{
    use super::*;
    #[test]
    fn create_packet_modify_source_test()
    {
        let interface_src = Ipv4Addr::new(192, 168, 1, 137);
        let interface_forward = Ipv4Addr::new(192, 168, 1, 138);
        let packet_dst = Ipv4Addr::new(8, 8, 8, 8);

        let raw = [
            0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8,
            0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04,
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x07,
        ];

        let mock_packet = ip::v4::Packet::new(&raw[..]).unwrap();

        let tcp = tcp::Packet::new(mock_packet.payload()).unwrap();

        assert!(mock_packet.is_valid());
        assert!(tcp.is_valid(&packet::ip::Packet::from(&mock_packet)));

        let packet = create_packet(&mock_packet, &interface_src, &interface_forward).unwrap();

        assert_eq!(packet.source(), interface_forward);
        assert_eq!(packet.destination(), packet_dst);
        assert!(packet.is_valid());

        let tcp = tcp::Packet::new(packet.payload()).unwrap();
        let ip = packet::ip::Packet::from(&packet);
        assert_eq!(16222, tcp.checksum());
        assert!(tcp.is_valid(&ip));
    }

    #[test]
    fn create_packet_modify_destination_test()
    {
        let interface_src = Ipv4Addr::new(8, 8, 8, 7);
        let interface_forward = Ipv4Addr::new(8, 8, 8, 8);

        let packet_src = Ipv4Addr::new(192, 168, 1, 137);
        let _packet_dst = Ipv4Addr::new(8, 8, 8, 8);

        let raw = [
            0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8,
            0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a,
            0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04,
            0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x03, 0x03, 0x07,
        ];

        let mock_packet = ip::v4::Packet::new(&raw[..]).unwrap();

        let tcp = tcp::Packet::new(mock_packet.payload()).unwrap();
        let ip = packet::ip::Packet::from(&mock_packet);
        assert!(mock_packet.is_valid());
        assert!(tcp.is_valid(&ip));

        let packet = create_packet(&mock_packet, &interface_src, &interface_forward).unwrap();

        assert_eq!(packet.source(), packet_src);
        assert_eq!(packet.destination(), interface_src);
        assert!(packet.is_valid());

        // tcp checksum: pseudo ip header 12 bytes + tcp header + tcp body
        // pseudo header(12 Bytes) = IP of the Source (32 bits) + IP of the Destination (32 bits) + TCP/UDP segment Length(16 bit) + Protocol(8 bits) + Fixed 8 bits

        let tcp = tcp::Packet::new(packet.payload()).unwrap();
        let ip = packet::ip::Packet::from(&packet);

        assert_eq!(16224, tcp.checksum());
        assert!(tcp.is_valid(&ip));
    }
}
