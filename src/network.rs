use packet::{ip, tcp, Error};
use packet::ip::{Protocol};
use packet::{Packet, PacketMut};
use tun::platform::Device;
use tun::{configure};
use std::net::{Ipv4Addr};

pub fn get_traffic_ip(pkt: &ip::v4::Packet<&[u8]>, interface_ip: &Ipv4Addr) -> Option<(Ipv4Addr, u16)>
{
    if pkt.protocol() != Protocol::Tcp {
        return None;
    }
    let tcp = tcp::Packet::new(pkt.payload()).ok()?;
    let local_port = if &pkt.source() == interface_ip {
        tcp.source()
    } else {
        tcp.destination()
    };

    let traffic_ip = if &pkt.source() == interface_ip {
        pkt.destination()
    } else {
        pkt.source()
    };
    Some((traffic_ip, local_port))
}

pub fn create_tunnel(name: &str, ip: &Ipv4Addr) -> Device
{
    let mut config = configure();

    let ips: [u8; 4] = ip.octets();
    config
        .name(name)
        .address((ips[0], ips[1], ips[2], ips[3]))
        .netmask((255, 255, 255, 0))
        .up();

    tun::create(&config).expect("Unable to create tunnel. Please use root or sudo")
}

pub fn create_packet(packet: &ip::v4::Packet<&[u8]>, interface_ip: &Ipv4Addr, forward_ip: &Ipv4Addr) -> Result<ip::v4::Packet<Vec<u8>>, Error>
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

    Ok(new_packet)
}


#[cfg(test)]
mod tests {
    use super::*;
    use packet::{Packet};

    #[test]
    fn create_packet_modify_source_test()
    {
        let interface_src = Ipv4Addr::new(192, 168, 1, 137);
        let interface_forward =  Ipv4Addr::new(192, 168, 1, 138);
        let packet_dst = Ipv4Addr::new(8, 8, 8, 8);

        let raw = [0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8, 0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07];
        let mock_packet = ip::v4::Packet::new(&raw[..]).unwrap();

		let tcp = tcp::Packet::new(mock_packet.payload()).unwrap();

		assert!(mock_packet.is_valid());
		assert!(tcp.is_valid(&packet::ip::Packet::from(&mock_packet)));

        let packet = create_packet(&mock_packet, &interface_src, &interface_forward).unwrap();

        assert_eq!(packet.source(), interface_forward);
        assert_eq!(packet.destination(), packet_dst);
        assert!(packet.is_valid());

        //@TODO fix tcp update checksum issues and uncomment
		// let tcp = tcp::Packet::new(packet.payload()).unwrap();
		// assert!(tcp.is_valid(&packet::ip::Packet::from(&packet)));
    }

    #[test]
    fn create_packet_modify_destination_test()
    {
        let interface_src = Ipv4Addr::new(192, 168, 1, 140);
        let interface_forward =  Ipv4Addr::new(8, 8, 8, 8);

        let packet_src = Ipv4Addr::new(192, 168, 1, 137);

        let raw = [0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8, 0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07];
        let mock_packet = ip::v4::Packet::new(&raw[..]).unwrap();

		let tcp = tcp::Packet::new(mock_packet.payload()).unwrap();

		assert!(mock_packet.is_valid());
		assert!(tcp.is_valid(&packet::ip::Packet::from(&mock_packet)));

        let packet = create_packet(&mock_packet, &interface_src, &interface_forward).unwrap();

        assert_eq!(packet.source(), packet_src);
        assert_eq!(packet.destination(), interface_src);
        assert!(packet.is_valid());

        //@TODO fix tcp update checksum issues and uncomment
		// let tcp = tcp::Packet::new(packet.payload()).unwrap();
		// assert!(tcp.is_valid(&packet::ip::Packet::from(&packet)));
    }
}