use crate::idps_log;
use crate::packet::analysis::ethernet::parse_ethernet_header;
use crate::packet::analysis::firewall::FirewallPacket;
use crate::packet::analysis::ip::parse_ip_packet;
use crate::packet::types::EtherType;
use crate::packet::{InetAddr, PacketData};
use crate::services::FirewallService;
use chrono::Utc;
use log::trace;
use std::net::IpAddr;

#[derive(Clone, Copy)]
pub struct IpHeader {
    pub version: u8,
    pub protocol: u8,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
}

pub enum AnalyzeResult {
    Accept(PacketData),
    Reject,
}

pub struct PacketAnalyzer {}

impl PacketAnalyzer {
    pub async fn analyze_packet(ethernet_frame: &[u8]) -> AnalyzeResult {
        // 基本的な長さチェック
        if ethernet_frame.len() < 14 + 20 {
            idps_log!("パケットが短すぎます: パケット長={}、期待値={}", ethernet_frame.len(), 14 + 20);
            return AnalyzeResult::Reject;
        }

        // Ethernetヘッダーの解析
        let ethernet_header = match parse_ethernet_header(ethernet_frame) {
            Ok(result) => result,
            Err(_) => return AnalyzeResult::Reject,
        };

        // IPパケットの解析
        let (src_ip, dst_ip, ip_protocol, src_port, dst_port, flags) = match parse_ip_packet(ethernet_frame, ethernet_header.ether_type).await {
            Ok(result) => result,
            Err(e) => return e,
        };

        // Firewallチェック
        let firewall_packet = FirewallPacket::from_packet(
            ethernet_header.src_mac.clone(),
            ethernet_header.dst_mac.clone(),
            ethernet_header.ether_type,
            src_ip,
            dst_ip,
            ip_protocol,
            src_port,
            dst_port,
        );

        if !FirewallService::check_packet(&firewall_packet).await {
            idps_log!(
                "パケットがファイアウォールルールによってブロックされました: {}:{} -> {}:{}",
                src_ip,
                src_port,
                dst_ip,
                dst_port
            );
            return AnalyzeResult::Reject;
        }

        if ethernet_header.ether_type == EtherType::IP_V6 {
            return AnalyzeResult::Reject;
        }

        trace!(
            "Transport: {}:{} -> {}:{}, Flags: SYN={}, ACK={}, RST={}, FIN={}",
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            flags & 0x02 != 0, // SYN
            flags & 0x10 != 0, // ACK
            flags & 0x04 != 0, // RST
            flags & 0x01 != 0  // FIN
        );

        AnalyzeResult::Accept(PacketData {
            src_mac: ethernet_header.src_mac,
            dst_mac: ethernet_header.dst_mac,
            ether_type: ethernet_header.ether_type,
            src_ip: InetAddr(src_ip),
            dst_ip: InetAddr(dst_ip),
            src_port: src_port as i32,
            dst_port: dst_port as i32,
            ip_protocol,
            timestamp: Utc::now(),
            raw_packet: ethernet_frame.to_vec(),
        })
    }
}
