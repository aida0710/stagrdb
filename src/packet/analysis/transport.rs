use crate::idps_log;
use crate::packet::analysis::AnalyzeResult;
use log::{debug, info, warn};
use std::net::IpAddr;

#[derive(Debug)]
pub struct TransportHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
}

impl TransportHeader {
    pub fn verify_tcp_checksum(&self, transport_data: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> bool {
        // パケット内のチェックサム値を取得
        let packet_checksum = u16::from_be_bytes([transport_data[16], transport_data[17]]);
        info!("パケット内のチェックサム: 0x{:04x}", packet_checksum);

        // 疑似ヘッダーの準備
        let mut pseudo_header = Vec::new();
        match src_ip {
            IpAddr::V4(v4) => {
                pseudo_header.extend_from_slice(&v4.octets());
                pseudo_header.extend_from_slice(&dst_ip.to_string().parse::<std::net::Ipv4Addr>().unwrap().octets());
                pseudo_header.push(0); // 予約済み
                pseudo_header.push(6); // TCPプロトコル番号
                pseudo_header.extend_from_slice(&(transport_data.len() as u16).to_be_bytes());
            },
            IpAddr::V6(_) => return false, // IPv6は今回は対象外
        }

        // チェックサム計算用にTCPヘッダとデータをコピー
        let mut tcp_segment = transport_data.to_vec();
        // チェックサムフィールドを一時的に0にする
        tcp_segment[16] = 0;
        tcp_segment[17] = 0;

        // チェックサムの計算
        let mut sum = calculate_checksum_sum(&pseudo_header);
        sum += calculate_checksum_sum(&tcp_segment);

        // キャリーの処理
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        let calculated_checksum = !sum as u16;
        info!("計算されたチェックサム: 0x{:04x}", calculated_checksum);

        let is_valid = packet_checksum == calculated_checksum;
        if !is_valid {
            warn!("TCPチェックサムが不一致: パケット内=0x{:04x}, 計算値=0x{:04x}", packet_checksum, calculated_checksum);
        } else {
            info!("TCPチェックサム: OK");
        }

        is_valid
    }
}

fn calculate_checksum_sum(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    for chunk in data.chunks(2) {
        if chunk.len() == 2 {
            sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
        } else {
            sum += (chunk[0] as u32) << 8;
        }
    }
    sum
}

pub fn parse_transport_header(data: &[u8], src_ip: IpAddr, dst_ip: IpAddr) -> Result<TransportHeader, AnalyzeResult> {
    // IPヘッダが必要なので、最低でもIPヘッダ長以上のデータが必要
    if data.len() < 20 {
        warn!("TCPヘッダが短すぎます: {} bytes", data.len());
        return Err(AnalyzeResult::Reject);
    }

    // IPヘッダ長を取得
    let ihl = ((data[0] & 0xF) * 4) as usize;

    // トランスポートヘッダの開始位置を計算
    let transport_data = &data[ihl..];

    // TCPヘッダには少なくとも14バイト必要（フラグまで読むため）
    if transport_data.len() < 14 {
        idps_log!("トランスポートヘッダが14byte未満の為、捨てられました");
        return Err(AnalyzeResult::Reject);
    }

    let header = TransportHeader {
        src_port: u16::from_be_bytes([transport_data[0], transport_data[1]]),
        dst_port: u16::from_be_bytes([transport_data[2], transport_data[3]]),
        flags: transport_data[13],
    };

    // チェックサム検証
    header.verify_tcp_checksum(transport_data, src_ip, dst_ip);

    Ok(header)
}
