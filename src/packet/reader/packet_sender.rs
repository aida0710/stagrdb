use crate::packet::reader::error::PacketReaderError;
use chrono::{DateTime, Utc};
use log::{error, info};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};
use std::time::Duration;
use tokio::time::sleep;

pub struct PacketSender;

impl PacketSender {
    const MAX_PACKET_SIZE: usize = 1500;

    pub async fn send_packets(interface: &NetworkInterface, packets: Vec<(DateTime<Utc>, Vec<u8>)>) -> Result<(), PacketReaderError> {
        if packets.is_empty() {
            info!("送信するパケットがありません");
            return Ok(());
        }

        let mut tx = match datalink::channel(interface, Default::default()) {
            Ok(Ethernet(tx, _)) => tx,
            Ok(_) => return Err(PacketReaderError::UnsupportedChannelType),
            Err(e) => return Err(PacketReaderError::NetworkError(e.to_string())),
        };

        info!("パケット送信を開始します: {} パケット", packets.len());
        let mut last_packet_time = packets[0].0;

        for (i, (timestamp, raw_packet)) in packets.iter().enumerate() {
            // 前のパケットとの時間差を計算して待機
            let time_diff = *timestamp - last_packet_time;
            if time_diff.num_microseconds().unwrap_or(0) > 0 {
                sleep(Duration::from_micros(time_diff.num_microseconds().unwrap_or(0) as u64)).await;
            }

            if raw_packet.len() > Self::MAX_PACKET_SIZE {
                error!("パケットサイズが制限を超えています: {} bytes (最大: {} bytes)", raw_packet.len(), Self::MAX_PACKET_SIZE);
                continue;
            }

            match tx.send_to(raw_packet, None) {
                Some(Ok(_)) => {
                    info!(
                        "{index}> 送信したパケット: {packet_size}bytes, timestamp = {timestamp}",
                        index = i + 1,
                        packet_size = raw_packet.len(),
                        timestamp = timestamp.format("%Y-%m-%d %H:%M:%S.%f").to_string()
                    );
                },
                Some(Err(e)) => {
                    error!("パケット送信エラー: {}", e);
                    continue;
                },
                None => {
                    error!("パケット送信エラー: 宛先が指定されていません");
                    continue;
                },
            }

            last_packet_time = *timestamp;
        }

        info!("パケット送信が完了しました");
        Ok(())
    }
}
