use crate::config::AppConfig;
use crate::packet::reader::error::PacketReaderError;
use crate::packet::reader::packet_sender::PacketSender;
use crate::packet::repository::PacketRepository;
use chrono::{DateTime, Utc};
use log::{error, info};
use pnet::datalink::NetworkInterface;
use std::time::Duration;

#[derive(Clone)]
pub struct PacketReader {
    last_timestamp: Option<DateTime<Utc>>,
    is_first_fetch: bool,
}

impl PacketReader {
    pub fn new() -> Self {
        Self {
            last_timestamp: None,
            is_first_fetch: true,
        }
    }

    pub async fn start(interface: NetworkInterface) -> Result<(), PacketReaderError> {
        let config: AppConfig = AppConfig::new().map_err(|e| PacketReaderError::ConfigurationError(e.to_string()))?;

        let mut reader = Self::new();

        loop {
            match reader.fetch_and_send_packets(&interface, config.node_id).await {
                Ok(_) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                },
                Err(e) => {
                    error!("パケット処理中にエラーが発生しました: {:?}", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                },
            }
        }
    }

    async fn fetch_and_send_packets(&mut self, interface: &NetworkInterface, node_id: i16) -> Result<(), PacketReaderError> {
        match PacketRepository::get_filtered_packets(node_id, self.is_first_fetch, self.last_timestamp.as_ref()).await {
            Ok(packets) => {
                if !packets.is_empty() {
                    info!(
                        "パケットを取得しました: {} 個 (開始時刻: {}, 終了時刻: {})",
                        packets.len(),
                        packets.first().map(|(t, _)| t).unwrap(),
                        packets.last().map(|(t, _)| t).unwrap()
                    );

                    // 最後のタイムスタンプを更新
                    self.last_timestamp = packets.last().map(|(t, _)| *t);

                    // パケットを送信
                    if let Err(e) = PacketSender::send_packets(interface, packets).await {
                        error!("パケットの送信に失敗しました: {:?}", e);
                    }
                }

                if self.is_first_fetch {
                    self.is_first_fetch = false;
                }

                Ok(())
            },
            Err(e) => {
                error!("パケットの取得に失敗しました: {:?}", e);
                Err(PacketReaderError::DatabaseError(e.to_string()))
            },
        }
    }
}
