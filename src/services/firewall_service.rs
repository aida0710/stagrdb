use crate::packet::analysis::{FirewallPacket, IpFirewall};
use crate::services::db_service::DbService;
use crate::services::error::ServiceError;
use log::{error, info};
use std::sync::Arc;
use tokio::sync::RwLock;

lazy_static::lazy_static! {
    static ref DYNAMIC_FIREWALL: Arc<RwLock<Option<IpFirewall>>> = Arc::new(RwLock::new(None));
}

pub struct FirewallService;

impl FirewallService {
    pub async fn initialize(node_id: i16) -> Result<(), ServiceError> {
        info!("ノード {} のファイアウォール設定を初期化しています...", node_id);

        // データベースからファイアウォール設定を取得
        match DbService::load_firewall_settings(node_id).await {
            Ok(firewall) => {
                // グローバルファイアウォールインスタンスを更新
                let mut fw = DYNAMIC_FIREWALL.write().await;
                *fw = Some(firewall);

                info!("ファイアウォールの初期化が完了しました");
                Ok(())
            },
            Err(e) => {
                error!("ファイアウォール設定の読み込みに失敗しました: {}", e);
                Err(ServiceError::FirewallLoadError(e.to_string()))
            },
        }
    }

    pub async fn check_packet(packet: &FirewallPacket) -> bool {
        let fw = DYNAMIC_FIREWALL.read().await;

        match &*fw {
            Some(firewall) => firewall.check(packet),
            None => {
                info!("ファイアウォールが初期化されていないため、全てのパケットを破棄します。早急に再起動してください。");
                false
            },
        }
    }
}
