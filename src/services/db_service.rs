use crate::database::{Database, ExecuteQuery};
use crate::packet::analysis::{Filter, IpFirewall, Policy};
use crate::packet::MacAddr;
use crate::services::error::ServiceError;
use log::{error, info, warn};
use pnet::datalink::NetworkInterface;
use std::net::IpAddr;
use std::str::FromStr;

pub struct DbService;

impl DbService {
    pub async fn validate_and_record_node(node_id: i16, interface: &NetworkInterface) -> Result<String, ServiceError> {
        let db = Database::get_database();

        // ノードの存在確認
        let validate_query = "SELECT name FROM node_list WHERE id = $1";
        let rows = db.query(validate_query, &[&node_id]).await?;

        if rows.is_empty() {
            error!("ノードID {} はデータベースに登録されていません", node_id);
            return Err(ServiceError::NodeNotFound(node_id));
        }

        let node_name: String = rows[0].get("name");
        info!("ノードID {} (名前: {}) が検証されました", node_id, node_name);

        let mac_address = match &interface.mac {
            Some(mac) => {
                let mac_str = mac.to_string();
                Self::parse_mac_address(&mac_str).unwrap_or(MacAddr([0, 0, 0, 0, 0, 0]))
            },
            None => {
                warn!("選択されたインターフェースにMACアドレスがありません: {}", interface.name);
                MacAddr([0, 0, 0, 0, 0, 0])
            },
        };

        let ip_addresses: Vec<String> = interface.ips.iter().map(|ip| ip.to_string()).collect();
        let ip_address_str = if ip_addresses.is_empty() {
            warn!("選択されたインターフェースにIPアドレスがありません: {}", interface.name);
            "0.0.0.0/0".to_string()
        } else {
            ip_addresses.join(",")
        };

        // 起動時間とインターフェース情報の記録
        let record_query = "INSERT INTO node_activity (node_id, boot_time, interface_name, mac_address, ip_addresses)
                           VALUES ($1, NOW(), $2, $3, $4) RETURNING id";

        let result = db.query(record_query, &[&node_id, &interface.name, &mac_address, &ip_address_str]).await?;

        let activity_id: i32 = result[0].get("id");

        info!("ノードID {} の起動を記録しました (activity_id: {})", node_id, activity_id);
        info!("インターフェース: {}, MACアドレス: {}, IPアドレス: {}", interface.name, mac_address, ip_address_str);

        Ok(node_name)
    }

    pub async fn load_firewall_settings(node_id: i16) -> Result<IpFirewall, ServiceError> {
        let db = Database::get_database();

        // ファイアウォールのポリシー決定（最も優先度の高いもの）
        let policy_query = "
            SELECT policy FROM firewall_settings
            WHERE (node_id = $1 OR node_id IS NULL)
            ORDER BY priority DESC LIMIT 1
        ";

        let policy_rows = db.query(policy_query, &[&node_id]).await?;
        let default_policy = if !policy_rows.is_empty() {
            let policy_str: String = policy_rows[0].get("policy");
            match policy_str.to_lowercase().as_str() {
                "whitelist" => Policy::Whitelist,
                "blacklist" => Policy::Blacklist,
                _ => {
                    info!("未知のポリシー '{}' が指定されました。デフォルトのWhitelistを使用します", policy_str);
                    Policy::Whitelist
                },
            }
        } else {
            info!("ファイアウォール設定が見つかりませんでした。デフォルトのWhitelistを使用します");
            Policy::Whitelist
        };

        // 選択されたポリシーを表示
        info!("ファイアウォールは {:?} ポリシーモードで動作します", default_policy);

        // すべての設定を取得して、ポリシーの一貫性を確認
        let all_policies_query = "
            SELECT DISTINCT policy
            FROM firewall_settings
            WHERE (node_id = $1 OR node_id IS NULL)
        ";

        let all_policies = db.query(all_policies_query, &[&node_id]).await?;

        // ポリシーの一貫性チェック
        for row in &all_policies {
            let policy_str: String = row.get("policy");
            let current_policy = match policy_str.to_lowercase().as_str() {
                "whitelist" => Policy::Whitelist,
                "blacklist" => Policy::Blacklist,
                _ => continue, // 不明なポリシーはスキップ
            };

            // メインポリシーと異なるポリシーが見つかった場合
            if std::mem::discriminant(&current_policy) != std::mem::discriminant(&default_policy) {
                warn!(
                    "ポリシーの不一致を検出: メインポリシーは {:?} ですが、{:?} も設定されています",
                    default_policy, current_policy
                );
                return Err(ServiceError::InconsistentPolicyError(format!(
                    "一貫性のないファイアウォールポリシー: {:?}と{:?}が混在しています",
                    default_policy, current_policy
                )));
            }
        }

        let mut firewall = IpFirewall::new(default_policy);

        // ファイアウォールルールの取得
        let rules_query = "
            SELECT filter_type, filter_value, priority
            FROM firewall_settings
            WHERE (node_id = $1 OR node_id IS NULL)
            ORDER BY priority DESC
        ";

        let rule_rows = db.query(rules_query, &[&node_id]).await?;
        let rules_count = rule_rows.len();

        for row in &rule_rows {
            let filter_type: String = row.get("filter_type");
            let filter_value: String = row.get("filter_value");
            let priority: i16 = row.get("priority");

            if let Some(filter) = Self::parse_filter_rule(&filter_type, &filter_value) {
                info!("ファイアウォールルールを追加: {:?}, 優先度: {}", filter, priority);
                firewall.add_rule(filter, priority as u8);
            } else {
                error!("ファイアウォールルールの解析に失敗しました: {} = {}", filter_type, filter_value);
            }
        }

        info!("ノード {} のファイアウォール設定を {} 個のルールでロードしました", node_id, rules_count);
        Ok(firewall)
    }

    fn parse_filter_rule(filter_type: &str, filter_value: &str) -> Option<Filter> {
        match filter_type {
            "SrcIpAddress" => IpAddr::from_str(filter_value).ok().map(Filter::SrcIpAddress),
            "DstIpAddress" => IpAddr::from_str(filter_value).ok().map(Filter::DstIpAddress),
            "SrcPort" => filter_value.parse::<u16>().ok().map(Filter::SrcPort),
            "DstPort" => filter_value.parse::<u16>().ok().map(Filter::DstPort),
            "EtherType" => {
                // 16進数の場合の処理
                if filter_value.starts_with("0x") {
                    u16::from_str_radix(&filter_value[2..], 16).ok().map(Filter::EtherType)
                } else {
                    // 10進数の場合
                    filter_value.parse::<u16>().ok().map(Filter::EtherType)
                }
            },
            "IpProtocol" => filter_value.parse::<u8>().ok().map(Filter::IpProtocol),
            "SrcMacAddress" => Self::parse_mac_address(filter_value).map(Filter::SrcMacAddress),
            "DstMacAddress" => Self::parse_mac_address(filter_value).map(Filter::DstMacAddress),
            _ => None,
        }
    }

    fn parse_mac_address(mac_str: &str) -> Option<MacAddr> {
        // MACアドレスの形式: XX:XX:XX:XX:XX:XX または XX-XX-XX-XX-XX-XX
        let cleaned_mac = mac_str.replace('-', ":");

        let parts: Vec<&str> = cleaned_mac.split(':').collect();
        if parts.len() != 6 {
            return None;
        }

        let mut bytes = [0u8; 6];
        for (i, part) in parts.iter().enumerate() {
            match u8::from_str_radix(part, 16) {
                Ok(byte) => bytes[i] = byte,
                Err(_) => return None,
            }
        }

        Some(MacAddr(bytes))
    }
}
