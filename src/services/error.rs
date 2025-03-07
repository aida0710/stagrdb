use crate::database::DatabaseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("データベースエラー: {0}")]
    DatabaseError(#[from] DatabaseError),

    #[error("ノード {0} が見つかりません")]
    NodeNotFound(i16),

    #[error("ファイアウォール設定の読み込みに失敗しました: {0}")]
    FirewallLoadError(String),

    #[error("ファイアウォールルールの解析に失敗しました: {0}")]
    FirewallRuleParseError(String),
}
