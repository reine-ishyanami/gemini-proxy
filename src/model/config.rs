use std::sync::{Arc, LazyLock};

pub static APP_CONFIG: LazyLock<Arc<AppConfig>> = LazyLock::new(|| {
    let config = init_config().unwrap();
    Arc::new(config)
});

fn init_config() -> anyhow::Result<AppConfig> {
    let config: AppConfig = std::fs::read_to_string("app.yml")
        .ok()
        .and_then(|config_str| serde_yml::from_str(&config_str).ok())
        .or_else(|| {
            std::fs::read_to_string("app.yaml")
                .ok()
                .and_then(|config_str| serde_yml::from_str(&config_str).ok())
        })
        .ok_or_else(|| anyhow::anyhow!("配置文件 app.yml/yaml 不存在"))?;
    if config.gemini.is_empty() {
        return Err(anyhow::anyhow!("请至少配置一个 Gemini API Key"));
    }
    Ok(config)
}

#[derive(Debug, serde::Deserialize)]
pub struct AppConfig {
    pub logger: Option<LoggerConfig>,
    pub gemini: Vec<GeminiConfig>,
}

#[derive(serde::Deserialize, Debug, Clone, Default)]
pub struct LoggerConfig {
    pub level: LogLevel,
    pub file: Option<LogFileConfig>,
    pub exclude: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

#[derive(serde::Deserialize, Debug, Clone, Default)]
pub struct LogFileConfig {
    pub dir: String,
    pub level: LogLevel,
}

#[derive(Debug, serde::Deserialize)]
pub struct GeminiConfig {
    pub key: String,
}
