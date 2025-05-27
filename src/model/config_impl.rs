use log::LevelFilter;

use super::{
    config::{AppConfig, LogLevel},
    log::DailyFileAdapter,
};
use std::io::Write;

impl AppConfig {
    /// 初始化日志
    pub fn init_logger(&self) -> anyhow::Result<()> {
        let logger = self.logger.clone();
        let exclude = logger
            .clone()
            .map(|l| l.exclude)
            .unwrap_or_default()
            .unwrap_or(Vec::with_capacity(0));
        let console_level = logger.map(|l| l.level).unwrap_or_default();

        let mut dispatch = fern::Dispatch::new()
            // 自定义输出格式
            .format(|out, message, record| {
                out.finish(format_args!(
                    "[{}][{}][{}] {}",
                    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f"),
                    record.target(),
                    record.level(),
                    message
                ))
            });
        for r#mod in exclude {
            dispatch = dispatch
                // 禁用指定模块日志
                .level_for(r#mod, log::LevelFilter::Off)
        }
        // 控制台输出配置
        dispatch = dispatch.chain(
            fern::Dispatch::new()
                // 控制台日志等级
                .level(console_level.into())
                .chain(std::io::stdout()),
        );
        if let Some(log_file) = self.logger.clone().unwrap_or_default().file {
            let daily_file = DailyFileAdapter::new(&log_file.dir)?;
            dispatch = dispatch.chain(
                fern::Dispatch::new()
                    // 日志文件日志
                    .level(log_file.level.into())
                    .chain(Box::new(daily_file) as Box<dyn Write + Send>),
            );
        }
        dispatch.apply()?;
        Ok(())
    }
}

impl From<LogLevel> for LevelFilter {
    fn from(value: LogLevel) -> Self {
        match value {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Trace => LevelFilter::Trace,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Error => LevelFilter::Error,
        }
    }
}
