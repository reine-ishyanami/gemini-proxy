use clap::Parser;
use dialoguer::Select;
use dialoguer::theme::ColorfulTheme;

use crate::ca::*;
use crate::server::run_service;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct App {
    #[command(subcommand)]
    pub cmd: Commands,
}

#[derive(Parser, Debug)]
pub enum Commands {
    Run,
    Generate,
    Install,
    Uninstall,
    Update,
}

pub(crate) async fn parse_command(cmd: Commands) {
    match cmd {
        Commands::Run => {
            if let Err(err) = run_service().await {
                log::error!("服务启动失败: {err}");
            }
        }
        Commands::Generate => {
            if let Err(err) = generate_ca() {
                log::error!("生成证书失败: {err}");
            }
        }
        Commands::Install => {
            install_ca();
        }
        Commands::Uninstall => {
            uninstall_ca();
        }
        Commands::Update => {
            update_ca();
        }
    }
}

pub(crate) async fn parse_select() {
    let options = vec!["Run", "Generate", "Install", "Uninstall", "Update"];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("请选择操作")
        .default(0)
        .items(&options)
        .interact()
        .unwrap();

    match options[selection] {
        "Run" => {
            if let Err(err) = run_service().await {
                log::error!("服务启动失败: {err}");
            }
        }
        "Generate" => {
            if let Err(err) = generate_ca() {
                log::error!("生成证书失败: {err}");
            }
        }
        "Install" => install_ca(),
        "Uninstall" => uninstall_ca(),
        "Update" => update_ca(),
        _ => unreachable!(),
    }
}
