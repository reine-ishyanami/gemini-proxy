use clap::Parser;
use dialoguer::theme::ColorfulTheme;
use dialoguer::Select;

use crate::action::*;

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
            run_service().await;
        },
        Commands::Generate => {
            generate_ca();
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
    let options = vec![
        "Run",
        "Generate",
        "Install",
        "Uninstall",
        "Update",
    ];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("请选择操作")
        .default(0)
        .items(&options)
        .interact()
        .unwrap();

    match options[selection] {
        "Run" => run_service().await,
        "Generate" => generate_ca(),
        "Install" => install_ca(),
        "Uninstall" => uninstall_ca(),
        "Update" => update_ca(),
        _ => unreachable!(),
    }
}