use clap::Parser;
use command::{App, parse_command, parse_select};
use model::config::APP_CONFIG;

mod certificate;
mod command;
mod model;
mod server;

#[tokio::main]
async fn main() {
    APP_CONFIG
        .init_logger()
        .expect("Failed to initialize logger");

    if let Ok(app) = App::try_parse() {
        parse_command(app.cmd).await;
    } else {
        parse_select().await;
    }
}
