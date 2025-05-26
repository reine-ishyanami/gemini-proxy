use clap::Parser;
use command::{App, parse_command, parse_select};

mod certificate;
mod command;
mod server;

#[tokio::main]
async fn main() {
    env_logger::init();
    if let Ok(app) = App::try_parse() {
        parse_command(app.cmd).await;
    } else {
        parse_select().await;
    }
}
