use clap::Parser;
use command::{parse_command, parse_select, App};

mod command;
mod action;

#[tokio::main]
async fn main() {
    if let Ok(app) = App::try_parse() {
        parse_command(app.cmd).await;
    } else {
        parse_select().await;
    }
}
