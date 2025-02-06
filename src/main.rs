use nftables::cli;

fn main() {
    let args = cli::collect_command_args();
    cli::handle_args(args);
}
