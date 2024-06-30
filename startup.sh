sudo /home/aida/.cargo/bin/cargo run --package cli-app --bin cli-app
cargo build --release
sudo setcap cap_net_raw,cap_net_admin=eip target/release/cli-app
./target/release/cli-app