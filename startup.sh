#!/bin/bash

# Rustのデフォルトツールチェーンを設定
echo "Rustのデフォルトツールチェーンを安定版に設定します..."
rustup default stable

# プロジェクトディレクトリに移動
echo "プロジェクトディレクトリに移動します..."

# shellcheck disable=SC2164
cd ~/RustroverProjects/rust-cli-app

# 既存のビルドファイルを削除
#echo "既存のビルドファイルを削除します..."
#cargo clean

# プロジェクトをビルド
echo "プロジェクトをビルドします..."
cargo build --release

# 実行ファイルに権限を付与
sudo setcap cap_net_raw,cap_net_admin=eip target/release/cli-app

echo "アプリケーションを実行します..."
sudo ./target/release/cli-app