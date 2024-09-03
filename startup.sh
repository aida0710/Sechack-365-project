#!/bin/bash

# コンソールログを消去
clear

# Rustのデフォルトツールチェーンを設定
echo "Rustのデフォルトツールチェーンを安定版に設定します..."
rustup default stable

# プロジェクトディレクトリに移動
echo "プロジェクトディレクトリに移動します..."

# shellcheck disable=SC2164
cd ~/RustroverProjects/nids-for-rust

# 既存のビルドファイルを削除
#echo "既存のビルドファイルを削除します..."
#cargo clean

# プロジェクトをビルド
echo "プロジェクトをビルドします..."
cargo build --release

# ビルドが成功した場合のみ、以下を実行
# shellcheck disable=SC2181
if [ $? -eq 0 ]; then
    # 実行ファイルに権限を付与
    echo "実行ファイルに権限を付与します..."
    sudo setcap cap_net_raw,cap_net_admin=eip target/release/nids-for-rust

    echo "アプリケーションを実行します..."
    sudo ./target/release/nids-for-rust
else
    echo "ビルドに失敗しました。エラーを確認してください。"
fi