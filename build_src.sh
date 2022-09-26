#!/usr/bin/env bash

echo "Build target rust"
cargo b --release --package millegrilles_maitredescles --bin millegrilles_maitredescles
#cargo b --release --package millegrilles_maitredescles --target aarch64-unknown-linux-gnu --bin millegrilles_maitredescles


