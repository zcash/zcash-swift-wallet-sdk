#!/usr/bin/python3

# Vendored verbatim from "Checkmate" by Electric Coin Company Prototypes and
# Experiments (https://github.com/zcash-hackworks/checkmate), MIT License.
# Bundled here so the update-checkpoints skill is self-contained and does not
# depend on a copy living in a developer's ~/Downloads. Do not edit the logic;
# the skill's driver (fetch_checkpoints.py) wraps this script.
#
# NOTE on the os.system / shell=True calls below: they are inherited from
# upstream and are NOT a command-injection risk in this skill. The only values
# interpolated into the shell are `host` (a hard-coded lightwalletd address from
# the driver's network table — never user input) and `height` (always a Python
# int from range()/the parsed latest block height). No untrusted string ever
# reaches the shell. The driver, not this file, is where new inputs would be
# added, so keep host values fixed and heights integer there.
#
# Usage:
#   checkmate.py LIGHTWALLETD_HOST --start-height HEIGHT [--interval N] [--to-json]
# Arguments are POSITIONAL: host first, then --start-height VALUE, then
# --interval VALUE. With --to-json each tree state is written to <height>.json
# in the current working directory.

import sys
import os
import subprocess
import json

from string import Template

def usage():
    return """
Checkmate: your GetTreeState checkpoint mate.

checkmate.py LIGHTWALLETD_HOST --start-height HEIGHT [--interval BLOCK_INTERVAL] [--to-json]
--start-height the height you want to start pulling tree states from
--to-json exports the outputs to [height].json files instead of just stdout
"""

def main():
    if len(sys.argv) < 4:
        print(" Error: insufficient arguments")
        print(usage())
        return 1

    lightwalletd_host = sys.argv[1]

    start_height = int(sys.argv[3])

    block_interval = 10000
    if "--interval" in sys.argv:
        block_interval = int(sys.argv[5])

    to_json = "--to-json" in sys.argv

    command_template = Template("grpcurl -d '{ \"height\" : $height }' $host cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState")

    if to_json:
        command_template = Template("grpcurl -d '{ \"height\" : $height }' $host cash.z.wallet.sdk.rpc.CompactTxStreamer/GetTreeState > $height.json")

    latest_height_template = Template("grpcurl $host cash.z.wallet.sdk.rpc.CompactTxStreamer/GetLatestBlock")
    output = subprocess.check_output(latest_height_template.substitute(host=lightwalletd_host), shell=True)

    latest_block = json.loads(output)
    latest_height = int(latest_block['height'])


    for h in range(start_height,latest_height,block_interval):
        os.system(command_template.substitute(height=h,host=lightwalletd_host))

    os.system(command_template.substitute(height=latest_height,host=lightwalletd_host))

if __name__ == "__main__":
    main()
