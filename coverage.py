import os
import sys
import re
import json
import subprocess

output_dir = "output"

if len(sys.argv) > 1:
    output_dir = sys.argv[1]

# collect all files from the queue
queue_files = []
queue_folder_name = "queue"

for entry in os.scandir(output_dir):
    if not entry.is_dir():
        continue

    queue_directory = os.path.join(entry.path, queue_folder_name)

    if not os.path.isdir(queue_directory):
        continue

    for file_name in os.scandir(queue_directory):
        if file_name.name.startswith("id:"):
            time_field = re.search(r"time:(\d+)", file_name.name)
            timestamp = int(time_field.group(1))
            queue_files.append((timestamp, file_name.path))

queue_files.sort(key=lambda item: item[0])

# replay queue files in emulator.py
cumulative_blocks = set()
coverage_over_time = []

for file_index, (stamp, fname) in enumerate(
    queue_files
):  # file_index only used for printing
    output_run = subprocess.run(
        ["python3", "emulator.py", fname], capture_output=True, text=True
    )
    blocks = set()  # for each file create a temporary set to store unique blocks
    for line in output_run.stdout.split("\n"):
        if "Basic block at" in line:
            basic_block = re.search("0x([0-9a-fA-F]+),", line)
            if basic_block:
                basic_block_hex = int(basic_block.group(1), 16)
                blocks.add(basic_block_hex)

    before_update = len(cumulative_blocks)
    cumulative_blocks.update(blocks)

    after_update = len(cumulative_blocks)
    new_block_count = after_update - before_update

    print(
        f"{file_index+1}/{len(queue_files)}: time = {stamp}, new total blocks: {after_update}, found {new_block_count} new blocks."
    )

    coverage_over_time.append(
        {
            "file": fname,
            "time": stamp,
            "new total unique blocks": after_update,
            "new blocks found": new_block_count,
        }
    )

    results = {
        "total unique blocks": len(cumulative_blocks),
        "total inputs": len(queue_files),
        "blocks": [hex(b) for b in cumulative_blocks],
        "coverage over time": coverage_over_time,
    }
    print(results)

# write results to json file
with open("coverage_results.json", "w") as file:
    json.dump(results, file)
