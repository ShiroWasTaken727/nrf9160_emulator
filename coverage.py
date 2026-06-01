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
            print(f"{timestamp}")
            queue_files.append((timestamp, file_name.path))
            queue_files.sort(key=lambda item: item[1])

    print(queue_files)

    # TODO: replay sorted queue files into emulator and track newly discovered blocks
