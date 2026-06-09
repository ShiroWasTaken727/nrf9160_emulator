import json
import matplotlib.pyplot as plt

# load coverage results
run_files = [
    "coverage_results_output_run_1_ghidra.json",
    "coverage_results_output_run_2_ghidra.json",
    "coverage_results_output_run_3_ghidra.json",
    "coverage_results_output_run_4_ghidra.json",
    "coverage_results_output_run_5_ghidra.json",
]

# plot each run
for i, filename in enumerate(run_files):
    with open(filename) as f:
        data = json.load(f)

    times_hours = []
    block_counts = []

    for entry in data["coverage over time"]:
        time_hours = entry["time"] / 1000 / 3600  # ms to hours
        block_count = entry["ghidra cumulative count"]
        times_hours.append(time_hours)
        block_counts.append(block_count)

    # extend the line to 24 hours if the last timestamp is within 24h and has no new coverage found
    if times_hours[-1] < 24:
        times_hours.append(24)
        block_counts.append(block_counts[-1])

    plt.plot(times_hours, block_counts, label="Run " + str(i + 1))

# labels and styling
plt.xlabel("Time (hours)")
plt.ylabel("Unique Ghidra basic blocks")
plt.title("Code coverage over time")
plt.xlim(0, 24)  # hours
plt.xticks([0, 4, 8, 12, 16, 20, 24])  # force specific x-ticks
plt.ylim(0, None)
plt.legend()
plt.grid(True)

# save and show
# plt.savefig("coverage_plot.png")
# plt.savefig("coverage_plot.pdf")
plt.show()
