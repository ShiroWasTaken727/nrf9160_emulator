import json
import pandas as pd
from array import *
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

granularity = 1

json_files = sorted(
    [
        "coverage_results_run_1_ghidra.json",
        "coverage_results_run_2_ghidra.json",
        "coverage_results_run_3_ghidra.json",
        "coverage_results_run_4_ghidra.json",
        "coverage_results_run_5_ghidra.json",
    ]
)


def gen_cov_plot(df):
    # taken from https://github.com/pr0me/safirefuzz-experiments/blob/main/04_eval_data/coverage/gen_fig3.ipynb

    fig, axes = plt.subplots(1, 1, figsize=(6, 4))

    sns.set_style("darkgrid")
    g = sns.lineplot(
        ax=axes,
        x="Time",
        y="Coverage",
        data=df,
        errorbar=("ci", 95),
        estimator=np.median,
    )

    g.set(xlabel="Time in Hours")
    g.set(ylabel="Median Number of Basic Blocks")
    g.set_xlim([-1, 25])
    g.set_xticks([x for x in range(-1, 26) if x % 2 == 0])
    g.grid(True)

    plt.tight_layout()
    plt.savefig("coverage_plot.pdf")
    plt.savefig("coverage_plot.png")


def fill_dataframe(fn):
    with open(fn, "r") as f:
        data = json.load(f)

    cov_data = [(x, 0) for x in range(0, 86400 + granularity, granularity)]

    for entry in data["coverage over time"]:
        time_s = round_value(entry["time"] / 1000.0)
        coverage = entry["ghidra cumulative count"]
        cov_data.append((time_s, coverage))

    df = pd.DataFrame(cov_data, columns=["Time", "Coverage"])
    return df


def round_value(x):
    base = granularity
    return base * round(x / base)


def parse_json_file():
    dfs = []

    for fn in json_files:
        df = fill_dataframe(fn)
        df.sort_values(by=["Time", "Coverage"], inplace=True)
        df.drop_duplicates(
            subset=["Time"], inplace=True, ignore_index=True, keep="last"
        )
        df["Coverage"] = (
            df["Coverage"].replace(0, np.nan).ffill().astype(int)
        )  # convert 0 to NaN and forward fill to get the last known coverage value for each time point, then convert back to int
        df["Time"] = df["Time"].apply(lambda x: float(x / (60 * 60)))

        dfs.append(df)

    dfs_con = pd.concat(dfs, ignore_index=True)

    # check
    print("Done parsing")
    gen_cov_plot(dfs_con)


def main():
    parse_json_file()


if __name__ == "__main__":
    main()
