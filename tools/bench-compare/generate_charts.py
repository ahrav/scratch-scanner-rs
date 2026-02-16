#!/usr/bin/env python3
"""Generate SVG comparison charts for the README benchmark tables.

Data is hardcoded from the benchmark results (the source CSVs are
gitignored). Requires only matplotlib.

Usage:
    python3 tools/bench-compare/generate_charts.py
"""

import os
import pathlib

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
import numpy as np

# ── Output directory ────────────────────────────────────────────────
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
OUT_DIR = REPO_ROOT / "docs" / "assets" / "charts"

# ── Colors ──────────────────────────────────────────────────────────
COLOR_SCANNER_RS = "#1a73e8"  # bold blue — scanner-rs
COLOR_KINGFISHER = "#9e9e9e"  # medium gray
COLOR_TRUFFLEHOG = "#bdbdbd"  # light gray
COLOR_GITLEAKS   = "#e0e0e0"  # lightest gray

SCANNER_COLORS = {
    "scanner-rs":  COLOR_SCANNER_RS,
    "Kingfisher":  COLOR_KINGFISHER,
    "TruffleHog":  COLOR_TRUFFLEHOG,
    "Gitleaks":    COLOR_GITLEAKS,
}

# ── Shared style helpers ────────────────────────────────────────────

def _apply_style(ax, xlabel, log_scale=False):
    """Apply consistent minimal styling to an axes."""
    ax.set_xlabel(xlabel, fontsize=10, fontfamily="sans-serif")
    ax.tick_params(axis="both", labelsize=9)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_linewidth(0.6)
    ax.spines["bottom"].set_linewidth(0.6)
    ax.xaxis.grid(True, linewidth=0.4, color="#e0e0e0")
    ax.yaxis.grid(False)
    ax.set_axisbelow(True)
    if log_scale:
        ax.set_xscale("log")


def _grouped_horizontal_bar(ax, repos, scanners, data, colors, xlabel,
                            log_scale=False, value_fmt="{:.1f}"):
    """Draw a grouped horizontal bar chart.

    Parameters
    ----------
    repos : list[str]          — y-axis labels (bottom to top)
    scanners : list[str]       — group labels (legend order)
    data : dict[str, list]     — scanner name → values (same order as repos)
    colors : dict[str, str]    — scanner name → color
    xlabel : str
    log_scale : bool
    value_fmt : str            — format string for bar-end labels
    """
    n_repos = len(repos)
    n_scanners = len(scanners)
    bar_height = 0.7 / n_scanners
    y_positions = np.arange(n_repos)

    for i, scanner in enumerate(scanners):
        offset = (i - n_scanners / 2 + 0.5) * bar_height
        vals = data[scanner]
        bars = ax.barh(
            y_positions + offset,
            vals,
            height=bar_height,
            color=colors[scanner],
            label=scanner,
            edgecolor="white",
            linewidth=0.3,
        )
        # Value labels at bar ends.
        for bar, val in zip(bars, vals):
            x_pos = bar.get_width()
            txt = value_fmt.format(val)
            ax.text(
                x_pos, bar.get_y() + bar.get_height() / 2,
                f"  {txt}", va="center", ha="left",
                fontsize=7, fontfamily="sans-serif", color="#444444",
            )

    ax.set_yticks(y_positions)
    ax.set_yticklabels(repos, fontfamily="sans-serif")
    ax.invert_yaxis()
    _apply_style(ax, xlabel, log_scale=log_scale)
    ax.legend(
        fontsize=8, frameon=True, framealpha=0.9, edgecolor="#cccccc",
        loc="lower right",
    )


# ── Chart 1: Speedup ───────────────────────────────────────────────

SPEEDUP_REPOS = ["node", "vscode", "linux", "rocksdb",
                 "tensorflow", "Babylon.js", "gcc", "jdk"]
SPEEDUP_DATA = {
    "Kingfisher":  [5.8, 2.3, 2.3, 2.3, 2.4, 1.3, 1.9, 1.7],
    "TruffleHog":  [35.6, 13.1, 10.6, 10.8, 16.0, 11.6, 12.4, 18.3],
    "Gitleaks":    [30.0, 8.3, 7.8, 6.7, 10.5, 11.1, 60.0, 16.1],
}


def make_speedup_chart():
    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.subplots_adjust(left=0.14, right=0.88, top=0.95, bottom=0.12)
    scanners = ["Kingfisher", "TruffleHog", "Gitleaks"]
    colors = {s: SCANNER_COLORS[s] for s in scanners}
    _grouped_horizontal_bar(
        ax, SPEEDUP_REPOS, scanners, SPEEDUP_DATA, colors,
        xlabel="Times slower than scanner-rs",
        log_scale=True,
        value_fmt="{:.1f}x",
    )
    ax.xaxis.set_major_formatter(ticker.FormatStrFormatter("%g"))
    return fig


# ── Chart 2: Cold vs warm ratio ────────────────────────────────────

COLD_WARM_REPOS = ["node", "vscode", "linux", "rocksdb",
                   "tensorflow", "Babylon.js", "gcc", "jdk"]
COLD_WARM_DATA = {
    "scanner-rs":  [10.1, 3.3, 13.1, 1.1, 9.5, 2.1, 19.8, 13.8],
    "Kingfisher":  [4.0, 1.5, 6.8, 1.1, 3.0, 1.5, 8.7, 4.1],
    "TruffleHog":  [1.3, 1.1, 1.0, 1.3, 1.1, 1.1, 1.4, 1.9],
    "Gitleaks":    [1.1, 0.9, 1.1, 1.0, 1.0, 1.0, 1.0, 1.3],
}


def make_cold_warm_chart():
    fig, ax = plt.subplots(figsize=(8, 4.5))
    fig.subplots_adjust(left=0.14, right=0.88, top=0.95, bottom=0.12)
    scanners = ["scanner-rs", "Kingfisher", "TruffleHog", "Gitleaks"]
    _grouped_horizontal_bar(
        ax, COLD_WARM_REPOS, scanners, COLD_WARM_DATA, SCANNER_COLORS,
        xlabel="Cold / warm wall-time ratio (filesystem mode)",
        value_fmt="{:.1f}x",
    )
    return fig


# ── Chart 3: Throughput ─────────────────────────────────────────────

# Rows are (repo, mode, cache) combos. Values normalized to MiB/s.
THROUGHPUT_ROWS = [
    "linux  fs warm",
    "gcc  fs warm",
    "vscode  fs warm",
    "node  git warm",
    "vscode  git warm",
    "linux  git warm",
]
THROUGHPUT_DATA = {
    # GiB/s → MiB/s conversion where needed (1 GiB = 1024 MiB)
    "scanner-rs":  [3.3 * 1024, 1.8 * 1024, 1.5 * 1024, 106, 84, 39],
    "Kingfisher":  [1.4 * 1024, 716, 284, 18, 37, 17],
    "TruffleHog":  [125, 109, 98, 3.0, 6.4, 3.7],
    "Gitleaks":    [112, 0.6, 125, 3.5, 10, 5.0],
}


def _fmt_throughput(val):
    """Format MiB/s as GiB/s when ≥ 512 MiB/s, else MiB/s."""
    if val >= 512:
        return f"{val / 1024:.1f} GiB/s"
    return f"{val:.0f} MiB/s"


def make_throughput_chart():
    fig, ax = plt.subplots(figsize=(8, 4.0))
    fig.subplots_adjust(left=0.18, right=0.84, top=0.95, bottom=0.12)
    scanners = ["scanner-rs", "Kingfisher", "TruffleHog", "Gitleaks"]

    n_rows = len(THROUGHPUT_ROWS)
    n_scanners = len(scanners)
    bar_height = 0.7 / n_scanners
    y_positions = np.arange(n_rows)

    for i, scanner in enumerate(scanners):
        offset = (i - n_scanners / 2 + 0.5) * bar_height
        vals = THROUGHPUT_DATA[scanner]
        bars = ax.barh(
            y_positions + offset,
            vals,
            height=bar_height,
            color=SCANNER_COLORS[scanner],
            label=scanner,
            edgecolor="white",
            linewidth=0.3,
        )
        for bar, val in zip(bars, vals):
            ax.text(
                bar.get_width(), bar.get_y() + bar.get_height() / 2,
                f"  {_fmt_throughput(val)}", va="center", ha="left",
                fontsize=7, fontfamily="sans-serif", color="#444444",
            )

    ax.set_yticks(y_positions)
    ax.set_yticklabels(THROUGHPUT_ROWS, fontfamily="sans-serif")
    ax.invert_yaxis()
    _apply_style(ax, "Throughput (MiB/s, log scale)", log_scale=True)
    ax.xaxis.set_major_formatter(ticker.FormatStrFormatter("%g"))
    ax.legend(
        fontsize=8, frameon=True, framealpha=0.9, edgecolor="#cccccc",
        loc="lower right",
    )
    return fig


# ── Chart 4: Memory / RSS ──────────────────────────────────────────

MEMORY_REPOS = ["node", "vscode", "linux", "tensorflow", "gcc"]
MEMORY_DATA = {
    "scanner-rs":  [5.5, 5.4, 22.9, 7.2, 15.8],
    "Kingfisher":  [2.3, 2.1, 8.1, 2.4, 5.6],
    "TruffleHog":  [1.7, 1.6, 8.3, 1.8, 4.8],
    "Gitleaks":    [1.6, 1.3, 7.2, 1.4, 4.5],
}


def make_memory_chart():
    fig, ax = plt.subplots(figsize=(8, 3.5))
    fig.subplots_adjust(left=0.14, right=0.88, top=0.95, bottom=0.14)
    scanners = ["scanner-rs", "Kingfisher", "TruffleHog", "Gitleaks"]
    _grouped_horizontal_bar(
        ax, MEMORY_REPOS, scanners, MEMORY_DATA, SCANNER_COLORS,
        xlabel="Peak RSS (GiB)",
        value_fmt="{:.1f}",
    )
    return fig


# ── Main ────────────────────────────────────────────────────────────

CHARTS = [
    ("speedup.svg",         make_speedup_chart),
    ("cold-warm-ratio.svg", make_cold_warm_chart),
    ("throughput.svg",      make_throughput_chart),
    ("memory-rss.svg",      make_memory_chart),
]


def main():
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for filename, fn in CHARTS:
        fig = fn()
        path = OUT_DIR / filename
        fig.savefig(str(path), format="svg", bbox_inches="tight")
        plt.close(fig)
        print(f"  wrote {path.relative_to(REPO_ROOT)}")
    print(f"\nDone — {len(CHARTS)} charts in {OUT_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
