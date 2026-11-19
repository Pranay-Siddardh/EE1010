
from pathlib import Path
import warnings

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "badminton_cleaned_data.csv"
OUTPUT_DIR = BASE_DIR / "output"

EXCEL_FILE = OUTPUT_DIR / "badminton_analysis.xlsx"

FIG_DIRS = {
    "Singles": BASE_DIR / "figs" / "singles",
    "Doubles": BASE_DIR / "figs" / "doubles",
    "Mixed": BASE_DIR / "figs" / "mixed",
}

FORMATS = {
    "Singles": ("Singles_W", "Singles_L"),
    "Doubles": ("Doubles_W", "Doubles_L"),
    "Mixed": ("Mixed_W", "Mixed_L"),
}

POLYNOMIAL_DEGREES = [1, 2, 3]
VALIDATION_FRACTION = 0.20


# ============================================================
# DIRECTORY SETUP
# ============================================================

def create_directories():

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for directory in FIG_DIRS.values():
        directory.mkdir(parents=True, exist_ok=True)


# ============================================================
# LOAD CSV
# ============================================================

def load_data():

    if not INPUT_FILE.exists():
        raise FileNotFoundError(
            f"CSV file not found:\n{INPUT_FILE}"
        )

    df = pd.read_csv(INPUT_FILE)

    df.columns = df.columns.astype(str).str.strip()

    required_columns = [
        "Date",
        "Singles_W", "Singles_L",
        "Doubles_W", "Doubles_L",
        "Mixed_W", "Mixed_L",
    ]

    missing = [
        col for col in required_columns
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing CSV columns: {missing}\n"
            f"Found columns: {df.columns.tolist()}"
        )

    print("CSV loaded successfully.")
    print(f"Records found: {len(df)}")

    return df


# ============================================================
# DATE PROCESSING
# ============================================================

def prepare_dates(df):

    df = df.copy()

    # The uploaded cleaned CSV uses ISO dates: YYYY-MM-DD.
    df["Date"] = pd.to_datetime(
        df["Date"],
        format="mixed",
        errors="coerce"
    )

    invalid = df["Date"].isna()

    if invalid.any():
        print(
            f"WARNING: {invalid.sum()} invalid date rows excluded."
        )

    df = df.loc[~invalid].copy()

    df = df.sort_values("Date").reset_index(drop=True)

    return df


# ============================================================
# DAILY DATA PREPARATION
# ============================================================

def prepare_daily(df, wins_col, losses_col):

    daily = df[
        ["Date", wins_col, losses_col]
    ].copy()

    daily = daily.rename(
        columns={
            wins_col: "wins",
            losses_col: "losses",
        }
    )

    daily["wins"] = pd.to_numeric(
        daily["wins"],
        errors="coerce"
    ).fillna(0)

    daily["losses"] = pd.to_numeric(
        daily["losses"],
        errors="coerce"
    ).fillna(0)

    if (daily[["wins", "losses"]] < 0).any().any():
        raise ValueError("Negative match counts found.")

    daily["wins"] = daily["wins"].astype(int)
    daily["losses"] = daily["losses"].astype(int)

    # Combine duplicate dates, if present.
    daily = (
        daily.groupby("Date", as_index=False)
        .agg(
            wins=("wins", "sum"),
            losses=("losses", "sum"),
        )
    )

    daily["total_matches"] = (
        daily["wins"] + daily["losses"]
    )

    # Ignore days without any recorded matches.
    daily = daily[
        daily["total_matches"] > 0
    ].copy()

    daily["win_percentage"] = (
        100 * daily["wins"] / daily["total_matches"]
    )

    return daily.sort_values("Date").reset_index(drop=True)


# ============================================================
# STATISTICAL ANALYSIS
# ============================================================

def calculate_statistics(daily):

    daily = daily.copy()

    percentages = daily["win_percentage"]

    mean = percentages.mean()

    variance = percentages.var(ddof=0)

    std_dev = percentages.std(ddof=0)

    total_wins = int(daily["wins"].sum())

    total_losses = int(daily["losses"].sum())

    total_matches = total_wins + total_losses

    pooled_percentage = (
        100 * total_wins / total_matches
        if total_matches > 0 else 0
    )

    upper_limit = mean + std_dev

    lower_limit = mean - std_dev

    # Deviation from the mean daily win percentage.
    daily["deviation"] = (
        daily["win_percentage"] - mean
    )

    # Performance classification.
    def classify(value):

        if value > upper_limit:
            return "Well Played"

        elif value < lower_limit:
            return "Could Be Better"

        return "Average"

    daily["classification"] = (
        daily["win_percentage"].apply(classify)
    )

    # Competition ranking: ties receive equal ranks.
    daily["rank"] = (
        daily["win_percentage"]
        .rank(method="min", ascending=False)
        .astype(int)
    )

    statistics = {
        "Days Played": len(daily),
        "Total Wins": total_wins,
        "Total Losses": total_losses,
        "Total Matches": total_matches,
        "Mean Daily Win Percentage (%)": mean,
        "Population Variance": variance,
        "Population Standard Deviation (%)": std_dev,
        "Pooled Win Percentage (%)": pooled_percentage,
        "Mean + Standard Deviation": upper_limit,
        "Mean - Standard Deviation": lower_limit,
    }

    return daily, statistics


# ============================================================
# POLYNOMIAL REGRESSION
# ============================================================

def fit_polynomial_models(daily):

    y = daily["win_percentage"].to_numpy(dtype=float)

    n = len(y)

    if n < 5:
        print("Insufficient observations for regression.")
        return None

    # Chronological index.
    x = np.arange(n, dtype=float)

    split = int(
        np.floor(n * (1 - VALIDATION_FRACTION))
    )

    split = max(3, min(split, n - 1))

    x_train = x[:split]
    y_train = y[:split]

    x_valid = x[split:]
    y_valid = y[split:]

    results = {}

    # Fit and validate linear, quadratic and cubic models.
    for degree in POLYNOMIAL_DEGREES:

        if len(x_train) <= degree:
            continue

        coefficients = np.polyfit(
            x_train,
            y_train,
            degree
        )

        model = np.poly1d(coefficients)

        predictions = model(x_valid)

        rmse = np.sqrt(
            np.mean((y_valid - predictions) ** 2)
        )

        mae = np.mean(
            np.abs(y_valid - predictions)
        )

        results[degree] = {
            "validation_rmse": rmse,
            "validation_mae": mae,
        }

    if not results:
        return None

    best_rmse = min(
        result["validation_rmse"]
        for result in results.values()
    )

    # Select the simplest model within 5% of the best RMSE.
    acceptable = [
        degree
        for degree, result in results.items()
        if result["validation_rmse"]
        <= best_rmse * 1.05
    ]

    selected_degree = min(acceptable)

    # Refit the selected model on all observations.
    coefficients = np.polyfit(
        x,
        y,
        selected_degree
    )

    model = np.poly1d(coefficients)

    fitted = model(x)

    residuals = y - fitted

    ss_res = np.sum(residuals ** 2)

    ss_tot = np.sum(
        (y - np.mean(y)) ** 2
    )

    r_squared = (
        1 - ss_res / ss_tot
        if ss_tot != 0 else np.nan
    )

    rmse = np.sqrt(
        np.mean(residuals ** 2)
    )

    mae = np.mean(
        np.abs(residuals)
    )

    return {
        "results": results,
        "selected_degree": selected_degree,
        "model": model,
        "coefficients": coefficients,
        "r_squared": r_squared,
        "rmse": rmse,
        "mae": mae,
        "fitted": fitted,
        "residuals": residuals,
        "split": split,
    }


# ============================================================
# DAILY PERFORMANCE PLOT
# ============================================================

def plot_daily_performance(name, daily, directory):

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.plot(
        daily["Date"],
        daily["win_percentage"],
        marker="o",
        linewidth=1.5,
        label="Daily Win Percentage"
    )

    mean = daily["win_percentage"].mean()

    std_dev = daily["win_percentage"].std(ddof=0)

    ax.axhline(
        mean,
        linestyle="--",
        label=f"Mean = {mean:.2f}%"
    )

    ax.axhline(
        mean + std_dev,
        linestyle=":",
        label=f"Mean + SD = {mean + std_dev:.2f}%"
    )

    ax.axhline(
        mean - std_dev,
        linestyle=":",
        label=f"Mean - SD = {mean - std_dev:.2f}%"
    )

    ax.set_title(f"{name}: Daily Win Percentage")

    ax.set_xlabel("Date")

    ax.set_ylabel("Win Percentage (%)")

    ax.set_ylim(0, 105)

    ax.grid(True, alpha=0.3)

    ax.legend()

    fig.autofmt_xdate()

    fig.tight_layout()

    fig.savefig(
        directory / "daily_performance.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close(fig)


# ============================================================
# REGRESSION PLOT
# ============================================================

def plot_regression(name, daily, regression, directory):

    if regression is None:
        return

    x = np.arange(len(daily))

    y = daily["win_percentage"].to_numpy()

    dense_x = np.linspace(
        x.min(),
        x.max(),
        400
    )

    fig, ax = plt.subplots(figsize=(12, 6))

    ax.scatter(
        x,
        y,
        label="Observed Performance",
        s=25
    )

    ax.plot(
        dense_x,
        regression["model"](dense_x),
        linewidth=2,
        label=(
            f"Polynomial Degree "
            f"{regression['selected_degree']}"
        )
    )

    ax.set_title(
        f"{name}: Polynomial Regression"
    )

    ax.set_xlabel("Chronological Day Index")

    ax.set_ylabel("Win Percentage (%)")

    ax.set_ylim(0, 105)

    ax.grid(True, alpha=0.3)

    ax.legend()

    fig.tight_layout()

    fig.savefig(
        directory / "polynomial_regression.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close(fig)


# ============================================================
# RESIDUAL PLOT
# ============================================================

def plot_residuals(name, regression, directory):

    if regression is None:
        return

    residuals = regression["residuals"]

    fig, ax = plt.subplots(figsize=(10, 5))

    ax.scatter(
        np.arange(len(residuals)),
        residuals,
        s=25
    )

    ax.axhline(
        0,
        linestyle="--"
    )

    ax.set_title(
        f"{name}: Regression Residuals"
    )

    ax.set_xlabel("Chronological Day Index")

    ax.set_ylabel("Residual (%)")

    ax.grid(True, alpha=0.3)

    fig.tight_layout()

    fig.savefig(
        directory / "regression_residuals.png",
        dpi=300,
        bbox_inches="tight"
    )

    plt.close(fig)


# ============================================================
# CONSOLE OUTPUT
# ============================================================

def print_statistics(name, statistics, regression):

    print("\n" + "=" * 65)

    print(name.upper())

    print("=" * 65)

    for key, value in statistics.items():

        if isinstance(value, (float, np.floating)):
            print(f"{key:<42}: {value:.4f}")

        else:
            print(f"{key:<42}: {value}")

    if regression is not None:

        print("\nREGRESSION RESULTS")

        print(
            "Selected degree:",
            regression["selected_degree"]
        )

        print(
            "R-squared:",
            f"{regression['r_squared']:.4f}"
        )

        print(
            "RMSE:",
            f"{regression['rmse']:.4f}"
        )

        print(
            "MAE:",
            f"{regression['mae']:.4f}"
        )

        print("\nValidation comparison:")

        for degree, result in regression["results"].items():

            print(
                f"Degree {degree}: "
                f"Validation RMSE = "
                f"{result['validation_rmse']:.4f}, "
                f"Validation MAE = "
                f"{result['validation_mae']:.4f}"
            )


# ============================================================
# EXCEL EXPORT
# ============================================================

def export_excel(all_daily, all_statistics, all_regressions):

    with pd.ExcelWriter(
        EXCEL_FILE,
        engine="openpyxl"
    ) as writer:

        # Overall summary.
        summary_rows = []

        for name, stats in all_statistics.items():

            row = {
                "Format": name,
                **stats
            }

            regression = all_regressions[name]

            if regression is not None:

                row["Selected Polynomial Degree"] = (
                    regression["selected_degree"]
                )

                row["Regression R-squared"] = (
                    regression["r_squared"]
                )

                row["Regression RMSE"] = (
                    regression["rmse"]
                )

                row["Regression MAE"] = (
                    regression["mae"]
                )

            summary_rows.append(row)

        pd.DataFrame(summary_rows).to_excel(
            writer,
            sheet_name="Overall Summary",
            index=False
        )

        # Individual format sheets.
        for name, daily in all_daily.items():

            daily.to_excel(
                writer,
                sheet_name=f"{name} Daily",
                index=False
            )

            stats_df = pd.DataFrame(
                list(all_statistics[name].items()),
                columns=["Metric", "Value"]
            )

            stats_df.to_excel(
                writer,
                sheet_name=f"{name} Statistics",
                index=False
            )

            regression = all_regressions[name]

            if regression is not None:

                comparison = pd.DataFrame([
                    {
                        "Polynomial Degree": degree,
                        "Validation RMSE": result["validation_rmse"],
                        "Validation MAE": result["validation_mae"],
                    }
                    for degree, result
                    in regression["results"].items()
                ])

                comparison.to_excel(
                    writer,
                    sheet_name=f"{name} Regression",
                    index=False
                )

        # Basic Excel formatting.
        workbook = writer.book

        for worksheet in workbook.worksheets:

            worksheet.freeze_panes = "A2"

            worksheet.auto_filter.ref = (
                worksheet.dimensions
            )

            for column_cells in worksheet.columns:

                max_length = 0

                column_letter = (
                    column_cells[0].column_letter
                )

                for cell in column_cells:

                    if cell.value is not None:

                        max_length = max(
                            max_length,
                            len(str(cell.value))
                        )

                worksheet.column_dimensions[
                    column_letter
                ].width = min(max_length + 3, 35)

    print("\nExcel workbook created:")
    print(EXCEL_FILE)


# ============================================================
# MAIN
# ============================================================

def main():

    warnings.filterwarnings(
        "ignore",
        category=RuntimeWarning
    )

    create_directories()

    print("=" * 65)
    print("BADMINTON PERFORMANCE ANALYSIS")
    print("=" * 65)

    print("\nLoading CSV...")

    df = load_data()

    df = prepare_dates(df)

    if df.empty:
        raise ValueError("No valid dated records found.")

    all_daily = {}
    all_statistics = {}
    all_regressions = {}

    for name, (wins_col, losses_col) in FORMATS.items():

        print(f"\nProcessing {name}...")

        # IMPORTANT: Both column names are passed here.
        daily = prepare_daily(
            df,
            wins_col,
            losses_col
        )

        if daily.empty:

            print(f"No records found for {name}.")

            continue

        daily, statistics = calculate_statistics(
            daily
        )

        regression = fit_polynomial_models(
            daily
        )

        directory = FIG_DIRS[name]

        plot_daily_performance(
            name,
            daily,
            directory
        )

        plot_regression(
            name,
            daily,
            regression,
            directory
        )

        plot_residuals(
            name,
            regression,
            directory
        )

        print_statistics(
            name,
            statistics,
            regression
        )

        all_daily[name] = daily

        all_statistics[name] = statistics

        all_regressions[name] = regression

    if not all_daily:

        raise ValueError(
            "No usable badminton match records were found."
        )

    export_excel(
        all_daily,
        all_statistics,
        all_regressions
    )

    print("\n" + "=" * 65)
    print("ANALYSIS COMPLETE")
    print("=" * 65)

    print("\nGenerated files:")

    print("output/badminton_analysis.xlsx")

    print("figs/singles/")

    print("figs/doubles/")

    print("figs/mixed/")


if __name__ == "__main__":
    main()

