from pathlib import Path
import numpy as np
import imageio.v3 as iio

# ==================================================
# CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "figs"

NAMES = [
    "arjun",
    "arya",
    "mudit",
    "visweshwar",
    "saksham",
    "pranay",
    "nethra",
    "sara",
]

FIXED_THRESHOLD = 128


# ==================================================
# IMAGE PROCESSING
# ==================================================

def load_jpg_as_rgb(image_path):
    """Load an image and return an RGB array in the range 0-255."""
    image = iio.imread(image_path)

    # Convert grayscale input to RGB.
    if image.ndim == 2:
        image = np.stack([image] * 3, axis=-1)

    # Remove alpha channel if present.
    elif image.ndim == 3 and image.shape[2] == 4:
        image = image[:, :, :3]

    if image.ndim != 3 or image.shape[2] != 3:
        raise ValueError(f"Unsupported image shape: {image.shape}")

    # JPEG images are normally uint8; handle other input formats safely.
    if np.issubdtype(image.dtype, np.floating):
        if image.max() <= 1.0:
            image = image * 255.0

    return np.clip(image, 0, 255).astype(np.uint8)


def rgb_to_ycbcr(rgb):
    """Convert RGB to YCbCr using ITU-R BT.601 formulas."""
    rgb = rgb.astype(np.float32)

    R = rgb[:, :, 0]
    G = rgb[:, :, 1]
    B = rgb[:, :, 2]

    Y = 0.299 * R + 0.587 * G + 0.114 * B
    Cb = 128 - 0.168736 * R - 0.331264 * G + 0.5 * B
    Cr = 128 + 0.5 * R - 0.418688 * G - 0.081312 * B

    return np.dstack((Y, Cb, Cr))


def ycbcr_to_grayscale(ycbcr):
    """Extract the Y (luminance) channel."""
    return np.clip(
        ycbcr[:, :, 0], 0, 255
    ).astype(np.uint8)


def fixed_threshold(grayscale, threshold=FIXED_THRESHOLD):
    """Apply a fixed threshold of 128."""
    return np.where(
        grayscale >= threshold, 255, 0
    ).astype(np.uint8)


def dynamic_threshold(grayscale):
    """Apply the mean grayscale intensity as the threshold."""
    mean_threshold = float(np.mean(grayscale))

    output = np.where(
        grayscale >= mean_threshold, 255, 0
    ).astype(np.uint8)

    return output, mean_threshold


# ==================================================
# SAVE OUTPUTS
# ==================================================

def save_image(path, image):
    """Save RGB or grayscale uint8 images without normalization errors."""
    image = np.asarray(image)

    if image.dtype != np.uint8:
        image = np.clip(image, 0, 255).astype(np.uint8)

    iio.imwrite(path, image)


# ==================================================
# PROCESS ONE PERSON
# ==================================================

def process_image(source_path, person_name):
    person_dir = OUTPUT_DIR / person_name
    person_dir.mkdir(parents=True, exist_ok=True)

    print(f"\nProcessing {person_name}: {source_path.name}")

    # Load and process the original image.
    rgb = load_jpg_as_rgb(source_path)
    ycbcr = rgb_to_ycbcr(rgb)
    grayscale = ycbcr_to_grayscale(ycbcr)

    # Apply both thresholding methods.
    static_bw = fixed_threshold(grayscale)
    dynamic_bw, mean_threshold = dynamic_threshold(grayscale)

    # Save all four images.
    save_image(person_dir / "input.jpg", rgb)
    save_image(person_dir / "gray.jpg", grayscale)
    save_image(person_dir / "static.jpg", static_bw)
    save_image(person_dir / "dynamic.jpg", dynamic_bw)

    print(f"  RGB shape:        {rgb.shape}")
    print(f"  Grayscale shape:  {grayscale.shape}")
    print(f"  Fixed threshold:  {FIXED_THRESHOLD}")
    print(f"  Mean threshold:   {mean_threshold:.2f}")
    print(f"  Saved to:         {person_dir}")
    print("  [SUCCESS]")


# ==================================================
# MAIN AUTOMATION
# ==================================================

def main():
    print("RGB IMAGE PROCESSING AUTOMATION")
    print(f"Input directory:  {BASE_DIR}")
    print(f"Output directory: {OUTPUT_DIR}")

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    success_count = 0
    failures = []

    for index, name in enumerate(NAMES, start=1):
        source_path = BASE_DIR / f"{index}.jpg"

        if not source_path.is_file():
            message = f"Missing input: {source_path.name}"
            print(f"[SKIPPED] {message}")
            failures.append(message)
            continue

        try:
            process_image(source_path, name)
            success_count += 1

        except Exception as error:
            message = f"{source_path.name}: {error}"
            print(f"[ERROR] {message}")
            failures.append(message)

    print("\n" + "=" * 45)
    print("AUTOMATION FINISHED")
    print(f"Successful images: {success_count}/{len(NAMES)}")
    print(f"Failed or missing: {len(failures)}")

    if failures:
        print("\nProblems encountered:")
        for failure in failures:
            print(f"  - {failure}")
    else:
        print("\nAll images processed successfully.")

    print(f"\nResults: {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
