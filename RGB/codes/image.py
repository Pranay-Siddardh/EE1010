import numpy as np
import matplotlib.pyplot as plt
from scipy.ndimage import gaussian_filter

# ==============================================================================
# STEP 1: READ THE JPG AND EXTRACT THE RAW RGB MATRIX
# ==============================================================================
def load_jpg_as_rgb(image_path):
    """
    Reads a JPEG image file from disk and loads it as a 3D NumPy array.
    Shape: (Height, Width, 3) where channels are [Red, Green, Blue].
    """
    try:
        import imageio.v3 as iio
        rgb_matrix = iio.imread(image_path)
    except ImportError:
        rgb_matrix = plt.imread(image_path)
        
    return rgb_matrix.astype(np.float32)


# ==============================================================================
# STEP 2: CONVERT RAW RGB MATRIX TO DECOUPLED YCbCr MATRIX
# ==============================================================================
def rgb_to_ycbcr(rgb_matrix):
    """
    Converts raw RGB pixel tuples into YCbCr space using ITU-R BT.601 formulas.
      - Y: Isolates Brightness (Luminance)
      - Cb & Cr: Isolate Color (Chrominance) offsets
    """
    R = rgb_matrix[:, :, 0]
    G = rgb_matrix[:, :, 1]
    B = rgb_matrix[:, :, 2]

    # Calculate Luminance (Y) and Chrominance (Cb, Cr)
    Y  = 0.299 * R + 0.587 * G + 0.114 * B
    Cb = 128 - 0.168736 * R - 0.331264 * G + 0.5 * B
    Cr = 128 + 0.5 * R - 0.418688 * G - 0.081312 * B

    return np.dstack((Y, Cb, Cr))


# ==============================================================================
# STEP 3: CONVERT TO GRAYSCALE (DISCARD COLOR CHANNELS)
# ==============================================================================
def ycbcr_to_grayscale(ycbcr_matrix):
    """
    Drops Cb and Cr channels completely, returning a 2D scalar array of Y values.
    Transforms memory structure from (Height, Width, 3) -> (Height, Width).
    """
    grayscale_matrix = ycbcr_matrix[:, :, 0]
    return np.clip(grayscale_matrix, 0, 255).astype(np.uint8)


# ==============================================================================
# STEP 4A: STATIC 128 REFERENCE THRESHOLDING (THE "REFERENCE BREAKER")
# ==============================================================================
def grayscale_to_static_bw(grayscale_matrix, threshold=128):
    """
    Applies a fixed, static threshold at 128 (midpoint of [0, 255]).
    
    Why is this a "reference breaker"?
      - If an image is overexposed (too bright) or underexposed (too dark),
        this naive method breaks down, losing fine details completely!
    """
    # Hardcoded threshold at 128
    bw_static = np.where(grayscale_matrix >= threshold, 255, 0).astype(np.uint8)
    return bw_static


# ==============================================================================
# STEP 4B: ADAPTIVE DYNAMICALLY SCALED BLACK & WHITE ALGORITHM
# ==============================================================================
def grayscale_to_adaptive_bw(grayscale_matrix):
    """
    Calculates the MEAN INTENSITY (mu) of the image and thresholds dynamically.
    Guarantees adaptive contrast scaling regardless of lighting!
    """
    mu = np.mean(grayscale_matrix)
    print(f"[INFO] Image Dynamic Threshold Mean (μ): {mu:.2f}")

    bw_adaptive = np.where(grayscale_matrix >= mu, 255, 0).astype(np.uint8)
    return bw_adaptive

def gaussian_adaptive_bw(grayscale_matrix, sigma=15, C=3):
    """
        Applies Gaussian-weighted local adaptive thresholding.
        - sigma: Controls the size of the smooth local neighborhood (higher = broader context).
        - C: A small constant subtracted from the local mean to fine-tune sensitivity.
        """
        # 1. Calculate a smooth local mean field using a Gaussian filter
        # This replaces harsh square boxes with a smooth, continuous mathematical surface.
    local_mean = gaussian_filter(grayscale_matrix.astype(np.float32), sigma=sigma)

        # 2. Threshold: Pixel is white if it's brighter than the smooth local average minus C
    bw_adaptive = np.where(grayscale_matrix >= (local_mean - C), 255, 0).astype(np.uint8)
    
    return bw_adaptive


# ==============================================================================
# EXECUTION PIPELINE
# ==============================================================================
if __name__ == "__main__":
    image_path = "input.jpg"

    print("Executing Image Processing Pipeline...")
    
    # 1. Pipeline Execution
    raw_rgb      = load_jpg_as_rgb(image_path)
    ycbcr        = rgb_to_ycbcr(raw_rgb)
    grayscale    = ycbcr_to_grayscale(ycbcr)
    
    # 2. Thresholding Algorithms
    static_bw    = grayscale_to_static_bw(grayscale, threshold=128)
    adaptive_bw  = grayscale_to_adaptive_bw(grayscale)
    gaussian_wide_reference = gaussian_adaptive_bw(grayscale, sigma=20, C=3)
    gaussian_localized_reference = gaussian_adaptive_bw(grayscale, sigma=10, C=3)

    # 3. Print Matrix Verifications
    print("\n==================================================")
    print("      MATRIX DATA STRUCTURE VERIFICATION")
    print("==================================================")
    print(f"1. Raw RGB Matrix Shape       : {raw_rgb.shape} (H, W, [R,G,B] Tuples)")
    print(f"2. YCbCr Matrix Shape         : {ycbcr.shape} (H, W, [Y,Cb,Cr] Tuples)")
    print(f"3. Grayscale Array Shape      : {grayscale.shape} (H, W) 2D Scalar Array")
    print(f"4. Static B&W Shape (128 Ref) : {static_bw.shape} (H, W) 2D Binary Array")
    print(f"5. Adaptive B&W Array Shape   : {adaptive_bw.shape} (H, W) 2D Binary Array")
    print(f"5. Adaptive Gaussian B&W Array Shape   : {gaussian_wide_reference.shape} (H, W) 2D Binary Array")
    print()
    print()
    print("==================================================\n")

    # 4. Save Outputs
    plt.imsave("output_grayscale.pdf", grayscale, cmap='gray')
    plt.imsave("fixed_reference.pdf", static_bw, cmap='gray')            # Static 128 reference
    plt.imsave("averaged_reference.pdf", adaptive_bw, cmap='gray')  # Dynamic adaptive output 
    plt.imsave("gaussian_wide_reference.pdf", gaussian_wide_reference, cmap='gray')
    plt.imsave("gaussian_localized_reference.pdf", gaussian_localized_reference, cmap='gray')



    print("[SUCCESS] Files successfully saved:")
    print("  - output_grayscale.pdf")
    print("  - output_ref.pdf (Static 128 Reference Breaker)")
    print(" - gaussian(wide & localized).pdf (Local Dynamic Scaling)")
    print("  - output_adaptive_bw.pdf (Adaptive Dynamic Threshold)")
