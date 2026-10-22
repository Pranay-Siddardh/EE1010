import numpy as np
import matplotlib.pyplot as plt

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

def rgb_to_ycbcr(rgb_matrix):
    """
    Converts raw RGB pixel tuples into YCbCr space using ITU-R BT.601 formulas.
    """
    R = rgb_matrix[:, :, 0]
    G = rgb_matrix[:, :, 1]
    B = rgb_matrix[:, :, 2]

    Y  = 0.299 * R + 0.587 * G + 0.114 * B
    Cb = 128 - 0.168736 * R - 0.331264 * G + 0.5 * B
    Cr = 128 + 0.5 * R - 0.418688 * G - 0.081312 * B

    return np.dstack((Y, Cb, Cr))

def ycbcr_to_grayscale(ycbcr_matrix):
    """
    Drops Cb and Cr channels completely, returning a 2D scalar array of Y values.
    """
    grayscale_matrix = ycbcr_matrix[:, :, 0]
    return np.clip(grayscale_matrix, 0, 255).astype(np.uint8)

def grayscale_to_adaptive_bw(grayscale_matrix):
    """
    Calculates the MEAN INTENSITY (mu) of the image and thresholds dynamically.
    """
    mu = np.mean(grayscale_matrix)
    print(f"[INFO] Image Dynamic Threshold Mean (μ): {mu:.2f}")

    bw_adaptive = np.where(grayscale_matrix >= mu, 255, 0).astype(np.uint8)
    return bw_adaptive

if __name__ == "__main__":
    image_path = "input.jpg"

    print("Executing Adaptive Dynamic Thresholding Pipeline...")
    
    raw_rgb   = load_jpg_as_rgb(image_path)
    ycbcr     = rgb_to_ycbcr(raw_rgb)
    grayscale = ycbcr_to_grayscale(ycbcr)
    
    adaptive_bw = grayscale_to_adaptive_bw(grayscale)

    print(f"1. Raw RGB Matrix Shape     : {raw_rgb.shape}")
    print(f"2. Grayscale Array Shape    : {grayscale.shape}")
    print(f"3. Adaptive B&W Shape (Mean): {adaptive_bw.shape}")

    plt.imsave("dynamic.jpg", adaptive_bw, cmap='gray')
    print("[SUCCESS] Saved dynamic.jpg")
