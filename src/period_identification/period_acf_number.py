import numpy as np
import matplotlib.pyplot as plt
from collections import defaultdict
from decimal import Decimal
from scipy.signal import find_peaks
import statistics
import Levenshtein

def encode_labels(sequence):
    """
    Map each unique label to an integer ID.
    """
    labels = [label for _, label in sequence]
    label_to_id = {label: idx for idx, label in enumerate(sorted(set(labels)))}
    encoded = [label_to_id[label] for label in labels]
    return np.array(encoded), label_to_id

def compute_autocorrelation(signal):
    """
    Compute normalized autocorrelation of a 1D integer sequence.
    """
    signal = signal - np.mean(signal)
    result = np.correlate(signal, signal, mode='full')
    result = result[result.size // 2:]  # keep non-negative lags
    result /= result[0]  # normalize
    return result


def detect_period_via_autocorrelation(sequence, max_lag=100, threshold=0.3, plot=True):
    """
    Detect period from label sequence using autocorrelation.

    Args:
        sequence: list of (timestamp, label)
        max_lag: max period length to search
        threshold: autocorrelation coefficient threshold for valid peaks
        plot: whether to plot autocorrelation result

    Returns:
        candidate_periods: list of lag values where correlation exceeds threshold
        autocorr: raw autocorrelation values
    """
    encoded, label_map = encode_labels(sequence)
    autocorr = compute_autocorrelation(encoded)

    # Detect peaks using scipy
    peaks, _ = find_peaks(autocorr[:max_lag], height=threshold)
    candidate_periods = [(lag, autocorr[lag]) for lag in peaks]

    if plot:
        plt.figure(figsize=(10, 4))
        plt.plot(autocorr[:max_lag], label='Autocorrelation')
        for lag, value in candidate_periods:
            plt.axvline(x=lag, color='r', linestyle='--', alpha=0.5)
            plt.text(lag, value + 0.02, f"{lag}", ha='center', fontsize=8)
        plt.title("Autocorrelation of Encoded Label Sequence")
        plt.xlabel("Lag")
        plt.ylabel("Correlation")
        plt.grid(True)
        plt.legend()
        plt.tight_layout()
        plt.show()

    return candidate_periods, autocorr


def normalized_levenshtein(seq1, seq2):
    # Convert input sequences to strings.
    # If input is a list, join elements with commas to form a string.
    s1 = ''.join(seq1) if isinstance(seq1, list) else str(seq1)
    s1 = s1.replace('-', '')
    s2 = ''.join(seq2) if isinstance(seq2, list) else str(seq2)
    s2 = s2.replace('-', '')

    # Compute the Levenshtein distance between the two strings
    dist = Levenshtein.distance(s1, s2)
    
    # Get the maximum length of the two strings to normalize distance
    max_len = max(len(s1), len(s2))
    
    # If both strings are empty, they are identical, similarity is 1.0
    if max_len == 0:
        return 1.0
    
    # Calculate normalized similarity score in the range [0,1]
    similarity = 1 - dist / max_len
    return similarity


def extract_periodic_segments(sequence, period, min_segments=10, similarity_threshold=0.9, similarity_ratio=0.85, time_jitter_ratio=0.1, coverage_threshold=0.8):
    """
    Extract segments that repeat with a given period, considering label similarity and 
    the stability of intervals between periodic segments.

    Args:
        sequence: List of (timestamp, label) tuples.
        period: Detected lag/period length (number of elements).
        label_threshold: Minimum required label similarity between consecutive segments.
        time_jitter_ratio: Maximum allowed relative standard deviation (std/mean) of 
                           intervals between segment start times.

    Returns:
        A list of tuples (period_start_index, repeated_labels) representing the 
        start index and label sequence of each detected periodic segment.
        Returns an empty list if the time intervals between detected segments are too unstable.
    """
    segments = []
    labels = [label for _, label in sequence]
    timestamps = [float(ts) for ts, _ in sequence]
    num_periods = len(labels) // period

    valid_starts = []
    total_length = 0
    similarity_scores = []
    
    for i in range(num_periods - 1):
        base = labels[i * period: (i + 1) * period]
        nxt = labels[(i + 1) * period: (i + 2) * period]

        if len(base) != len(nxt):
            continue

        # Calculate label similarity between consecutive segments
        # label_matches = sum(1 for a, b in zip(base, nxt) if a == b)
        # label_similarity = label_matches / len(base)
        label_similarity_score = normalized_levenshtein(base, nxt)

        if label_similarity_score < similarity_threshold*similarity_ratio: # for a single segment, unexpected fluctuation is allowed, but not for multiple segments, the average similarity should be high
            continue  # Skip if similarity below threshold
        similarity_scores.append(label_similarity_score)
        # Collect start time of this valid periodic segment
        valid_starts.append(timestamps[i * period])

        segments.append((i * period, base))
        total_length += len(base)

    # If multiple valid segments found, check the stability of the intervals between their start times
    interval_mean = 0
    interval_std = 0
    if len(valid_starts) > min_segments:
        intervals = [t2 - t1 for t1, t2 in zip(valid_starts, valid_starts[1:])]
        interval_mean = statistics.mean(intervals)
        interval_std = statistics.stdev(intervals)

        # If standard deviation of intervals is too large relative to the mean, discard all segments
        if interval_std > interval_mean * time_jitter_ratio:
            print(f"Period: {period}, Time jitter too large: {interval_std} > {interval_mean * time_jitter_ratio}")
            return [], 0, 0, 0, 0
    else:
        print(f"Period: {period}, Not enough valid segments found: {len(valid_starts)}")
        return [], 0, 0, 0, 0
    
    similaritys_mean = sum(similarity_scores) / len(similarity_scores)
    coverage_ratio = total_length / len(labels)
    # print(f"Period: {period}")
    # print(f"Sequence Size: {len(sequence)}")
    # print(f"Segments Size: {len(segments)}")
    # print(f"Coverage Ratio: {coverage_ratio}")
    if similaritys_mean < similarity_threshold:
        print(f"Period: {period}, Low Similaritys Mean: {similaritys_mean} >= {similarity_threshold}")
        return [], 0, 0, 0, 0
    elif coverage_ratio < coverage_threshold:
        print(f"Period: {period}, Low Coverage Ratio: {coverage_ratio} >= {coverage_threshold}")
        return [], 0, 0, 0, 0
    else:
        return segments, similaritys_mean, coverage_ratio, interval_mean, interval_std


# Example usage
if __name__ == '__main__':
    sequence = [
        (Decimal('0.0'), 'C-62'), (Decimal('0.1'), 'S-62'), (Decimal('0.2'), 'C-54'),
        (Decimal('0.3'), 'C-66'), (Decimal('0.4'), 'S-71'), (Decimal('0.5'), 'C-54'),
        (Decimal('0.6'), 'S-54'), (Decimal('0.7'), 'S-54'), (Decimal('0.8'), 'C-54'),
        (Decimal('0.9'), 'C-62'), (Decimal('1.0'), 'S-62'), (Decimal('1.1'), 'C-54'),
        (Decimal('1.2'), 'C-66'), (Decimal('1.3'), 'S-71'), (Decimal('1.4'), 'C-54'),
        (Decimal('1.5'), 'S-54'), (Decimal('1.6'), 'S-54'), (Decimal('1.7'), 'C-54'),
        (Decimal('1.8'), 'C-62'), (Decimal('1.9'), 'S-62'), (Decimal('2.0'), 'C-54'),
        (Decimal('2.1'), 'C-66'), (Decimal('2.2'), 'S-71'), (Decimal('2.3'), 'C-54'),
        (Decimal('2.4'), 'S-54'), (Decimal('2.5'), 'S-54'), (Decimal('2.6'), 'C-54'),
    ]

    candidate_periods, autocorr = detect_period_via_autocorrelation(sequence, max_lag=20, threshold=0.3)

    for period, score in candidate_periods:
        print(f"Candidate Period: {period}, Score: {score:.3f}")
        segments, similaritys_mean, coverage_ratio, mean_interval, std_interval = extract_periodic_segments(sequence, period)
        print(f"  Similaritys Mean: {similaritys_mean:.3f}")
        print(f"  Coverage Ratio: {coverage_ratio:.3f}")
        for idx, seg in segments:
            print(f"  Repeated Segment at {idx}: {seg}")
