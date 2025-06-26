import statistics
from difflib import SequenceMatcher


def similar_ratio(a, b):
    """Calculate similarity ratio between two sequences."""
    return SequenceMatcher(None, a, b).ratio()


def calculate_matched_len_threshold(size):  # TODO impact of matched_len_threshold
    """Calculate the minimum length of a matched subsequence."""
    matched_len_threshold = size
    if size <= 3:
        matched_len_threshold = size
    elif 3 < size <= 6:  # allow 1 miss, more robust to network interference
        matched_len_threshold = size
        # matched_len_threshold = size - 1
    else:
        matched_len_threshold = size
        # matched_len_threshold = int(size * 0.8)
    return matched_len_threshold


def match_pattern_from(base_labels, sequence, start_idx, max_len, sim_thresh):
    """
    Try to match a prefix of base_labels starting from sequence[start_idx].
    Allows matching shorter subsequences than base_labels.
    
    Returns:
        best_match: the best matching subsequence labels
        best_len: length of that subsequence
    """
    best_match = None
    best_score = 0
    best_len = 0
    matched_len_threshold = calculate_matched_len_threshold(max_len)

    # Try from longest to shortest subsequence
    for L in range(max_len, matched_len_threshold-1, -1):
        if start_idx + L > len(sequence):
            continue
        candidate_labels = [label for _, label in sequence[start_idx:start_idx+L]]
        score = similar_ratio(base_labels[:L], candidate_labels)
        if score >= sim_thresh and score > best_score:
            best_match = candidate_labels
            best_len = L
            best_score = score

    return best_match, best_len


def compute_start_index_intervals(covered_groups):
    # Step 1: Get the minimum index (starting index) for each group
    starts = [min(group) for group in covered_groups]

    # Step 2: Calculate the difference between consecutive starting indices
    intervals = [s2 - s1 for s1, s2 in zip(starts, starts[1:])]

    return starts, intervals


def detect_strict_periodic_pattern(sequence, min_len=3, max_len=10, sim_thresh=0.85,
                                   jitter_ratio=0.1, min_coverage_ratio=0.3):
    """
    Detect strict periodic patterns in a timestamped sequence.

    Args:
        sequence: List of tuples (timestamp, label).
        min_len: Minimum length of candidate pattern.
        max_len: Maximum length of candidate pattern.
        sim_thresh: Similarity threshold for matching subsequences.
        jitter_ratio: Maximum allowed standard deviation for interval durations (1σ).
        min_coverage_ratio: Minimum required coverage ratio of matched elements.

    Returns:
        best_pattern: The labels of the detected pattern.
        match_times: List of timestamps where the pattern starts.
        avg_period: Average period between pattern occurrences.
        covered_indices: Set of indices covered by the detected pattern occurrences.
    """
    best_pattern = None
    best_match_times = []
    best_avg_period = None
    best_std_dev = None
    best_coverage = 0
    best_covered_indices = set()

    # Initially, use all indices in the first half as candidates
    half_len = len(sequence) // 2
    start_candidates = set(range(half_len))

    for size in range(min_len, max_len + 1):
        new_candidates = set()  # to collect valid pattern start indices for next size

        for i in sorted(start_candidates):
            if i + size > len(sequence):
                continue  # avoid out-of-bounds

            base_window = sequence[i:i + size]
            base_labels = [label for _, label in base_window]
            base_start_time = sequence[i][0]

            # Initialize matches with the base window
            match_times = [base_start_time]
            covered_indices = [set(range(i, i + size))]

            j = i + size  # Start searching for matching subsequences after base
            while j < len(sequence) - size + 1:
                _ , matched_len = match_pattern_from(base_labels, sequence, j, size, sim_thresh)

                if matched_len > 0:
                    match_times.append(sequence[j][0])
                    covered_indices.append(set(range(j, j + matched_len)))
                    j += matched_len
                else:
                    j += 1

            # Require at least 3 occurrences for a valid pattern
            if len(match_times) >= 3:
                all_firsts = [min(ci) for ci in covered_indices if min(ci) < half_len]  # use min to get actual index from set
                new_candidates.add(min(all_firsts))  # add all to the candidate set

                intervals = [t2 - t1 for t1, t2 in zip(match_times, match_times[1:])]
                std_dev = statistics.stdev(intervals) if len(intervals) > 1 else 0
                avg_period = statistics.mean(intervals)

                if std_dev <= jitter_ratio * avg_period:
                    all_covered = set().union(*covered_indices)
                    coverage_ratio = len(all_covered) / len(sequence)

                    if coverage_ratio >= min_coverage_ratio and coverage_ratio > best_coverage:
                        best_pattern = base_labels
                        best_match_times = match_times
                        best_avg_period = avg_period
                        best_std_dev = std_dev
                        best_coverage = coverage_ratio
                        best_covered_indices = covered_indices
                        starts, index_intervals = compute_start_index_intervals(covered_indices)

                        print('--------------------------------')
                        print('pattern: ', best_pattern)
                        print('match_times: ', best_match_times)
                        print('avg_period: ', best_avg_period)
                        print('best_std_dev: ', best_std_dev)
                        print('best_coverage: ', best_coverage)
                        print('covered_indices: ', best_covered_indices)
                        print('starts: ', starts)
                        print('intervals: ', index_intervals)
                        print("")

        # Update candidates for the next longer size
        if new_candidates:
            # Expand each candidate ±3 positions, and make sure the index stays within bounds
            expanded_candidates = set()
            for idx in new_candidates:
                for offset in range(-3, 4):  # includes -3 to +3
                    new_idx = idx + offset
                    if 0 <= new_idx < len(sequence):
                        expanded_candidates.add(new_idx)

            # Update start_candidates for the next round
            start_candidates = expanded_candidates
        else:
            # If no matches found at current length, next longer length is unlikely
            break

    return best_pattern, best_match_times, best_avg_period, best_std_dev, best_coverage, best_covered_indices

