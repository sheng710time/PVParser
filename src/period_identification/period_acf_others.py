import matplotlib.pyplot as plt
from difflib import SequenceMatcher
import Levenshtein


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


def strict_match_ratio(a, b):
    if len(a) != len(b):
        return 0
    matches = sum(1 for x, y in zip(a, b) if x == y)
    return matches / len(a)


def symbolic_autocorrelation(labels, min_lag=1, max_lag=30):
    """
    Compute symbolic autocorrelation by comparing the sequence with its lagged version,
    using SequenceMatcher.ratio() as the similarity metric.
    
    Args:
        labels: list of string labels, e.g. ['C-108', 'S-60', ...]
        min_lag: minimum lag (offset) to consider
        max_lag: maximum lag (offset) to consider
    
    Returns:
        List of tuples (lag, similarity_score)
    """
    results = []
    N = len(labels)
    for lag in range(min_lag, min(max_lag + 1, N)):
        seq1 = labels[:N - lag]
        seq2 = labels[lag:]
        # similarity = SequenceMatcher(None, seq1, seq2).ratio()
        similarity = strict_match_ratio(seq1, seq2)
        # similarity = normalized_levenshtein(seq1, seq2)
        results.append((lag, similarity))
    return results


def plot_autocorrelation(acf_results):
    """
    Plot symbolic autocorrelation results.
    
    Args:
        acf_results: list of tuples (lag, similarity_score)
    """
    lags, scores = zip(*acf_results)
    plt.figure(figsize=(10, 5))
    plt.stem(lags, scores)
    plt.xlabel('Lag')
    plt.ylabel('Similarity (SequenceMatcher.ratio)')
    plt.title('Symbolic Autocorrelation (Simulated AFC)')
    plt.grid(True)
    plt.show()

# Example usage:
if __name__ == "__main__":
    labels = ['C-108', 'S-60', 'S-179', 'C-60', 'C-108', 'S-60', 'S-179', 'C-60', 'C-108', 'S-60', 'S-106']
    acf_results = symbolic_autocorrelation(labels, min_lag=1, max_lag=10)
    print("Lag and similarity:")
    for lag, sim in acf_results:
        print(f"Lag={lag}, Similarity={sim:.3f}")
    plot_autocorrelation(acf_results)
