from pathlib import Path
from util.packet_length_extractor import read_sequence_from_csv
from period_identification.period_acf_number import detect_period_via_autocorrelation, extract_periodic_segments

def identify_period_from_csv(csv_file):
    if Path(csv_file).exists():
        print("Extracting directed length sequence...")
        _, dir_len_sequence = read_sequence_from_csv(csv_file, "dir_len")
        candidate_periods, autocorr = detect_period_via_autocorrelation(dir_len_sequence, max_lag=50, threshold=0.3)

        best_period = None
        best_segments = None
        best_coverage = 0
        best_similaritys_mean = 0
        best_interval_mean = 0
        best_interval_std = float('inf')
        best_interval_std_mean = float('inf')
        for period, score in candidate_periods:
            # print(f"Candidate Period: {period}, Score: {score:.3f}")
            segments, similaritys_mean, coverage_ratio, interval_mean, interval_std = extract_periodic_segments(dir_len_sequence, period, min_segments=10, similarity_threshold=0.9, similarity_ratio=0.8, time_jitter_ratio=0.5, coverage_threshold=0.8)
            if segments:
                interval_std_mean = interval_std / interval_mean if interval_mean > 0 else 0
                print("-"*30)
                print(f"Current Period: {period}")
                print(f"Current Segments Size: {len(segments)}")
                print(f"Current Coverage Ratio: {coverage_ratio}")
                print(f"Current Similaritys Mean: {similaritys_mean}")
                print(f"Current Mean Interval: {interval_mean}")
                print(f"Current Std Interval: {interval_std}")
                print(f"Current Std/Mean: {interval_std_mean}")
                print("")
                if coverage_ratio > best_coverage*0.9 and similaritys_mean > best_similaritys_mean*0.9 and interval_std_mean < best_interval_std_mean:
                    print("*"*30)
                    print(f"New Best Period: {period}")
                    best_segments = segments
                    best_coverage = coverage_ratio
                    best_similaritys_mean = similaritys_mean
                    best_period = period
                    best_interval_mean = interval_mean
                    best_interval_std = interval_std
                    best_interval_std_mean = interval_std_mean
                # for idx, seg in segments:
                    # print(f"  Repeated Segment at {idx}: {seg}")

        if best_segments:
            print(">"*30)
            print(f"Best Period: {best_period}")
            print(f"Best Segments Size: {len(best_segments)}")
            print(f"Best Coverage Ratio: {best_coverage:.5f}")
            print(f"Best Similaritys Mean: {best_similaritys_mean:.5f}")
            print(f"Best Mean Interval: {best_interval_mean}")
            print(f"Best Std Interval: {best_interval_std}")
            print(f"Best Std/Mean: {best_interval_std_mean}")
            # print(f"Best Segments:")
            # for idx, seg in best_segments:
            #     print(f"  Repeated Segment at {idx}: {seg}")
            # for idx, seg in best_segments:
                # print(f"  Repeated Segment at {idx}: {seg}")
        else:
            print("No segments found") 
            
            

if __name__ == "__main__":
    # csv_file = "dataset/scada/Modbus_polling_only_6RTU(106)_length_control_sequence.csv" 
    csv_file = "dataset/swat/network/Dec2019_00000_20191206100500_00000w_filtered(192.168.1.10-192.168.1.200)_test_kept_app_length_control_sequence.csv"
    # csv_file = "dataset/swat/network/Dec2019_00000_20191206100500_00000w_filtered(192.168.1.10-192.168.1.200)_test_kept_app_length_control_sequence.csv"
    identify_period_from_csv(csv_file)