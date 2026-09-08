"""Metadata only. Bounded prefix sampling is disclosed, never payload inspection."""
import numpy as np

FEATURES = ["packet_count", "byte_count", "mean_size", "std_size", "min_size", "max_size",
            "small_ratio", "large_ratio", "packets_per_second", "bytes_per_second",
            "mean_iat", "std_iat", "burstiness", "duration", "size_bin_0", "size_bin_1",
            "size_bin_2", "size_bin_3", "iat_bin_0", "iat_bin_1", "iat_bin_2", "iat_bin_3"]


def extract(samples: list[tuple[float, int]]) -> dict[str, float]:
    if not samples:
        return dict.fromkeys(FEATURES, 0.0)
    sizes = np.array([x[1] for x in samples], dtype=float)
    times = np.sort(np.array([x[0] for x in samples], dtype=float))
    iat = np.diff(times) if len(times) > 1 else np.array([0.0])
    duration = float(times[-1] - times[0])
    mean, std = float(iat.mean()), float(iat.std())
    sh = np.histogram(sizes, bins=[0, 200, 600, 1200, np.inf])[0] / len(sizes)
    ih = np.histogram(iat, bins=[0, .005, .05, .5, np.inf])[0] / len(iat)
    values = [len(sizes), sizes.sum(), sizes.mean(), sizes.std(), sizes.min(), sizes.max(),
              (sizes < 200).mean(), (sizes >= 1200).mean(),
              len(sizes) / duration if duration else 0, sizes.sum() / duration if duration else 0,
              mean, std, (std - mean) / (std + mean) if std + mean else 0, duration, *sh, *ih]
    return {k: float(v) for k, v in zip(FEATURES, values, strict=True)}


def bidirectional_features(forward: list[tuple[float, int]], reverse: list[tuple[float, int]]) -> dict[str, float]:
    """Endpoint-pair aggregation, not proof that opposite SPIs are paired Child SAs."""
    total = len(forward) + len(reverse)
    return {**extract(forward + reverse), "direction_ratio": len(forward) / total if total else 0,
            "request_response_asymmetry": abs(len(forward) - len(reverse)) / total if total else 0}
