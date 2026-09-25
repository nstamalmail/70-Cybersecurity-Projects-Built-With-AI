"""Sequence mining: n-gram extraction, n-gram clustering and Markov modelling.

The visualiser is only useful if it tells the analyst *what comes after what*,
so three complementary views are derived from the same call list:

* **n-grams** - the frequent ordered tuples of APIs (``CreateFileW ->
  WriteFile -> CloseHandle``) ranked by a score that rewards frequency and
  length, which is how behaviour motifs like "drop and execute" surface.
* **n-gram clustering** - greedy growing of maximal frequent sequences, so a
  12-step motif is reported once instead of twelve overlapping 3-grams.
* **Markov model** - a first-order transition matrix over API names, giving
  transitions per process and the highest-probability paths used to draw the
  behaviour graph.
"""
from __future__ import annotations

from collections import Counter, defaultdict

from app.core.model import ApiCall, CallSequence, NGramHit, Transition


# --------------------------------------------------------------------------- #
#  N-grams
# --------------------------------------------------------------------------- #
def ngrams(items: list, n: int) -> list[tuple]:
    if n <= 0 or len(items) < n:
        return []
    return [tuple(items[index:index + n]) for index in range(len(items) - n + 1)]


def extract_ngrams(
    calls: list[ApiCall],
    *,
    sizes=(2, 3, 4, 5),
    min_occurrences: int = 2,
    top: int = 60,
    per_process: bool = False,
) -> list[NGramHit]:
    """Rank ordered API tuples by ``occurrences * length``."""
    groups: dict[int, list[str]] = defaultdict(list)
    for call in calls:
        groups[call.process_id if per_process else 0].append(call.api)

    counter: Counter = Counter()
    for sequence in groups.values():
        for size in sizes:
            for gram in ngrams(sequence, size):
                counter[gram] += 1

    hits: list[NGramHit] = []
    for gram, count in counter.items():
        if count < min_occurrences:
            continue
        hits.append(
            NGramHit(
                sequence=list(gram),
                occurrences=count,
                length=len(gram),
                score=float(len(gram) * count),
            )
        )
    hits.sort(key=lambda hit: (hit.score, hit.length, hit.occurrences), reverse=True)

    if per_process and hits:
        # annotate with which process (first match) contributed most
        for hit in hits:
            hit.process_id = _best_process(hit.sequence, groups)
    return hits[:top]


def _best_process(sequence: list[str], groups: dict[int, list[str]]) -> int | None:
    best: tuple[int, int] | None = None
    for pid, calls in groups.items():
        count = 0
        size = len(sequence)
        for index in range(len(calls) - size + 1):
            if calls[index:index + size] == sequence:
                count += 1
        if count and (best is None or count > best[1]):
            best = (pid, count)
    return best[0] if best else None


def _contains(haystack: list[str], needle: list[str]) -> bool:
    size = len(needle)
    if size == 0 or size > len(haystack):
        return False
    return any(haystack[index:index + size] == needle for index in range(len(haystack) - size + 1))


def cluster_ngrams(
    calls: list[ApiCall],
    *,
    min_support: int = 2,
    max_len: int = 14,
    top: int = 25,
    seed_size: int = 3,
) -> list[CallSequence]:
    """Greedily grow frequent n-grams into maximal recurring sequences.

    All occurrences of every seed n-gram are indexed in one pass, which makes
    each extension step proportional to the number of surviving occurrences
    rather than a re-scan of the whole call list.
    """
    by_process: dict[int, list[str]] = defaultdict(list)
    for call in calls:
        by_process[call.process_id].append(call.api)
    sequences = list(by_process.values())
    if not sequences:
        return []

    index: dict[tuple, list[tuple[int, int]]] = defaultdict(list)
    for sequence_index, sequence in enumerate(sequences):
        for position in range(max(0, len(sequence) - seed_size + 1)):
            index[tuple(sequence[position:position + seed_size])].append((sequence_index, position))

    clusters: list[CallSequence] = []
    for seed, occurrences in sorted(index.items(), key=lambda item: -len(item[1]))[: top * 8]:
        if len(occurrences) < min_support:
            continue
        if any(_contains(cluster.sequence, list(seed)) for cluster in clusters):
            continue
        current = list(seed)
        live = list(occurrences)
        while len(current) < max_len:
            candidates: Counter = Counter()
            for sequence_index, position in live:
                follow = position + len(current)
                sequence = sequences[sequence_index]
                if follow < len(sequence):
                    candidates[sequence[follow]] += 1
            if not candidates:
                break
            tail, count = candidates.most_common(1)[0]
            if count < min_support:
                break
            current.append(tail)
            live = [
                (sequence_index, position)
                for sequence_index, position in live
                if position + len(current) - 1 < len(sequences[sequence_index])
                and sequences[sequence_index][position + len(current) - 1] == tail
            ]
            if not live:
                break
        clusters.append(
            CallSequence(
                sequence=current,
                support=len(occurrences),
                length=len(current),
                score=float(len(current) * len(occurrences)),
            )
        )

    # Drop clusters that are fully contained in a longer cluster.
    maximal = [
        cluster
        for cluster in clusters
        if not any(
            other is not cluster and len(other.sequence) > len(cluster.sequence) and _contains(other.sequence, cluster.sequence)
            for other in clusters
        )
    ]
    maximal.sort(key=lambda item: (item.score, item.length), reverse=True)
    return maximal[:top]


def cover_sequences(calls: list[ApiCall], clusters: list[CallSequence], top: int = 200) -> list[CallSequence]:
    """Return the concrete call instances that instantiate each cluster."""
    instances: list[CallSequence] = []
    apis = [call.api for call in calls]
    for cluster in clusters:
        size = len(cluster.sequence)
        for index in range(len(apis) - size + 1):
            if apis[index:index + size] == cluster.sequence:
                window = calls[index:index + size]
                instances.append(
                    CallSequence(
                        sequence=list(cluster.sequence),
                        support=cluster.support,
                        length=size,
                        start_time=window[0].timestamp,
                        end_time=window[-1].timestamp,
                        process_id=window[0].process_id,
                        process_name=window[0].process_name,
                        call_ids=[call.call_id for call in window],
                        score=cluster.score,
                    )
                )
                if len(instances) >= top:
                    return instances
    return instances


# --------------------------------------------------------------------------- #
#  Markov transitions
# --------------------------------------------------------------------------- #
def build_markov(calls: list[ApiCall], *, per_process: bool = False, top: int = 400) -> list[Transition]:
    """First-order API transition matrix (global by default, per process on request)."""
    by_process: dict[int, list[ApiCall]] = defaultdict(list)
    for call in calls:
        by_process[call.process_id].append(call)

    pairs: Counter = Counter()
    totals: Counter = Counter()
    for pid, sequence in by_process.items():
        key_pid = pid if per_process else 0
        for previous, current in zip(sequence, sequence[1:]):
            pairs[(key_pid, previous.api, current.api)] += 1
            totals[(key_pid, previous.api)] += 1

    transitions: list[Transition] = []
    for (pid, source, target), count in pairs.items():
        total = totals.get((pid, source), 0)
        transitions.append(
            Transition(
                source=source,
                target=target or "",
                count=count,
                probability=(count / total) if total else 0.0,
                process_id=(pid or None) if per_process else None,
            )
        )
    transitions.sort(key=lambda item: (item.count, item.probability), reverse=True)
    return transitions[:top]


def highest_probability_paths(transitions: list[Transition], *, top: int = 12, max_len: int = 8) -> list[list[str]]:
    """Greedy walk of the strongest transitions to suggest behaviour paths."""
    ranked: dict[str, list[Transition]] = defaultdict(list)
    totals: Counter = Counter()
    for transition in transitions:
        ranked[transition.source].append(transition)
        totals[transition.source] += transition.count
    for outgoing in ranked.values():
        outgoing.sort(key=lambda item: (-item.probability, -item.count))

    paths: list[list[str]] = []
    for start in sorted(ranked, key=lambda name: -totals[name])[: top * 4]:
        path = [start]
        while len(path) < max_len:
            candidates = [item.target for item in ranked.get(path[-1], []) if item.target and item.target not in path]
            if not candidates:
                break
            path.append(candidates[0])
        if len(path) >= 3 and path not in paths:
            paths.append(path)
        if len(paths) >= top:
            break
    return paths[:top]


# --------------------------------------------------------------------------- #
#  Sequence-level statistics
# --------------------------------------------------------------------------- #
def sequence_stats(calls: list[ApiCall], processes: list) -> dict:
    if not calls:
        return {}
    total_weight = sum(call.weight for call in calls)
    duration = max(call.timestamp for call in calls) or 0.0
    failed = sum(call.weight for call in calls if call.failed)
    unique = Counter(call.api for call in calls)
    return {
        "total_calls": len(calls),
        "weighted_calls": total_weight,
        "unique_apis": len(unique),
        "processes": len(processes),
        "duration_seconds": round(duration, 2),
        "failed_calls": failed,
        "failure_ratio": round(failed / total_weight, 4) if total_weight else 0.0,
        "calls_per_second": round(total_weight / duration, 3) if duration > 0 else 0.0,
        "top_apis": unique.most_common(15),
        "repeat_collapsed": sum(1 for call in calls if call.repeated > 1),
    }


def burst_detection(calls: list[ApiCall], *, window: float = 1.0, threshold: int = 40) -> list[dict]:
    """Find windows where the call rate spikes (install/persistence/ransom bursts)."""
    if not calls:
        return []
    buckets: Counter = Counter()
    for call in calls:
        buckets[int(call.timestamp // window)] += call.weight
    bursts: list[dict] = []
    for bucket, count in sorted(buckets.items()):
        if count >= threshold:
            bursts.append(
                {
                    "start": round(bucket * window, 2),
                    "end": round((bucket + 1) * window, 2),
                    "calls": count,
                    "rate": round(count / window, 1),
                }
            )
    bursts.sort(key=lambda item: item["calls"], reverse=True)
    return bursts[:20]
