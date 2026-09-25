# LBSim Memory: decisions & lessons

- Smooth WRR (nginx algorithm): current_weight += weight each pick, pick max, then
  subtract total weight from the winner. Verifiably yields exact weight ratios over a
  window (10/10/20 for 1/1/2 in 40 picks) - the naive "pick by countdown" variant
  doesn't interleave as nicely.
- Race semantics: stop() captures the HealthChecker reference BEFORE nulling it so the
  final snapshot keeps the health log; the original code lost transitions when the
  reference was cleared first.
- Health state machine is fall/rise threshold based (like HAProxy), not single-probe:
  one failed probe must NOT mark DOWN, or the sim flaps. http_500 mode only fails HTTP
  checks; slow mode fails HTTP by timeout but passes TCP - shows L4 vs L7 difference.
- SimulationResult.backends stores dicts (to_dict) so report/import code handles both
  dicts and dataclasses uniformly; imported sessions are plain dicts by nature.
- Threads write events into logs guarded by small locks and bounded (del log[:-1000]);
  the GUI event feed is a bounded QPlainTextEdit (maximumBlockCount) so long runs
  can't balloon memory.
- All probes/pacing use time.monotonic and Event.wait(interval) instead of sleep so
  stop() responds instantly even mid-interval.
