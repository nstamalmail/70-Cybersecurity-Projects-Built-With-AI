# BMTVD Memory: decisions & lessons

- psutil.net_io_counters(pernic=True) is the backbone; rates are deltas between
  snapshots divided by elapsed wall time, clamped to >= 0 to survive counter resets
  (e.g. NIC resets) that would otherwise show negative bandwidth spikes.
- QtCharts (QLineSeries) renders the live and history charts; series are replaced
  wholesale on import rather than appended, which avoids stale-point bugs.
- The first snapshot has no baseline: store None rates instead of 0 so charts don't
  draw a fake spike at t0.
- History JSON schema mirrors the engine's snapshot dicts exactly (timestamp,
  total_upload_bps, total_download_bps, connection_count, interfaces, processes), so
  import/restore is the same code path as a paused live session.
- Connection counting uses psutil.net_connections which may need elevated rights for
  other processes' sockets; the engine degrades to counting only accessible sockets
  and notes the limitation in the report rather than failing.
- Keeping the monitor thread separate from the Qt thread with a snapshot queue keeps
  the UI responsive at 1s intervals even with charts redrawing.
