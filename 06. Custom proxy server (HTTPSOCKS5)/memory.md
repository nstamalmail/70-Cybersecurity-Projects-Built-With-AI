# CPS Memory: decisions & lessons

- Auto-detection is one byte: SOCKS5 greeting starts with 0x05; everything else is
  treated as HTTP. This avoids running two listeners and matches the architecture doc.
- Critical CONNECT bug: after reading the request line, the client's remaining headers
  (Host: etc.) were still in the buffer and got tunneled to the target as payload, so
  the target parsed "Host:" as a request line (HTTP/0.9 400). Fix: drain headers until
  CRLFCRLF before opening the tunnel.
- asyncio.CancelledError during server shutdown is expected; swallow it in the handler
  wrapper so the console stays clean when the user stops the server.
- Traffic recording happens at tunnel open/close (host, port, proto, bytes up/down,
  verdict) rather than per-chunk; keeps the UI table and reports identical.
- Smoke-test targets: Python's http.server needed explicit Content-Length AND the test
  client needed a recv timeout instead of waiting for EOF (keep-alive connection), or
  the test looked like a proxy failure when it was just connection semantics.
- JSONL chosen for the traffic-log import sample because it streams one connection
  record per line - the same schema the engine records live.
