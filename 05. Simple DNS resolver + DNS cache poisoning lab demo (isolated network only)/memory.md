# DRCP Memory: decisions & lessons

- The attack is deterministic thanks to `race_hold_ms`: the resolver holds the upstream
  reply for ~120ms to model WAN latency, giving the attacker a real race window instead
  of relying on GIL timing luck.
- Correct race semantics: the FIRST response that passes validation consumes the pending
  slot (`ctx["resolved"]`); late replies (even legit ones) are discarded. The verdict is
  snapshotted at poisoning time because the cache legitimately self-heals afterwards.
- dnslib normalization: `str(q.qname)` keeps a trailing dot ("bank.test.lab."); zone and
  cache lookups must strip it or every lookup silently misses.
- Outbound queries must be rebuilt with the resolver's OWN txn id (never forward the
  client packet verbatim) or upstream replies can't be matched to pending slots.
- The fake authoritative "signs" responses (LABSIG marker); DNSSEC-mode validation
  checks the marker AND the real upstream source port, so forgery fails cleanly.
- AttackEngine success = cache actually poisoned (verified state), not "guess matched",
  because validation can still reject a correctly-guessed packet.
- Windows UDP: set SIO_UDP_CONNRESET (0x9800000C) off on all lab sockets and swallow
  errors on sendto/recvfrom; trigger sockets are created fresh per query and closed
  immediately to avoid ConnectionResetError noise on loopback.
