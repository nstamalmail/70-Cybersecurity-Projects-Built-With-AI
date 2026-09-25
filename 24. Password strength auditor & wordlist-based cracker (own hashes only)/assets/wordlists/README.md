# Builtin wordlists — policy

Everything in this directory is **synthetic / educational** and hand-written for
demos and self-tests. HashArmor deliberately does **not** bundle real breach
corpora (rockyou, crackstation, HaveIBeenPwned dumps, …):

1. Distributing breach data is legally risky in most jurisdictions.
2. Real wordlists are the adversary's ammunition; an auditor tool should not
   ship them by default.

For a real audit, point HashArmor at your own wordlist files via the GUI
(Crack tab → Wordlist → Browse). Files are plain text, one candidate per line.
