# AUKORA: a suggested repository review

AUKORA is an open-source personal-AI foundation under AGPL-3.0-or-later. This is a suggested checklist; the reviewer's request and governing instructions take precedence.

The central rule is:

The software that proposes an act should not be the authority that permits it.

1. Check rather than trust. Record the checkout's commit and tree. If you can execute code, run `./prime verify` and report exactly what passes, what fails and what it lists as UNPERFORMED. If you cannot execute, say so and review the source.
2. Read the README and `docs/AUKORA-GOLDEN-BOUNDARY.md`. Inspect the code and command behind two or three Working claims. Say whether the implementation supports each claim and its stated limit.
3. Review the known gaps. Distinguish synthetic fixtures, the recorded bounded experiment, source-only mechanisms, disabled runtime paths and proposed designs. A source-suite PASS is not a whole-product certificate.
4. Report the strongest supported claims, the most important remaining gaps and the next measurements needed before broader use. Include failures and uncertainties even when they conflict with the repository's description.

The live agent is not yet fully contained, the owner signer remains synthetic, and root and identity design need hardening. Real PostgreSQL 16 and distinct Linux users did run in one bounded synthetic-P256-approved save with independent service restarts; this does not qualify the current product. A real authenticator with user verification would not establish hardware custody or human identity.

The broader design combines replaceable models and apps with human-controlled identity, authority, memory, registered agents and networking. Those proposals should be assessed separately from the mechanisms that the commands demonstrate. Broader discussion is optional; `docs/VISION-QUESTIONS.md` offers research questions.
