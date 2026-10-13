# Plans and decisions

This directory contains the current plan, scoped proposals and architecture decisions:

- [NORTH-STAR.md](NORTH-STAR.md) is the plan the owner steers by and carries the latest dated status.
- [BROWSER-NODE.md](BROWSER-NODE.md) is the current browser-node build and acceptance plan.
- [REVIEW-BROWSER-NODE.md](REVIEW-BROWSER-NODE.md) records the browser-node review, the pre-binding restriction, its independent second-family review and the remaining open findings.
- [VOICE-LIVE.md](VOICE-LIVE.md) describes the current live-voice path, prerequisites and gaps.
- [CLEANUP.md](CLEANUP.md) is the October 13 repository-cleanup inventory and decision record.
- [CHECK-2026-10-13.md](CHECK-2026-10-13.md) is the October 13 source-check record and its limits.

The [archive](archive/README.md) preserves superseded plans without presenting them as current work. Plans and check records do not establish current source or runtime behavior; verify current claims and executable checks before relying on them.

## Working method

Changes to the browser release are proven first on a rehearsal node with a stand-in approval and inspected in a real browser before the owner is asked. Commits are checked on Linux before push. A second model family reviews security-relevant changes read-only. Tests that need the fetched harness report UNPERFORMED when it is absent.
