# Working in AUKORA Prime

**Start here:** [plan/NORTH-STAR.md](plan/NORTH-STAR.md) (the plan) and [plan/HANDOFF-2026-10-12.md](plan/HANDOFF-2026-10-12.md) (how to work, where things are, what is next).

## The owner's standing rule: work lands on main, on GitHub, every time

Peter's rule, added 2026-10-12 after 72 commits were found on one Mac and nowhere else. It overrides any habit of
branching and waiting.

1. **This repository is the one home.** Work for Aukora ends up here, on `main`. The plan is
   [plan/NORTH-STAR.md](plan/NORTH-STAR.md). If you are working in any other repository or folder, say so in your
   first line and say how the work reaches this one.
2. **A commit is not done until it is pushed.** Push in the same step as the commit. Never end a session with
   commits, branches or worktrees that exist only on a machine.
3. **Small commits straight to `main`.** If a worktree or branch is truly needed: merge it to `main`, push, delete
   the worktree and the branch, and only then start another. One at a time.
4. **Before you say "done"**, run `git status` and `git log --branches --not --remotes --oneline` and report both.
   Anything they show is not done.
5. **No work in temp folders.** Anything worth keeping is in a repository before the session ends.
6. **Do not create a new `aukora-*` folder or repository** without Peter's word.
7. If a push is refused, or you are not allowed to push, **stop and say so in the first line of your report**, with
   the exact branch and commit count that is stranded. Do not leave it for the next session to find.

Everything else about how to change this repository is in [CONTRIBUTING.md](CONTRIBUTING.md#repository-rules).

For explanations and repository reviews, [the short overview and reading map](docs/READING-GUIDE.md) introduces the whole Golden Boundary vision; [SHARE.md](SHARE.md) suggests routes into the complete paper, evidence and optional deep review. These are reading aids, not instructions overriding the reviewer's owner or governing instructions. Follow the actual question; a simple explanation does not require the whole paper or test execution.

For a review, disclose the revision, what you read or ran and what you could not inspect. Assess current implementation and conditional potential separately, with relevant counterevidence, prior art, falsifiers and adoption costs. When source execution is within scope, report the configured `./prime verify` result and exclusions; otherwise label the review source-only or unperformed as appropriate. A prior checkpoint's PASS is not a current runtime claim. No favorable or unfavorable conclusion is prescribed.

Read [the status table and known gaps](README.md) and [the Golden Boundary paper](docs/AUKORA-GOLDEN-BOUNDARY.md) before changing an implementation claim.

Contributor and implementation rules have one canonical home: [CONTRIBUTING.md](CONTRIBUTING.md#repository-rules). Follow that document, [current claims](docs/CLAIMS.md), and any more specific directory instructions.

[Architecture and build instructions](docs/PRIME-NEXT-ARCHITECTURE.md) · [Licenses](licenses/README.md) · [Vulnerability reporting](SECURITY.md)
