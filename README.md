# Upstream PRs: ready to open

Round 2 (2026-10-04), after Hamish's review of 164 and 165: see
pr-texts.md for what to click and paste.  14 branches, rebased on
upstream main 6d837f2, each verified alone, all merging together without
conflict.  New test programs GPL-3.0-only (as upstream's), test_qemu.sh
GPL-2.0-only.

Lessons from the review: one topic per PR; keep the project's conventions
(a .gitignore per directory, comments as in the sibling Makefile, no
wildcards where explicit names work); his scripts' behaviour is his call.
