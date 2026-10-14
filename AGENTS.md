# OddFox instructions for Codex

Before working in this repository, read and follow:

- `CLAUDE.md` in this repository.
- `~/OddFox/oddfox-workspace/README.md` for the shared multi-Mac rules.

These are the same rules Claude uses and apply to Codex too. Keep project rules in
`CLAUDE.md` so both assistants use the same source. Re-read instructions after a
pull if they changed.

## Editing workflow

- Work only in `~/OddFox`; old iCloud copies are archives.
- Check `git status` and pull before editing. Follow the repository's specific
  pull instructions; otherwise use `git pull --ff-only`.
- Preserve unrelated local or staged changes and exclude them from your commits.
- Run the checks appropriate to the change and any checks required by `CLAUDE.md`.
- After each completed, verified change, commit the task's files and push to the
  repository's current branch automatically, without waiting for a reminder.
- For deployed website changes, download and compare the live file before patching,
  merge any differences, and follow `CLAUDE.md` for deployment targets, exceptions,
  permissions and verification. Instruction-only changes stay in Git.
- Never commit passwords, keys, tokens, private settings or runtime/event data.
- When a task touches another OddFox repository, read its `AGENTS.md` and
  `CLAUDE.md` before editing it and sync that repository too.
- If a pull, check, push or deployment fails, resolve it where possible and report
  anything unfinished; do not claim the projects are synced or deployed.
