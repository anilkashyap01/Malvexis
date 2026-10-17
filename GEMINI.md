# GEMINI.md - Antigravity-specific notes for Malvexis

Read `AGENTS.md` first and follow it fully. It holds the project's hard safety rules, architecture, commands, and definition of done. This file only adds Antigravity-specific behavior and never overrides or relaxes anything in `AGENTS.md`.

## Working style in Antigravity

- For any change that touches more than one file, write a short plan first (files to change, tests to add) and wait for approval before editing.
- Work on one `docs/ROADMAP.md` task at a time. Do not start the next task in the same run.
- Run `pytest` in the terminal after every change and include the result in your summary. Do not mark a task done on a failing or unrun test suite.
- Keep the terminal and browser away from real malware: do not download samples, do not open sample-hosting sites, and do not run anything inside `samples/`. If a task seems to need real samples, stop and ask the owner to run it inside an isolated VM.
- When the browser tool is useful (checking VirusTotal, MalwareBazaar, YARA, or `pefile` docs), read documentation only. Never paste API keys into a browser or a prompt.
- Finish each task with: what changed, what you verified, what you could not verify, and any scoring weights you touched.
