# TUI notes

Read this doc before changing paths under `internal/tui/**`.

For security invariants S1--S20 see [AGENTS.md](../../AGENTS.md).

---

## General (TUI-1)

- Module paths: `charm.land/bubbletea/v2`, `charm.land/lipgloss/v2`, `charm.land/bubbles/v2` (overview in AGENTS.md Quick facts).
- Non-TUI commands no longer send terminal query sequences. v1's init sent OSC 11 and CSI 6n; under sudo the responses became garbage.

## Refresh timeouts (TUI-2)

- Every IPC call during a TUI refresh uses a 10-second timeout (`shared.Within`). If the daemon is frozen, the status line shows an error after at most ~12 s; the next tick refreshes normally.
- Action calls (`certfoldc`: `f`/`R`; `certfolds` TUI: `R`/`d`/`n`) do not use the 10-second timeout. They are bounded only by the IPC client's 5-minute overall timeout.

## Key names (TUI-3)

- The space key is named `"space"`.

## lipgloss v2 (TUI-4)

- `Width` includes the border.
- bubbles tables require an explicit width.
- lipgloss v2 emits SGR even when not connected to a terminal. Tests must read the view through `ansi.Strip`.

## Wide glyphs (TUI-5)

- Only characters allowed by `shared.WideGlyph` may appear in TUI chrome: `─ │ ╭ ╮ ╰ ╯ • ›`. See [PLT-4 in platforms.md](platforms.md) for the conhost problem these guard against.

## Smoke-testing under %TEMP% (TUI-6)

- Before starting `certfolds` in a temp directory for a smoke test, tighten the config directory permissions as the startup directory check directs.

## bubbletea v2 terminal probes (TUI-7)

- bubbletea v2 sends `ESC[?u` (kitty keyboard protocol query, cannot be disabled individually) on the first render. Terminals that support the protocol may leave the response on the prompt if `q` is pressed immediately after launch. `DECRQM 2026/2027` is also sent when `SSH_TTY` is unset.
