# goCrack

`goCrack` is a Go Bubble Tea/Lipgloss TUI for orchestrating hashcat. It reads `~/.config/goCrack/config.json`, scans the configured `hashes`, `wordlists`, and `rules` directories, then builds previewable hashcat command queues.

On first startup, goCrack checks for configured paths. If `~/.config/goCrack/config.json` is missing or required dependencies cannot be found, it tries PATH and nearby relative directories first, then opens an interactive path picker for anything still missing. Set `GOCRACK_CONFIG` to point at a different config file. If an older app-local `config.json` is present, goCrack reads it once and saves the migrated config to `~/.config/goCrack/config.json`.

## Run

```powershell
cd path\to\goCrack
go run .
```

Or build it:

```powershell
go build -o goCrack.exe .
.\goCrack.exe
```

Install it:

```powershell
make install
```

`make install` builds `goCrack` into `~/.local/bin` by default and creates the config directory. Override the destination with `BINDIR` or `PREFIX`:

```powershell
$env:BINDIR = "$HOME\bin"
make install
```

## Flow

The first screen is the homepage. Pick one attack type there, then goCrack opens only the cards that attack needs: hash targets, wordlists, seed words, CeWL URL, options, then queue preview/run.

## Controls

- Arrow keys or mouse wheel move through lists.
- `Tab` switches panes on the target screen.
- `Space` selects or toggles the highlighted row.
- On the homepage, `Space` selects the highlighted attack type.
- `a` selects all currently filtered rows on target and wordlist cards.
- `x` clears the active selection group.
- `/` filters the active list.
- `Enter` moves forward.
- `Left` moves back.
- `p` rebuilds the queue preview.
- `r` runs the queue.
- While running, `s` asks hashcat for status, `b` bypasses/skips the current attack, `q` asks hashcat to quit cleanly, and `Esc` force-cancels the process.
- `q` quits.

## Output

The runner adds `--status --status-timer 10` when the status option is enabled. Pressing `r` opens a dedicated run page split into two panes:

- Left third: current command, `s`/`b`/`q` controls, latest status page, and cracked hashes.
- Right two thirds: raw hashcat stdout/stderr output with no suppression. Carriage returns and ANSI control bytes are normalized so hashcat cannot move the TUI cursor, and long lines wrap inside the pane instead of being truncated.

The TUI derives pane height from Bubble Tea's live window-size event and subtracts the rendered header/help rows before drawing cards, so panes are clipped to the visible terminal height instead of using fixed offsets.

During cracking, goCrack adds a per-command `--outfile` and watches it for new recoveries. Live cracks are inserted at the top of the cracked list with a green `*`; goCrack does not run `hashcat --show` before the queue starts.

## Processor Coverage

The attack catalog maps the SensePost `scripts/processors` set into Go planners:

1. Bruteforce masks
2. Light rules
3. Heavy rules
4. Seed word rules
5. Seed word hybrid
6. Hybrid masks
7. Toggle stack
8. Combinator
9. Potfile iterate
10. Prefix/suffix mining
11. Common substring mining
12. Adaptive rule generation
13. Adaptive mask generation
14. Fingerprint token expansion
15. Multiple wordlists
16. Username as password
17. Local Markov generator
18. CeWL wordlist generation
19. Digit remover
20. Rule stacker
21. Custom bruteforce
22. Buka multiple wordlists

Additional goCrack processors:

- `A` sweeps every discovered `.rule` file recursively.
- `H` sweeps every `.rule` file under `rules/hybrid`.

That means the original named SensePost bundles are preserved, while rule files outside those bundles are still reachable from the TUI.

## Large File Handling

The scanner records file metadata without reading wordlists into memory. When multiple hash files are selected for the same mode, goCrack creates a streamed combined hash target under a per-process OS temp directory, using buffered copy rather than holding the input in RAM. On Windows this is typically `%TEMP%\goCrack-<id>\hashes`.

Potfile-derived processors stream the potfile and cap derived candidate files so they remain usable on large pots. Generated working files are written under that per-process OS temp directory instead of the hashcat tree; per-command live-crack files and combined hash targets are removed after the queue exits, and the whole temp directory is removed when goCrack exits normally.
