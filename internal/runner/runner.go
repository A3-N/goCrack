package runner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"gocrack/internal/planner"
)

type Event struct {
	Line     string
	Status   string
	Crack    string
	Current  string
	NewCrack bool
	Done     bool
	Error    error
}

func Start(parent context.Context, commands []planner.Command, tempDir string) (<-chan Event, chan<- string, context.CancelFunc) {
	if tempDir == "" {
		tempDir = planner.DefaultTempDir()
	}
	ctx, cancel := context.WithCancel(parent)
	ch := make(chan Event, 256)
	control := make(chan string, 32)
	go func() {
		defer close(ch)
		defer cleanupCombinedHashTargets(commands, tempDir)
		seen := map[string]bool{}
		total := len(commands)
		for i, cmd := range commands {
			select {
			case <-ctx.Done():
				ch <- Event{Line: "cancelled"}
				return
			default:
			}
			runCmd, outfile := withLiveOutfile(cmd, tempDir)
			current := fmt.Sprintf("[%d/%d] %s\n%s", i+1, total, runCmd.Label, planner.FormatCommand(runCmd))
			ch <- Event{Line: fmt.Sprintf("[%d/%d] %s", i+1, total, cmd.Label), Current: current}
			ch <- Event{Line: "$ " + planner.FormatCommand(runCmd)}

			c := exec.CommandContext(ctx, runCmd.Exe, runCmd.Args...)
			if runCmd.Exe != "" {
				c.Dir = filepath.Dir(runCmd.Exe)
				if strings.EqualFold(filepath.Base(runCmd.Exe), "cewl") {
					c.Dir = ""
				}
			}
			stdout, err := c.StdoutPipe()
			if err != nil {
				ch <- Event{Line: err.Error()}
				removeFile(outfile)
				continue
			}
			stderr, err := c.StderrPipe()
			if err != nil {
				ch <- Event{Line: err.Error()}
				removeFile(outfile)
				continue
			}
			stdin, err := c.StdinPipe()
			if err != nil {
				ch <- Event{Line: err.Error()}
				removeFile(outfile)
				continue
			}
			if err := c.Start(); err != nil {
				ch <- Event{Line: err.Error()}
				removeFile(outfile)
				continue
			}

			var wg sync.WaitGroup
			wg.Add(2)
			go pump(&wg, ch, stdout)
			go pump(&wg, ch, stderr)
			doneLive := make(chan struct{})
			var liveWG sync.WaitGroup
			if outfile != "" {
				liveWG.Add(1)
				go monitorOutfile(&liveWG, doneLive, outfile, seen, ch)
			}
			doneControls := make(chan struct{})
			go pumpControls(doneControls, control, stdin, ch)
			wg.Wait()
			err = c.Wait()
			close(doneLive)
			liveWG.Wait()
			close(doneControls)
			_ = stdin.Close()
			removeFile(outfile)
			if err != nil {
				ch <- Event{Line: "exit: " + err.Error()}
			} else {
				ch <- Event{Line: "exit: 0"}
			}
		}
		ch <- Event{Done: true, Line: "queue complete"}
	}()
	return ch, control, cancel
}

func withLiveOutfile(cmd planner.Command, tempDir string) (planner.Command, string) {
	if cmd.Mode == 0 || cmd.Hashlist == "" || hasOutfile(cmd.Args) {
		return cmd, ""
	}
	base := filepath.Join(tempDir, "live")
	if err := os.MkdirAll(base, 0755); err != nil {
		return cmd, ""
	}
	f, err := os.CreateTemp(base, "live-cracks-*.out")
	if err != nil {
		return cmd, ""
	}
	outfile := f.Name()
	_ = f.Close()
	cmd.Args = append(cmd.Args, "--outfile", outfile)
	if !hasArg(cmd.Args, "--outfile-format") {
		cmd.Args = append(cmd.Args, "--outfile-format", "1,2")
	}
	return cmd, outfile
}

func hasOutfile(args []string) bool {
	return hasArg(args, "--outfile") || hasArg(args, "-o")
}

func hasArg(args []string, names ...string) bool {
	for _, arg := range args {
		for _, name := range names {
			if arg == name || strings.HasPrefix(arg, name+"=") {
				return true
			}
		}
	}
	return false
}

func pump(wg *sync.WaitGroup, ch chan<- Event, r io.Reader) {
	defer wg.Done()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	status := statusCollector{}
	for sc.Scan() {
		for _, line := range terminalLines(sc.Text()) {
			if page, ok := status.feed(line); ok {
				ch <- Event{Line: line, Status: page}
			} else {
				ch <- Event{Line: line}
			}
		}
	}
	if err := sc.Err(); err != nil {
		ch <- Event{Line: "stream: " + err.Error()}
	}
}

type statusCollector struct {
	active bool
	lines  []string
}

func (s *statusCollector) feed(line string) (string, bool) {
	clean := cleanStatusLine(line)
	if strings.HasPrefix(clean, "Session..........:") {
		s.active = true
		s.lines = []string{clean}
		return strings.Join(s.lines, "\n"), true
	}
	if !s.active {
		return "", false
	}
	if clean == "" {
		return strings.Join(s.lines, "\n"), true
	}
	if isStatusLine(clean) {
		s.lines = append(s.lines, clean)
		return strings.Join(s.lines, "\n"), true
	}
	s.active = false
	return "", false
}

func isStatusLine(line string) bool {
	if strings.Contains(line, ".:") {
		return true
	}
	return strings.HasPrefix(line, "Started:") || strings.HasPrefix(line, "Stopped:")
}

func cleanStatusLine(line string) string {
	if idx := strings.Index(line, "Session..........:"); idx >= 0 {
		return strings.TrimSpace(line[idx:])
	}
	return strings.TrimSpace(line)
}

func terminalLines(line string) []string {
	line = strings.ReplaceAll(line, "\r", "\n")
	parts := strings.Split(line, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = stripANSI(part)
		part = strings.ReplaceAll(part, "\t", "    ")
		part = strings.Map(func(r rune) rune {
			if r == '\n' || r == '\r' || r == '\t' {
				return r
			}
			if unicode.IsControl(r) {
				return -1
			}
			return r
		}, part)
		out = append(out, part)
	}
	return out
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b && i+1 < len(s) && s[i+1] == '[' {
			i += 2
			for i < len(s) {
				c := s[i]
				if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
					break
				}
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func cleanupCombinedHashTargets(commands []planner.Command, tempDir string) {
	root := filepath.Join(tempDir, "hashes")
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return
	}
	seen := map[string]bool{}
	for _, cmd := range commands {
		if cmd.Hashlist == "" || seen[cmd.Hashlist] {
			continue
		}
		seen[cmd.Hashlist] = true
		base := filepath.Base(cmd.Hashlist)
		if !strings.HasPrefix(base, "goCrack-combined-") && !strings.HasPrefix(base, "goCrack-manual-") {
			continue
		}
		absPath, err := filepath.Abs(cmd.Hashlist)
		if err != nil {
			continue
		}
		rel, err := filepath.Rel(absRoot, absPath)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			continue
		}
		removeFile(absPath)
	}
	cleanupGeneratedHashFiles(absRoot, "goCrack-manual-")
}

func cleanupGeneratedHashFiles(absRoot, prefix string) {
	_ = filepath.WalkDir(absRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasPrefix(filepath.Base(path), prefix) {
			return nil
		}
		absPath, err := filepath.Abs(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(absRoot, absPath)
		if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return nil
		}
		removeFile(absPath)
		return nil
	})
}

func removeFile(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

func pumpControls(done <-chan struct{}, control <-chan string, stdin io.Writer, ch chan<- Event) {
	for {
		select {
		case <-done:
			return
		case s := <-control:
			if strings.TrimSpace(s) == "" {
				continue
			}
			_, _ = io.WriteString(stdin, s)
			ch <- Event{Line: "sent hashcat control: " + strings.TrimSpace(s)}
		}
	}
}

func monitorOutfile(wg *sync.WaitGroup, done <-chan struct{}, path string, seen map[string]bool, ch chan<- Event) {
	defer wg.Done()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		readOutfile(path, seen, ch)
		select {
		case <-done:
			readOutfile(path, seen, ch)
			return
		case <-ticker.C:
		}
	}
}

func readOutfile(path string, seen map[string]bool, ch chan<- Event) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || seen[line] {
			continue
		}
		seen[line] = true
		ch <- Event{Crack: line, NewCrack: true}
	}
}
