package scanner

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gocrack/internal/config"
)

type Inventory struct {
	Modes     []ModeGroup
	Wordlists []FileRef
	Rules     []RuleRef
}

type ModeGroup struct {
	Mode  int
	Path  string
	Files []FileRef
}

type FileRef struct {
	Name string
	Rel  string
	Path string
	Size int64
}

type RuleRef struct {
	Name  string
	Rel   string
	Path  string
	Size  int64
	Lines int64
	Group string
}

func Scan(cfg config.Settings) (Inventory, error) {
	modes, err := ScanHashModes(cfg.Hashes, cfg.Mode)
	if err != nil {
		return Inventory{}, err
	}
	wordlists, err := ScanFiles(cfg.Wordlists)
	if err != nil {
		return Inventory{}, err
	}
	rules, err := ScanRules(cfg.Rulelists)
	if err != nil {
		return Inventory{}, err
	}
	return Inventory{Modes: modes, Wordlists: wordlists, Rules: rules}, nil
}

func ScanHashModes(root string, fallbackMode int) ([]ModeGroup, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var groups []ModeGroup
	var rootFiles []FileRef
	for _, e := range entries {
		p := filepath.Join(root, e.Name())
		if e.IsDir() {
			mode, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			files, err := ScanFiles(p)
			if err != nil {
				return nil, err
			}
			groups = append(groups, ModeGroup{Mode: mode, Path: p, Files: files})
			continue
		}
		if isGeneratedGoCrackFile(e.Name()) {
			continue
		}
		if info, err := e.Info(); err == nil {
			rootFiles = append(rootFiles, FileRef{Name: e.Name(), Rel: e.Name(), Path: p, Size: info.Size()})
		}
	}
	if len(rootFiles) > 0 {
		groups = append(groups, ModeGroup{Mode: fallbackMode, Path: root, Files: rootFiles})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].Mode < groups[j].Mode })
	return groups, nil
}

func ScanFiles(root string) ([]FileRef, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, nil
	}
	var files []FileRef
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if isGeneratedGoCrackFile(d.Name()) {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = d.Name()
		}
		files = append(files, FileRef{Name: d.Name(), Rel: rel, Path: path, Size: info.Size()})
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return strings.ToLower(files[i].Rel) < strings.ToLower(files[j].Rel) })
	return files, err
}

func isGeneratedGoCrackFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasPrefix(lower, "gocrack-combined-") ||
		strings.HasPrefix(lower, "gocrack-manual-") ||
		strings.HasPrefix(lower, "live-cracks-")
}

func ScanRules(root string) ([]RuleRef, error) {
	if _, err := os.Stat(root); err != nil {
		return nil, nil
	}
	var rules []RuleRef
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.EqualFold(filepath.Ext(path), ".rule") {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = d.Name()
		}
		group := "root"
		if dir := filepath.Dir(rel); dir != "." {
			group = strings.Split(dir, string(os.PathSeparator))[0]
		}
		rules = append(rules, RuleRef{
			Name:  d.Name(),
			Rel:   rel,
			Path:  path,
			Size:  info.Size(),
			Lines: countLines(path),
			Group: group,
		})
		return nil
	})
	sort.Slice(rules, func(i, j int) bool { return strings.ToLower(rules[i].Rel) < strings.ToLower(rules[j].Rel) })
	return rules, err
}

func CombineFiles(out string, files []FileRef) error {
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return err
	}
	dst, err := os.Create(out)
	if err != nil {
		return err
	}
	defer dst.Close()
	w := bufio.NewWriterSize(dst, 1<<20)
	defer w.Flush()
	for _, f := range files {
		src, err := os.Open(f.Path)
		if err != nil {
			return err
		}
		_, copyErr := io.CopyBuffer(w, src, make([]byte, 1<<20))
		closeErr := src.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeErr != nil {
			return closeErr
		}
		if _, err := w.WriteString("\n"); err != nil {
			return err
		}
	}
	return nil
}

func CombineHashFiles(out string, mode int, files []FileRef) error {
	if err := os.MkdirAll(filepath.Dir(out), 0755); err != nil {
		return err
	}
	dst, err := os.Create(out)
	if err != nil {
		return err
	}
	defer dst.Close()
	w := bufio.NewWriterSize(dst, 1<<20)
	defer w.Flush()
	seen := map[string]bool{}
	for _, f := range files {
		src, err := os.Open(f.Path)
		if err != nil {
			return err
		}
		sc := bufio.NewScanner(src)
		sc.Buffer(make([]byte, 64*1024), 16*1024*1024)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if !IsLikelyHashLine(mode, line) || seen[line] {
				continue
			}
			seen[line] = true
			if _, err := w.WriteString(line + "\n"); err != nil {
				_ = src.Close()
				return err
			}
		}
		scanErr := sc.Err()
		closeErr := src.Close()
		if scanErr != nil {
			return scanErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func IsLikelyHashLine(mode int, line string) bool {
	line = strings.TrimSpace(line)
	if line == "" || isMetadataLine(line) {
		return false
	}
	if mode == 1000 {
		return isNTLMHashLine(line)
	}
	if strings.HasPrefix(line, "$") {
		return true
	}
	for _, field := range strings.FieldsFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || r == ':' || r == ';' || r == ','
	}) {
		if isHexLen(field, 16, 256) {
			return true
		}
	}
	return false
}

func isMetadataLine(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	prefixes := []string{
		"#",
		"//",
		"[-]",
		"[*]",
		"failed to parse",
		"hash parsing error",
		"token length exception",
		"* token length exception",
		"this error happens",
		"malformed, or",
		"--username",
		"started:",
		"stopped:",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isNTLMHashLine(line string) bool {
	if isHexLen(line, 32, 32) {
		return true
	}
	parts := strings.Split(line, ":")
	if len(parts) >= 4 && isHexLen(parts[2], 32, 32) && isHexLen(parts[3], 32, 32) {
		return true
	}
	if len(parts) >= 2 && isHexLen(parts[len(parts)-1], 32, 32) {
		return true
	}
	return false
}

func isHexLen(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func FormatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for x := n / unit; x >= unit; x /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func countLines(path string) int64 {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var n int64
	for sc.Scan() {
		n++
	}
	return n
}
