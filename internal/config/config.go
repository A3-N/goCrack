package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

const ConfigEnv = "GOCRACK_CONFIG"

type Settings struct {
	Hashcat   string            `json:"hashcat"`
	CeWL      string            `json:"cewl,omitempty"`
	Rulelists string            `json:"rulelists"`
	Wordlists string            `json:"wordlists"`
	Hashes    string            `json:"hashes"`
	Potfile   string            `json:"potfile"`
	Mode      int               `json:"mode"`
	Modes     []int             `json:"modes,omitempty"`
	Loopback  bool              `json:"loopback"`
	Kernel    bool              `json:"kernel"`
	Hwmon     bool              `json:"hwmon"`
	RuleFiles map[string]string `json:"rule_files"`

	HashcatExe string `json:"-"`
	CeWLExe    string `json:"-"`
}

type Issue struct {
	Key       string
	Label     string
	Message   string
	Required  bool
	Directory bool
}

func DefaultPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv(ConfigEnv)); p != "" {
		return filepath.Abs(expandPath(p))
	}
	if wd, err := os.Getwd(); err == nil && looksLikeAppDir(wd) {
		return filepath.Join(wd, "config.json"), nil
	}
	dir, err := AppDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.json"), nil
}

func AppDir() (string, error) {
	exe, err := os.Executable()
	if err == nil {
		if real, evalErr := filepath.EvalSymlinks(exe); evalErr == nil {
			exe = real
		}
		return filepath.Dir(exe), nil
	}
	return os.Getwd()
}

func looksLikeAppDir(dir string) bool {
	for _, name := range []string{"go.mod", "config.example.json"} {
		if isFile(filepath.Join(dir, name)) {
			return true
		}
	}
	return false
}

func Load(path string) (Settings, bool, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Prepare(cfg), false, nil
	}
	if err != nil {
		return Settings{}, false, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Settings{}, false, fmt.Errorf("parse %s: %w", path, err)
	}
	return Prepare(cfg), true, nil
}

func Save(path string, cfg Settings) error {
	cfg = Prepare(cfg)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0600)
}

func Default() Settings {
	return Settings{
		Mode:      1000,
		Loopback:  true,
		Hwmon:     true,
		RuleFiles: defaultRuleFiles(),
	}
}

func Prepare(cfg Settings) Settings {
	if cfg.Mode == 0 {
		cfg.Mode = 1000
	}
	if cfg.RuleFiles == nil {
		cfg.RuleFiles = defaultRuleFiles()
	}

	cfg.Hashcat = cleanPath(cfg.Hashcat)
	cfg.CeWL = cleanPath(cfg.CeWL)
	cfg.Rulelists = cleanPath(cfg.Rulelists)
	cfg.Wordlists = cleanPath(cfg.Wordlists)
	cfg.Hashes = cleanPath(cfg.Hashes)
	cfg.Potfile = cleanPath(cfg.Potfile)

	cfg.HashcatExe = resolveExecutable(cfg.Hashcat, hashcatNames())
	if cfg.Hashcat == "" && cfg.HashcatExe != "" {
		cfg.Hashcat = filepath.Dir(cfg.HashcatExe)
	}
	cfg.CeWLExe = resolveExecutable(cfg.CeWL, []string{"cewl"})
	if cfg.CeWL == "" && cfg.CeWLExe != "" {
		cfg.CeWL = cfg.CeWLExe
	}

	cfg = discoverDirectories(cfg)
	if cfg.Potfile == "" && cfg.HashcatExe != "" {
		cfg.Potfile = filepath.Join(filepath.Dir(cfg.HashcatExe), "hashcat.potfile")
	}
	return cfg
}

func RequiredIssues(cfg Settings) []Issue {
	cfg = Prepare(cfg)
	var issues []Issue
	if cfg.HashcatExe == "" {
		issues = append(issues, Issue{
			Key:       "hashcat",
			Label:     "Hashcat folder",
			Message:   "Hashcat not found. Type or browse to the hashcat folder.",
			Required:  true,
			Directory: true,
		})
	}
	if !isDir(cfg.Hashes) {
		issues = append(issues, Issue{
			Key:       "hashes",
			Label:     "Hashes directory",
			Message:   "Hashes directory not found. Type or browse to the directory containing hash files.",
			Required:  true,
			Directory: true,
		})
	}
	if !isDir(cfg.Wordlists) {
		issues = append(issues, Issue{
			Key:       "wordlists",
			Label:     "Wordlists directory",
			Message:   "Wordlists directory not found. Type or browse to the directory containing wordlists.",
			Required:  true,
			Directory: true,
		})
	}
	if !isDir(cfg.Rulelists) {
		issues = append(issues, Issue{
			Key:       "rulelists",
			Label:     "Rulelists directory",
			Message:   "Rulelists directory not found. Type or browse to the directory containing hashcat rule files.",
			Required:  true,
			Directory: true,
		})
	}
	return issues
}

func SetPath(cfg Settings, key, path string) Settings {
	path = cleanPath(path)
	switch key {
	case "hashcat":
		cfg.Hashcat = path
		if exe := resolveExecutable(path, hashcatNames()); exe != "" {
			root := filepath.Dir(exe)
			if cfg.Potfile == "" || !isFile(cfg.Potfile) {
				cfg.Potfile = filepath.Join(root, "hashcat.potfile")
			}
			if !isDir(cfg.Hashes) {
				cfg.Hashes = findDir([]string{root}, "hashes")
			}
			if !isDir(cfg.Wordlists) {
				cfg.Wordlists = findDir([]string{root}, "wordlists", "wordlist", "lists")
			}
			if !isDir(cfg.Rulelists) {
				cfg.Rulelists = findDir([]string{root}, "rules", "rulelists")
			}
		}
	case "cewl":
		cfg.CeWL = path
	case "hashes":
		cfg.Hashes = path
	case "wordlists":
		cfg.Wordlists = path
	case "rulelists":
		cfg.Rulelists = path
	case "potfile":
		cfg.Potfile = path
	}
	return Prepare(cfg)
}

func FieldValue(cfg Settings, key string) string {
	switch key {
	case "hashcat":
		if cfg.Hashcat != "" {
			return cfg.Hashcat
		}
		return cfg.HashcatExe
	case "cewl":
		if cfg.CeWL != "" {
			return cfg.CeWL
		}
		return cfg.CeWLExe
	case "hashes":
		return cfg.Hashes
	case "wordlists":
		return cfg.Wordlists
	case "rulelists":
		return cfg.Rulelists
	case "potfile":
		return cfg.Potfile
	default:
		return ""
	}
}

func IsFieldValid(cfg Settings, key string) bool {
	cfg = Prepare(cfg)
	switch key {
	case "hashcat":
		return cfg.HashcatExe != ""
	case "cewl":
		return cfg.CeWLExe != ""
	case "hashes":
		return isDir(cfg.Hashes)
	case "wordlists":
		return isDir(cfg.Wordlists)
	case "rulelists":
		return isDir(cfg.Rulelists)
	case "potfile":
		return cfg.Potfile != ""
	default:
		return false
	}
}

func discoverDirectories(cfg Settings) Settings {
	bases := candidateBases(cfg)
	if cfg.Hashes == "" {
		cfg.Hashes = findDir(bases, "hashes")
	}
	if cfg.Wordlists == "" {
		cfg.Wordlists = findDir(bases, "wordlists", "wordlist", "lists")
	}
	if cfg.Rulelists == "" {
		cfg.Rulelists = findDir(bases, "rules", "rulelists")
	}
	return cfg
}

func candidateBases(cfg Settings) []string {
	var bases []string
	if wd, err := os.Getwd(); err == nil {
		bases = append(bases, wd)
	}
	if app, err := AppDir(); err == nil {
		bases = append(bases, app, filepath.Dir(app))
	}
	if cfg.HashcatExe != "" {
		bases = append(bases, filepath.Dir(cfg.HashcatExe))
	}
	seen := map[string]bool{}
	var out []string
	for _, base := range bases {
		if base == "" {
			continue
		}
		abs, err := filepath.Abs(base)
		if err != nil {
			continue
		}
		if !seen[strings.ToLower(abs)] {
			seen[strings.ToLower(abs)] = true
			out = append(out, abs)
		}
	}
	return out
}

func findDir(bases []string, names ...string) string {
	for _, base := range bases {
		for _, name := range names {
			p := filepath.Join(base, name)
			if isDir(p) {
				return p
			}
		}
	}
	return ""
}

func cleanPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	path = expandPath(os.ExpandEnv(path))
	if isBareCommand(path) {
		return path
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Clean(abs)
}

func expandPath(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~"+string(os.PathSeparator)) || strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func resolveExecutable(path string, names []string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		for _, name := range names {
			if p, err := exec.LookPath(name); err == nil {
				return cleanPath(p)
			}
		}
		return ""
	}
	path = cleanPath(path)
	if isBareCommand(path) {
		if p, err := exec.LookPath(path); err == nil {
			return cleanPath(p)
		}
		return ""
	}
	st, err := os.Stat(path)
	if err == nil {
		if st.IsDir() {
			for _, name := range names {
				p := filepath.Join(path, name)
				if isFile(p) {
					return p
				}
			}
			return ""
		}
		return path
	}
	return ""
}

func hashcatNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"hashcat.exe", "hashcat"}
	}
	return []string{"hashcat", "hashcat.exe"}
}

func isBareCommand(path string) bool {
	return !filepath.IsAbs(path) && !strings.ContainsAny(path, `/\`)
}

func isDir(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.IsDir()
}

func isFile(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func defaultRuleFiles() map[string]string {
	return map[string]string{
		"big":             "1big.rule",
		"buka":            "buka_400k.rule",
		"d3ad0ne":         "d3ad0ne.rule",
		"d3adhob0":        "d3adhob0.rule",
		"digits1":         "digits1.rule",
		"digits2":         "digits2.rule",
		"digits3":         "digits3.rule",
		"dive":            "dive.rule",
		"fbfull":          "facebook-firstnames-capital.rule",
		"fbtop":           "facebook-firstnames-capital-top.rule",
		"fordyv1":         "fordyv1.rule",
		"generated2":      "generated2.rule",
		"generated3":      "generated3.rule",
		"hob064":          "hob064.rule",
		"huge":            "huge.rule",
		"leetspeak":       "leetspeak.rule",
		"NSAKEYv2":        "NSAKEY.v2.dive.rule",
		"ORTRTA":          "OneRuleToRuleThemAll.rule",
		"ORTRTS":          "OneRuleToRuleThemStill.rule",
		"OUTD":            "OptimizedUpToDate.rule",
		"pantag":          "pantagrule.popular.rule",
		"passwordpro":     "passwordspro.rule",
		"robotmyfavorite": "Robot_MyFavorite.rule",
		"rockyou30000":    "rockyou-30000.rule",
		"rule3":           "3.rule",
		"stacking58":      "stacking58.rule",
		"techtrip2":       "techtrip_2.rule",
		"tenKrules":       "10krules.rule",
		"toggles1":        "toggles1.rule",
		"toggles2":        "toggles2.rule",
		"toprules2020":    "toprules2020.rule",
		"TOXIC10k":        "TOXIC-10krules.rule",
		"TOXICSP":         "T0XlC-insert_space_and_special_0_F.rule",
		"williamsuper":    "williamsuper.rule",
		"hashmob150":      "HashMob.150k.rule",
	}
}
