package setup

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"gocrack/internal/config"
)

type field struct {
	key      string
	label    string
	message  string
	dir      bool
	required bool
	always   bool
}

type Model struct {
	cfg        config.Settings
	configPath string
	fields     []field
	index      int
	input      textinput.Model
	picker     filepicker.Model
	width      int
	height     int
	err        string
	done       bool
	cancelled  bool
}

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("39"))
	mutedStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	goodStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	warnStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("214"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	boxStyle   = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
)

func Run(cfg config.Settings, configPath string, firstRun bool) (config.Settings, bool, error) {
	fields := setupFields(cfg, firstRun)
	if len(fields) == 0 {
		return cfg, true, nil
	}
	m := newModel(cfg, configPath, fields)
	p := tea.NewProgram(m, tea.WithAltScreen())
	final, err := p.Run()
	if err != nil {
		return cfg, false, err
	}
	res, ok := final.(Model)
	if !ok {
		return cfg, false, fmt.Errorf("setup returned unexpected model %T", final)
	}
	if res.cancelled {
		return res.cfg, false, nil
	}
	return config.Prepare(res.cfg), true, nil
}

func setupFields(cfg config.Settings, firstRun bool) []field {
	if firstRun {
		return []field{
			{
				key:      "hashcat",
				label:    "Hashcat folder",
				message:  "Type or browse to the hashcat folder. goCrack will derive hashcat, potfile, hashes, wordlists, and rules from this folder when present.",
				dir:      true,
				required: true,
				always:   true,
			},
			{
				key:      "hashes",
				label:    "Hashes directory",
				message:  "Type or browse to the directory containing hash files.",
				dir:      true,
				required: true,
				always:   true,
			},
			{
				key:      "wordlists",
				label:    "Wordlists directory",
				message:  "Type or browse to the directory containing wordlists.",
				dir:      true,
				required: true,
				always:   true,
			},
			{
				key:      "rulelists",
				label:    "Rulelists directory",
				message:  "Type or browse to the directory containing hashcat rule files.",
				dir:      true,
				required: true,
				always:   true,
			},
		}
	}
	var fields []field
	for _, issue := range config.RequiredIssues(cfg) {
		fields = append(fields, field{
			key:      issue.Key,
			label:    issue.Label,
			message:  issue.Message,
			dir:      issue.Directory,
			required: issue.Required,
		})
	}
	return fields
}

func newModel(cfg config.Settings, configPath string, fields []field) Model {
	m := Model{
		cfg:        config.Prepare(cfg),
		configPath: configPath,
		fields:     fields,
	}
	m.skipValidFields()
	m.resetPicker()
	return m
}

func (m Model) Init() tea.Cmd {
	return m.picker.Init()
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.picker.SetHeight(max(6, msg.Height-12))
		m.input.Width = max(30, msg.Width-8)
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			m.cancelled = true
			return m, tea.Quit
		case "enter":
			if typed := strings.TrimSpace(m.input.Value()); typed != "" {
				return m.selectPath(typed)
			}
		case " ":
			if strings.TrimSpace(m.input.Value()) == "" && m.current().dir {
				return m.selectPath(m.picker.CurrentDirectory)
			}
		}
	}

	var cmds []tea.Cmd
	if shouldUpdateInput(msg, m.input.Value()) {
		m.refreshInputSuggestions()
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		cmds = append(cmds, cmd)
		m.refreshInputSuggestions()
	}

	if shouldUpdatePicker(msg, m.input.Value()) {
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		cmds = append(cmds, cmd)
		if !m.current().dir {
			if did, path := m.picker.DidSelectFile(msg); did {
				return m.selectPath(path)
			}
		}
	}
	return m, tea.Batch(cmds...)
}

func (m Model) View() string {
	if len(m.fields) == 0 || m.index >= len(m.fields) {
		return titleStyle.Render("goCrack setup") + "\n\n" + goodStyle.Render("Configuration complete.")
	}
	f := m.current()
	var b strings.Builder
	b.WriteString(titleStyle.Render("goCrack setup"))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render("Config: " + m.configPath))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("%s %d/%d\n", f.label, m.index+1, len(m.fields)))
	b.WriteString(errStyle.Bold(true).Render(missingText(f)))
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render(f.message))
	b.WriteString("\n")
	current := config.FieldValue(m.cfg, f.key)
	if current == "" {
		b.WriteString(warnStyle.Render("Current: not configured"))
	} else {
		b.WriteString("Current: " + current)
	}
	b.WriteString("\n")
	if m.err != "" {
		b.WriteString(errStyle.Render(m.err))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString("Path: ")
	b.WriteString(m.input.View())
	b.WriteString("\n")
	if matches := m.input.MatchedSuggestions(); len(matches) > 0 {
		b.WriteString(mutedStyle.Render("Tab completes: " + matches[0]))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(mutedStyle.Render("Type or paste a path, press Tab to autocomplete, press Enter to accept the path shown above."))
	b.WriteString("\n")
	if f.dir {
		b.WriteString(mutedStyle.Render("Browse below with arrows. Enter opens a directory. Space selects the current browsed directory when the path box is empty."))
	} else {
		b.WriteString(mutedStyle.Render("Browse below with arrows. Enter opens directories and selects a file when the path box is empty."))
	}
	b.WriteString("\n\n")
	b.WriteString(boxStyle.Width(max(40, m.width-4)).Render(m.picker.View()))
	return b.String()
}

func (m Model) current() field {
	if len(m.fields) == 0 {
		return field{}
	}
	return m.fields[clamp(m.index, 0, len(m.fields)-1)]
}

func shouldUpdateInput(msg tea.Msg, value string) bool {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return false
	}
	switch key.String() {
	case "ctrl+c", "esc", "enter":
		return false
	case "up", "down", "pgup", "pgdown":
		return false
	case "left", "right", "backspace":
		return value != ""
	default:
		return true
	}
}

func shouldUpdatePicker(msg tea.Msg, value string) bool {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return true
	}
	switch key.String() {
	case "up", "down", "pgup", "pgdown":
		return true
	case "enter", "left", "right", "backspace":
		return strings.TrimSpace(value) == ""
	default:
		return false
	}
}

func (m *Model) refreshInputSuggestions() {
	m.input.SetSuggestions(pathSuggestions(m.input.Value(), m.current().dir))
}

func pathSuggestions(prefix string, dirOnly bool) []string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil
	}
	expanded := normalizeTypedPath(prefix)
	dir, base := completionDirBase(expanded)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	baseLower := strings.ToLower(base)
	var out []string
	for _, entry := range entries {
		name := entry.Name()
		if baseLower != "" && !strings.HasPrefix(strings.ToLower(name), baseLower) {
			continue
		}
		path := filepath.Join(dir, name)
		if entry.IsDir() {
			out = append(out, path+string(os.PathSeparator))
			continue
		}
		if !dirOnly {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	if len(out) > 30 {
		return out[:30]
	}
	return out
}

func completionDirBase(path string) (string, string) {
	if hasTrailingSeparator(path) {
		return path, ""
	}
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	if dir == "" {
		dir = "."
	}
	return dir, base
}

func hasTrailingSeparator(path string) bool {
	return strings.HasSuffix(path, `/`) || strings.HasSuffix(path, `\`)
}

func normalizeTypedPath(path string) string {
	path = strings.TrimSpace(os.ExpandEnv(path))
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}

func missingText(f field) string {
	switch f.key {
	case "hashcat":
		return "Hashcat not found"
	case "hashes":
		return "Hashes directory not found"
	case "wordlists":
		return "Wordlists directory not found"
	case "rulelists":
		return "Rulelists directory not found"
	default:
		return f.label + " not found"
	}
}

func placeholderForField(f field) string {
	if f.key == "hashcat" {
		return "Type path to hashcat folder"
	}
	if f.dir {
		return "Type directory path"
	}
	switch f.key {
	default:
		return "Type file path"
	}
}

func (m Model) selectPath(path string) (tea.Model, tea.Cmd) {
	path = normalizeTypedPath(path)
	if path == "" {
		m.err = "select a path"
		return m, nil
	}
	f := m.current()
	if f.dir {
		if st, err := os.Stat(path); err != nil || !st.IsDir() {
			m.err = "selected path is not a directory"
			return m, nil
		}
	} else {
		if st, err := os.Stat(path); err != nil || st.IsDir() {
			m.err = "selected path is not a file"
			return m, nil
		}
	}
	m.cfg = config.SetPath(m.cfg, f.key, path)
	if f.required && !config.IsFieldValid(m.cfg, f.key) {
		m.err = "selected path did not satisfy " + f.label
		return m, nil
	}
	return m.advance()
}

func (m Model) advance() (tea.Model, tea.Cmd) {
	m.index++
	m.err = ""
	m.skipValidFields()
	if m.index >= len(m.fields) {
		m.done = true
		return m, tea.Quit
	}
	m.resetPicker()
	return m, m.picker.Init()
}

func (m *Model) skipValidFields() {
	for m.index < len(m.fields) {
		f := m.fields[m.index]
		if f.always {
			return
		}
		if f.required && config.IsFieldValid(m.cfg, f.key) {
			m.index++
			continue
		}
		if !f.required && config.IsFieldValid(m.cfg, f.key) {
			m.index++
			continue
		}
		return
	}
}

func (m *Model) resetPicker() {
	if len(m.fields) == 0 || m.index >= len(m.fields) {
		return
	}
	f := m.current()
	p := filepicker.New()
	p.ShowHidden = true
	p.ShowPermissions = false
	p.ShowSize = true
	p.FileAllowed = !f.dir
	p.DirAllowed = false
	p.CurrentDirectory = startDir(config.FieldValue(m.cfg, f.key))
	if m.height > 0 {
		p.SetHeight(max(6, m.height-12))
	}
	m.picker = p

	input := textinput.New()
	input.Prompt = ""
	input.Placeholder = placeholderForField(f)
	input.CharLimit = 4096
	input.Width = max(30, m.width-8)
	input.ShowSuggestions = true
	input.CompletionStyle = mutedStyle
	input.SetValue(config.FieldValue(m.cfg, f.key))
	_ = input.Focus()
	m.input = input
	m.refreshInputSuggestions()
}

func startDir(path string) string {
	if path != "" {
		if st, err := os.Stat(path); err == nil {
			if st.IsDir() {
				return path
			}
			return filepath.Dir(path)
		}
		if dir := filepath.Dir(path); dir != "." && dir != "" {
			if st, err := os.Stat(dir); err == nil && st.IsDir() {
				return dir
			}
		}
	}
	if wd, err := os.Getwd(); err == nil {
		return wd
	}
	return "."
}

func clamp(v, lo, hi int) int {
	if hi < lo {
		return lo
	}
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
