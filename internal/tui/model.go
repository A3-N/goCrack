package tui

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"gocrack/internal/config"
	"gocrack/internal/planner"
	"gocrack/internal/runner"
	"gocrack/internal/scanner"
)

const (
	stepHome = iota
	stepTargets
	stepWordlists
	stepOptions
	stepQueue
	stepRun
)

type model struct {
	root       string
	cfg        config.Settings
	inv        scanner.Inventory
	processors []planner.Processor
	tempDir    string

	width  int
	height int
	step   int

	targetFocus int
	modeCursor  int
	hashCursor  int
	wordCursor  int
	attCursor   int
	optCursor   int
	prevCursor  int

	selectedHashes     map[int]map[string]scanner.FileRef
	selectedWordlists  map[string]scanner.FileRef
	selectedProcessors map[string]bool

	filtering bool
	filter    textinput.Model
	editField string
	edit      textinput.Model

	options  planner.Options
	seedText string
	cewlURL  string

	plan      planner.Plan
	planDirty bool
	running   bool
	events    <-chan runner.Event
	control   chan<- string
	cancelRun context.CancelFunc
	runLog    []string
	status    string
	current   string
	cracked   []string
	runDone   bool
}

type runMsg runner.Event

var (
	accent = lipgloss.Color("39")
	muted  = lipgloss.Color("240")
	warn   = lipgloss.Color("214")
	bad    = lipgloss.Color("196")
	good   = lipgloss.Color("42")
	hashC  = lipgloss.Color("81")
	plainC = lipgloss.Color("229")
	valueC = lipgloss.Color("252")
	hoverC = lipgloss.Color("236")

	titleStyle     = lipgloss.NewStyle().Bold(true).Foreground(accent)
	mutedStyle     = lipgloss.NewStyle().Foreground(muted)
	activeStyle    = lipgloss.NewStyle().Foreground(accent).Bold(true)
	highlightStyle = lipgloss.NewStyle().Background(hoverC).Foreground(lipgloss.Color("231"))
	warnStyle      = lipgloss.NewStyle().Foreground(warn)
	errorStyle     = lipgloss.NewStyle().Foreground(bad)
	okStyle        = lipgloss.NewStyle().Foreground(good)
	hashStyle      = lipgloss.NewStyle().Foreground(hashC)
	plainStyle     = lipgloss.NewStyle().Foreground(plainC).Bold(true)
	valueStyle     = lipgloss.NewStyle().Foreground(valueC)
	boxStyle       = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 1)
)

func New(root string, cfg config.Settings, inv scanner.Inventory, tempDir string) tea.Model {
	filter := textinput.New()
	filter.Placeholder = "filter"
	filter.Prompt = "/ "
	filter.CharLimit = 256

	edit := textinput.New()
	edit.Prompt = "> "
	edit.CharLimit = 4096

	m := model{
		root:               root,
		cfg:                cfg,
		inv:                inv,
		processors:         planner.Catalog(),
		tempDir:            tempDir,
		selectedHashes:     map[int]map[string]scanner.FileRef{},
		selectedWordlists:  map[string]scanner.FileRef{},
		selectedProcessors: map[string]bool{},
		filter:             filter,
		edit:               edit,
		options: planner.Options{
			Loopback:        cfg.Loopback,
			Kernel:          cfg.Kernel,
			HwmonDisable:    cfg.Hwmon,
			Status:          true,
			CustomChars:     6,
			CustomIncrement: true,
			MarkovNGram:     3,
			MarkovAmount:    5000,
			CeWLDepth:       2,
			CeWLMinLength:   5,
		},
		planDirty: true,
	}
	m.preselectSingleItems()
	return m
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case runMsg:
		ev := runner.Event(msg)
		if ev.Status != "" {
			m.status = ev.Status
		}
		if ev.Current != "" {
			m.current = ev.Current
			m.status = ""
		}
		if ev.Crack != "" {
			crack := ev.Crack
			if ev.NewCrack {
				m.cracked = append([]string{"* " + crack}, m.cracked...)
			} else {
				m.cracked = append([]string{crack}, m.cracked...)
			}
			if len(m.cracked) > 500 {
				m.cracked = m.cracked[:500]
			}
		}
		if ev.Line != "" {
			m.runLog = append(m.runLog, ev.Line)
			if len(m.runLog) > 2000 {
				m.runLog = m.runLog[len(m.runLog)-2000:]
			}
		}
		if ev.Done {
			m.running = false
			m.runDone = true
			return m, nil
		}
		if m.running {
			return m, waitEvent(m.events)
		}
		return m, nil
	case tea.MouseMsg:
		return m.handleMouse(msg)
	case tea.KeyMsg:
		if m.editField != "" {
			return m.updateEdit(msg)
		}
		if m.filtering {
			return m.updateFilter(msg)
		}
		switch msg.String() {
		case "ctrl+c":
			if m.running && m.cancelRun != nil {
				m.cancelRun()
				return m, nil
			}
			return m, tea.Quit
		case "q", "Q":
			if m.running && m.control != nil {
				m.control <- "q\n"
				return m, nil
			}
			return m, tea.Quit
		case "s", "S":
			if m.running && m.control != nil {
				m.control <- "s\n"
			}
			return m, nil
		case "b", "B":
			if m.running && m.control != nil {
				m.control <- "b\n"
			}
			return m, nil
		case "esc":
			if m.running && m.cancelRun != nil {
				m.cancelRun()
				return m, nil
			}
		case "/":
			m.filtering = true
			m.filter.Focus()
			return m, nil
		case "tab":
			if m.step == stepTargets {
				m.targetFocus = 1 - m.targetFocus
			} else {
				m.nextStep()
			}
			return m, nil
		case "shift+tab":
			m.prevStep()
			return m, nil
		case "left":
			if m.step == stepTargets && m.targetFocus == 1 {
				m.targetFocus = 0
			} else {
				m.prevStep()
			}
			return m, nil
		case "right", "enter":
			if m.step == stepTargets && msg.String() == "right" && m.targetFocus == 0 {
				m.targetFocus = 1
			} else {
				m.nextStep()
			}
			return m, nil
		case "up", "k":
			m.moveCursor(-1)
			return m, nil
		case "down", "j":
			m.moveCursor(1)
			return m, nil
		case "pgup":
			m.moveCursor(-m.pageSize())
			return m, nil
		case "pgdown":
			m.moveCursor(m.pageSize())
			return m, nil
		case " ":
			m.toggleCurrent()
			return m, nil
		case "a":
			m.selectAllFiltered()
			return m, nil
		case "x":
			m.clearCurrentSelection()
			return m, nil
		case "+", "=":
			m.adjustOption(1)
			return m, nil
		case "-":
			m.adjustOption(-1)
			return m, nil
		case "e":
			m.beginEdit()
			return m, nil
		case "p":
			if m.step == stepQueue {
				m.rebuildPlan()
			}
			return m, nil
		case "r":
			if m.step == stepQueue && !m.running {
				m.rebuildPlan()
				if len(m.plan.Commands) > 0 {
					m.runLog = nil
					m.status = ""
					m.current = ""
					m.cracked = nil
					m.runDone = false
					m.running = true
					m.step = stepRun
					m.events, m.control, m.cancelRun = runner.Start(context.Background(), m.plan.Commands, m.tempDir)
					return m, waitEvent(m.events)
				}
			}
			return m, nil
		}
	}
	return m, nil
}

func (m model) View() string {
	if m.width == 0 {
		return "goCrack"
	}
	var b strings.Builder
	b.WriteString(m.header())
	b.WriteString("\n")
	b.WriteString(m.promptLine())
	b.WriteString("\n")
	b.WriteString("\n")
	switch m.step {
	case stepHome:
		b.WriteString(m.viewHome())
	case stepTargets:
		b.WriteString(m.viewTargets())
	case stepWordlists:
		b.WriteString(m.viewWordlists())
	case stepOptions:
		b.WriteString(m.viewOptions())
	case stepQueue:
		b.WriteString(m.viewQueue())
	case stepRun:
		b.WriteString(m.viewRun())
	}
	return b.String()
}

func (m *model) preselectSingleItems() {
	for i, g := range m.inv.Modes {
		if g.Mode == m.cfg.Mode {
			m.modeCursor = i
			break
		}
	}
	if len(m.inv.Modes) == 1 && len(m.inv.Modes[0].Files) == 1 {
		m.selectHash(m.inv.Modes[0].Mode, m.inv.Modes[0].Files[0])
	}
	if len(m.inv.Wordlists) == 1 {
		m.selectedWordlists[m.inv.Wordlists[0].Path] = m.inv.Wordlists[0]
	}
}

func (m model) header() string {
	stages := []string{"Home", "Targets", "Wordlists", "Options", "Queue", "Run"}
	var parts []string
	for i, s := range stages {
		part := fmt.Sprintf(" %d %s ", i+1, s)
		if i == m.step {
			part = activeStyle.Render("[" + strings.TrimSpace(part) + "]")
		} else {
			part = mutedStyle.Render(strings.TrimSpace(part))
		}
		parts = append(parts, part)
	}
	line := titleStyle.Render("goCrack") + "  " + strings.Join(parts, "  ")
	return line
}

func (m model) help() string {
	switch m.step {
	case stepHome:
		return mutedStyle.Render("homepage | arrows/mouse choose attack | space selects | / filters | enter configures | q quits")
	case stepTargets:
		return mutedStyle.Render("arrows move | tab switches mode/hash pane | space selects | / filters | enter continues | q quits")
	case stepOptions:
		return mutedStyle.Render("arrows move | space toggles | +/- changes numbers | e edits text fields | enter continues")
	case stepQueue:
		return mutedStyle.Render("p rebuilds preview | r runs queue | arrows scroll preview | left goes back | q quits")
	case stepRun:
		if m.running {
			return mutedStyle.Render("run view | s status | b bypass/skip current attack | q asks hashcat to quit | esc force-cancels")
		}
		return mutedStyle.Render("run complete | q quits | left returns to queue")
	default:
		return mutedStyle.Render("arrows move | space selects | a selects filtered | x clears | / filters | enter continues | q quits")
	}
}

func (m model) promptLine() string {
	if m.filtering {
		return m.filter.View()
	}
	if m.editField != "" {
		return m.edit.View()
	}
	return m.help()
}

func (m model) bodyHeight() int {
	if m.height <= 0 {
		return 20
	}
	chrome := lipgloss.Height(m.header()) + lipgloss.Height(m.promptLine()) + 2
	return max(1, m.height-chrome)
}

func (m model) bodyContentHeight() int {
	return max(1, m.bodyHeight()-2)
}

func (m model) pageSize() int {
	return max(1, m.bodyContentHeight()-1)
}

func (m model) viewTargets() string {
	leftW := max(28, m.width/3)
	rightW := max(40, m.width-leftW-5)
	contentH := m.bodyContentHeight()
	modeLines := []string{panelTitle("Hash modes", m.targetFocus == 0)}
	for i, g := range m.inv.Modes {
		selected := len(m.selectedHashes[g.Mode]) > 0
		cursor := i == m.modeCursor && m.targetFocus == 0
		line := checkboxLine(cursor, selected, fmt.Sprintf("%d", g.Mode), fmt.Sprintf("%d files", len(g.Files)), leftW-4)
		modeLines = append(modeLines, line)
	}
	if len(m.inv.Modes) == 0 {
		modeLines = append(modeLines, errorStyle.Render("No hash modes found under "+m.cfg.Hashes))
	}

	hashLines := []string{panelTitle("Hash files", m.targetFocus == 1)}
	files := m.filteredHashFiles()
	start, end := windowRange(m.hashCursor, len(files), contentH-1)
	for i := start; i < end; i++ {
		f := files[i]
		mode := m.currentMode()
		selected := m.selectedHashes[mode] != nil && m.selectedHashes[mode][f.Path].Path != ""
		cursor := i == m.hashCursor && m.targetFocus == 1
		line := checkboxLine(cursor, selected, f.Rel, scanner.FormatSize(f.Size), rightW-4)
		hashLines = append(hashLines, line)
	}
	if len(files) == 0 {
		hashLines = append(hashLines, mutedStyle.Render("No files in selected mode or filter."))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top,
		boxStyle.Width(leftW).Render(strings.Join(fitLines(modeLines, contentH), "\n")),
		" ",
		boxStyle.Width(rightW).Render(strings.Join(fitLines(hashLines, contentH), "\n")),
	)
}

func (m model) viewWordlists() string {
	files := m.filteredWordlists()
	contentH := m.bodyContentHeight()
	lines := []string{panelTitle("Wordlists", true)}
	start, end := windowRange(m.wordCursor, len(files), contentH-1)
	for i := start; i < end; i++ {
		f := files[i]
		selected := m.selectedWordlists[f.Path].Path != ""
		line := checkboxLine(i == m.wordCursor, selected, f.Rel, scanner.FormatSize(f.Size), m.width-6)
		lines = append(lines, line)
	}
	if len(files) == 0 {
		lines = append(lines, mutedStyle.Render("No wordlists found or filter removed them."))
	}
	return boxStyle.Width(m.width - 4).Render(strings.Join(fitLines(lines, contentH), "\n"))
}

func (m model) viewHome() string {
	leftW := max(44, m.width/2)
	rightW := max(36, m.width-leftW-5)
	contentH := m.bodyContentHeight()

	lines := []string{panelTitle("Attack homepage", true)}
	procs := m.filteredProcessors()
	start, end := windowRange(m.attCursor, len(procs), contentH-1)
	for i := start; i < end; i++ {
		p := procs[i]
		selected := m.selectedProcessors[p.ID]
		text := p.ID + "  " + p.Name
		detail := p.Source
		line := checkboxLine(i == m.attCursor, selected, text, detail, leftW-4)
		lines = append(lines, line)
		if i == m.attCursor {
			lines = append(lines, truncate("    "+mutedStyle.Render(p.Description), m.width-6))
		}
	}

	next := []string{panelTitle("Next required cards", false)}
	if id := m.selectedProcessorID(); id == "" {
		next = append(next, warnStyle.Render("Select one attack type to configure the next card."))
	} else {
		next = append(next, okStyle.Render(m.selectedProcessorName()))
		for _, item := range m.requirementLines(id) {
			next = append(next, item)
		}
		next = append(next, "")
		next = append(next, mutedStyle.Render("Enter opens the first required card."))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top,
		boxStyle.Width(leftW).Render(strings.Join(fitLines(lines, contentH), "\n")),
		" ",
		boxStyle.Width(rightW).Render(strings.Join(fitLines(next, contentH), "\n")),
	)
}

func (m model) viewOptions() string {
	opts := m.optionRows()
	contentH := m.bodyContentHeight()
	lines := []string{panelTitle("Options", true)}
	for i, row := range opts {
		if i == m.optCursor {
			lines = append(lines, highlightStyle.Render("> "+row))
		} else {
			lines = append(lines, "  "+row)
		}
	}
	return boxStyle.Width(m.width - 4).Render(strings.Join(fitLines(lines, contentH), "\n"))
}

func (m model) viewQueue() string {
	if m.planDirty && !m.running {
		m.rebuildPlan()
	}
	lines := []string{panelTitle("Preview", true)}
	contentH := m.bodyContentHeight()
	for _, w := range m.plan.Warnings {
		lines = append(lines, warnStyle.Render("! "+w))
	}
	if len(m.plan.Commands) == 0 {
		lines = append(lines, errorStyle.Render("No runnable commands yet. Select targets, wordlists, and attacks."))
	} else {
		start, end := windowRange(m.prevCursor, len(m.plan.Commands), contentH-2)
		for i := start; i < end; i++ {
			c := m.plan.Commands[i]
			line := fmt.Sprintf("%03d %s", i+1, planner.FormatCommand(c))
			if i == m.prevCursor {
				lines = append(lines, highlightStyle.Render(truncate("> "+line, m.width-6)))
			} else {
				lines = append(lines, truncate("  "+line, m.width-6))
			}
		}
		lines = append(lines, okStyle.Render(fmt.Sprintf("%d command(s) ready", len(m.plan.Commands))))
	}
	return boxStyle.Width(m.width - 4).Render(strings.Join(fitLines(lines, contentH), "\n"))
}

func (m model) viewRun() string {
	leftW := max(32, m.width/3)
	rightW := max(50, m.width-leftW-5)
	contentH := m.bodyContentHeight()

	left := []string{panelTitle("Current command", m.running)}
	if strings.TrimSpace(m.current) == "" {
		left = append(left, mutedStyle.Render("Waiting for first command."))
	} else {
		for _, line := range strings.Split(m.current, "\n") {
			appendWrapped(&left, line, leftW-4)
		}
	}
	left = append(left, "")
	left = append(left, panelTitle("Status", m.running))
	if strings.TrimSpace(m.status) == "" {
		left = append(left, mutedStyle.Render("Press s or wait for --status."))
	} else {
		for _, line := range strings.Split(m.status, "\n") {
			appendWrapped(&left, colorStatusLine(line), leftW-4)
		}
	}
	left = append(left, "")
	left = append(left, panelTitle("Cracked", m.running))
	if len(m.cracked) == 0 {
		left = append(left, mutedStyle.Render("New cracks from this run will appear here."))
	} else {
		end := min(len(m.cracked), contentH)
		for _, line := range m.cracked[:end] {
			appendWrapped(&left, colorCrackLine(line), leftW-4)
		}
	}
	if m.runDone {
		left = append(left, "")
		left = append(left, okStyle.Render("Queue complete."))
	}

	right := []string{panelTitle("Raw hashcat output", true)}
	rawRows := make([]string, 0, len(m.runLog))
	for _, line := range m.runLog {
		appendWrapped(&rawRows, line, rightW-4)
	}
	start := 0
	maxLines := contentH
	if len(rawRows) > maxLines {
		start = len(rawRows) - maxLines
	}
	right = append(right, rawRows[start:]...)
	if len(rawRows) == 0 {
		right = append(right, mutedStyle.Render("Raw output appears here."))
	}

	return lipgloss.JoinHorizontal(lipgloss.Top,
		boxStyle.Width(leftW).Render(strings.Join(fitLines(left, contentH), "\n")),
		" ",
		boxStyle.Width(rightW).Render(strings.Join(fitLines(right, contentH), "\n")),
	)
}

func (m *model) updateFilter(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.filtering = false
		m.filter.Blur()
		m.filter.SetValue("")
		m.clampCursors()
		return m, nil
	case "enter":
		m.filtering = false
		m.filter.Blur()
		m.clampCursors()
		return m, nil
	}
	var cmd tea.Cmd
	m.filter, cmd = m.filter.Update(msg)
	m.clampCursors()
	return m, cmd
}

func (m *model) updateEdit(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.editField = ""
		m.edit.Blur()
		return m, nil
	case "enter":
		v := strings.TrimSpace(m.edit.Value())
		switch m.editField {
		case "seed":
			m.seedText = v
		case "cewl":
			m.cewlURL = v
		case "device":
			m.options.Device = v
		}
		m.editField = ""
		m.edit.Blur()
		m.planDirty = true
		return m, nil
	}
	var cmd tea.Cmd
	m.edit, cmd = m.edit.Update(msg)
	return m, cmd
}

func (m *model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.MouseWheelUp:
		m.moveCursor(-3)
	case tea.MouseWheelDown:
		m.moveCursor(3)
	case tea.MouseLeft:
		row := msg.Y - 7
		if row < 0 {
			return m, nil
		}
		switch m.step {
		case stepTargets:
			if msg.X < m.width/3+4 {
				m.targetFocus = 0
				m.modeCursor = clamp(row-1, 0, len(m.inv.Modes)-1)
			} else {
				m.targetFocus = 1
				files := m.filteredHashFiles()
				start, _ := windowRange(m.hashCursor, len(files), m.pageSize()-1)
				m.hashCursor = clamp(start+row-1, 0, len(files)-1)
				m.toggleCurrent()
			}
		case stepWordlists:
			files := m.filteredWordlists()
			start, _ := windowRange(m.wordCursor, len(files), m.pageSize())
			m.wordCursor = clamp(start+row-1, 0, len(files)-1)
			m.toggleCurrent()
		case stepHome:
			procs := m.filteredProcessors()
			start, _ := windowRange(m.attCursor, len(procs), m.pageSize())
			m.attCursor = clamp(start+row-1, 0, len(procs)-1)
			m.toggleCurrent()
		}
	}
	return m, nil
}

func (m *model) nextStep() {
	if m.step == stepHome && m.selectedProcessorID() == "" {
		m.selectCurrentProcessor()
	}
	for s := m.step + 1; s <= stepQueue; s++ {
		if m.stepRelevant(s) {
			m.step = s
			break
		}
	}
	if m.step == stepQueue {
		m.rebuildPlan()
	}
}

func (m *model) prevStep() {
	for s := m.step - 1; s >= stepHome; s-- {
		if m.stepRelevant(s) {
			m.step = s
			break
		}
	}
}

func (m *model) moveCursor(delta int) {
	switch m.step {
	case stepHome:
		m.attCursor = clamp(m.attCursor+delta, 0, len(m.filteredProcessors())-1)
	case stepTargets:
		if m.targetFocus == 0 {
			m.modeCursor = clamp(m.modeCursor+delta, 0, len(m.inv.Modes)-1)
			m.hashCursor = 0
		} else {
			m.hashCursor = clamp(m.hashCursor+delta, 0, len(m.filteredHashFiles())-1)
		}
	case stepWordlists:
		m.wordCursor = clamp(m.wordCursor+delta, 0, len(m.filteredWordlists())-1)
	case stepOptions:
		m.optCursor = clamp(m.optCursor+delta, 0, len(m.optionRows())-1)
	case stepQueue:
		m.prevCursor = clamp(m.prevCursor+delta, 0, len(m.plan.Commands)-1)
	}
}

func (m *model) toggleCurrent() {
	switch m.step {
	case stepHome:
		m.selectCurrentProcessor()
	case stepTargets:
		if m.targetFocus == 0 {
			mode := m.currentMode()
			if len(m.selectedHashes[mode]) > 0 {
				delete(m.selectedHashes, mode)
			} else if files := m.filteredHashFiles(); len(files) > 0 {
				m.selectHash(mode, files[0])
			}
		} else {
			files := m.filteredHashFiles()
			if len(files) == 0 {
				return
			}
			m.toggleHash(m.currentMode(), files[m.hashCursor])
		}
	case stepWordlists:
		files := m.filteredWordlists()
		if len(files) == 0 {
			return
		}
		f := files[m.wordCursor]
		if m.selectedWordlists[f.Path].Path != "" {
			delete(m.selectedWordlists, f.Path)
		} else {
			m.selectedWordlists[f.Path] = f
		}
	case stepOptions:
		m.toggleOption()
	}
	m.planDirty = true
}

func (m *model) selectAllFiltered() {
	switch m.step {
	case stepTargets:
		for _, f := range m.filteredHashFiles() {
			m.selectHash(m.currentMode(), f)
		}
	case stepWordlists:
		for _, f := range m.filteredWordlists() {
			m.selectedWordlists[f.Path] = f
		}
	}
	m.planDirty = true
}

func (m *model) clearCurrentSelection() {
	switch m.step {
	case stepTargets:
		delete(m.selectedHashes, m.currentMode())
	case stepWordlists:
		m.selectedWordlists = map[string]scanner.FileRef{}
	case stepHome:
		m.selectedProcessors = map[string]bool{}
	}
	m.planDirty = true
}

func (m *model) toggleOption() {
	key := m.optionKey()
	switch key {
	case "loopback":
		m.options.Loopback = !m.options.Loopback
	case "kernel":
		m.options.Kernel = !m.options.Kernel
	case "hwmon":
		m.options.HwmonDisable = !m.options.HwmonDisable
	case "status":
		m.options.Status = !m.options.Status
	case "custom_increment":
		m.options.CustomIncrement = !m.options.CustomIncrement
	case "seed", "cewl", "device":
		m.beginEdit()
	}
	m.planDirty = true
}

func (m *model) adjustOption(delta int) {
	switch m.optionKey() {
	case "custom_chars":
		m.options.CustomChars = clamp(m.options.CustomChars+delta, 1, 99)
	case "markov_amount":
		m.options.MarkovAmount = clamp(m.options.MarkovAmount+delta*1000, 1000, 1000000)
	case "cewl_depth":
		m.options.CeWLDepth = clamp(m.options.CeWLDepth+delta, 1, 99)
	case "cewl_min":
		m.options.CeWLMinLength = clamp(m.options.CeWLMinLength+delta, 1, 99)
	}
	m.planDirty = true
}

func (m *model) beginEdit() {
	switch m.optionKey() {
	case "seed":
		m.editField = "seed"
		m.edit.SetValue(m.seedText)
	case "cewl":
		m.editField = "cewl"
		m.edit.SetValue(m.cewlURL)
	case "device":
		m.editField = "device"
		m.edit.SetValue(m.options.Device)
	default:
		return
	}
	m.edit.Focus()
	m.edit.CursorEnd()
}

type optionRowItem struct {
	key  string
	text string
}

func (m model) optionRows() []string {
	items := m.optionItems()
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.text)
	}
	return out
}

func (m model) optionItems() []optionRowItem {
	id := m.selectedProcessorID()
	items := []optionRowItem{
		{"loopback", boolRow("Loopback", m.options.Loopback, "--loopback on rule attacks")},
		{"kernel", boolRow("Optimized kernel", m.options.Kernel, "-O plus --bitmap-max=24")},
		{"hwmon", boolRow("Disable hwmon", m.options.HwmonDisable, "--hwmon-disable")},
		{"status", boolRow("Status card", m.options.Status, "--status --status-timer 10")},
		{"device", "Device filter: " + emptyValue(m.options.Device)},
	}
	if id == "21" {
		items = append(items,
			optionRowItem{"custom_chars", fmt.Sprintf("Custom brute chars: %d", m.options.CustomChars)},
			optionRowItem{"custom_increment", boolRow("Custom brute increment", m.options.CustomIncrement, "--increment")},
		)
	}
	if id == "17" {
		items = append(items, optionRowItem{"markov_amount", fmt.Sprintf("Markov amount: %d", m.options.MarkovAmount)})
	}
	if needsSeed(id) {
		items = append(items, optionRowItem{"seed", "Seed words: " + emptyValue(m.seedText)})
	}
	if id == "18" {
		items = append(items,
			optionRowItem{"cewl_depth", fmt.Sprintf("CeWL depth: %d", m.options.CeWLDepth)},
			optionRowItem{"cewl_min", fmt.Sprintf("CeWL min length: %d", m.options.CeWLMinLength)},
			optionRowItem{"cewl", "CeWL URL: " + emptyValue(m.cewlURL)},
		)
	}
	return items
}

func (m model) optionKey() string {
	items := m.optionItems()
	if len(items) == 0 {
		return ""
	}
	return items[clamp(m.optCursor, 0, len(items)-1)].key
}

func (m *model) rebuildPlan() {
	hashes := map[int][]scanner.FileRef{}
	for mode, set := range m.selectedHashes {
		for _, f := range set {
			hashes[mode] = append(hashes[mode], f)
		}
		sort.Slice(hashes[mode], func(i, j int) bool { return hashes[mode][i].Rel < hashes[mode][j].Rel })
	}
	wordlists := make([]scanner.FileRef, 0, len(m.selectedWordlists))
	for _, f := range m.selectedWordlists {
		wordlists = append(wordlists, f)
	}
	sort.Slice(wordlists, func(i, j int) bool { return wordlists[i].Rel < wordlists[j].Rel })

	procs := make([]string, 0, len(m.selectedProcessors))
	for id := range m.selectedProcessors {
		procs = append(procs, id)
	}
	sort.Slice(procs, func(i, j int) bool {
		return processorOrder(procs[i]) < processorOrder(procs[j])
	})

	m.plan = planner.Build(planner.Selection{
		Config:     m.cfg,
		Hashes:     hashes,
		Wordlists:  wordlists,
		Rules:      m.inv.Rules,
		Processors: procs,
		Options:    m.options,
		SeedWords:  splitWords(m.seedText),
		CeWLURL:    m.cewlURL,
		TempDir:    m.tempDir,
	})
	m.planDirty = false
	m.prevCursor = clamp(m.prevCursor, 0, len(m.plan.Commands)-1)
}

func (m *model) selectHash(mode int, f scanner.FileRef) {
	if m.selectedHashes[mode] == nil {
		m.selectedHashes[mode] = map[string]scanner.FileRef{}
	}
	m.selectedHashes[mode][f.Path] = f
}

func (m *model) toggleHash(mode int, f scanner.FileRef) {
	if m.selectedHashes[mode] == nil {
		m.selectedHashes[mode] = map[string]scanner.FileRef{}
	}
	if m.selectedHashes[mode][f.Path].Path != "" {
		delete(m.selectedHashes[mode], f.Path)
		if len(m.selectedHashes[mode]) == 0 {
			delete(m.selectedHashes, mode)
		}
	} else {
		m.selectedHashes[mode][f.Path] = f
	}
}

func (m model) currentMode() int {
	if len(m.inv.Modes) == 0 {
		return m.cfg.Mode
	}
	return m.inv.Modes[clamp(m.modeCursor, 0, len(m.inv.Modes)-1)].Mode
}

func (m model) filteredHashFiles() []scanner.FileRef {
	if len(m.inv.Modes) == 0 {
		return nil
	}
	files := m.inv.Modes[clamp(m.modeCursor, 0, len(m.inv.Modes)-1)].Files
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	if q == "" {
		return files
	}
	var out []scanner.FileRef
	for _, f := range files {
		if strings.Contains(strings.ToLower(f.Rel), q) {
			out = append(out, f)
		}
	}
	return out
}

func (m model) filteredWordlists() []scanner.FileRef {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	if q == "" {
		return m.inv.Wordlists
	}
	var out []scanner.FileRef
	for _, f := range m.inv.Wordlists {
		if strings.Contains(strings.ToLower(f.Rel), q) {
			out = append(out, f)
		}
	}
	return out
}

func (m model) filteredProcessors() []planner.Processor {
	q := strings.ToLower(strings.TrimSpace(m.filter.Value()))
	if q == "" {
		return m.processors
	}
	var out []planner.Processor
	for _, p := range m.processors {
		hay := strings.ToLower(p.ID + " " + p.Name + " " + p.Source + " " + p.Description)
		if strings.Contains(hay, q) {
			out = append(out, p)
		}
	}
	return out
}

func (m *model) clampCursors() {
	m.hashCursor = clamp(m.hashCursor, 0, len(m.filteredHashFiles())-1)
	m.wordCursor = clamp(m.wordCursor, 0, len(m.filteredWordlists())-1)
	m.attCursor = clamp(m.attCursor, 0, len(m.filteredProcessors())-1)
}

func (m model) selectedHashCount() int {
	total := 0
	for _, set := range m.selectedHashes {
		total += len(set)
	}
	return total
}

func (m *model) selectCurrentProcessor() {
	procs := m.filteredProcessors()
	if len(procs) == 0 {
		return
	}
	p := procs[clamp(m.attCursor, 0, len(procs)-1)]
	m.selectedProcessors = map[string]bool{p.ID: true}
	m.optCursor = 0
	m.planDirty = true
}

func (m model) selectedProcessorID() string {
	var ids []string
	for id := range m.selectedProcessors {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return processorOrder(ids[i]) < processorOrder(ids[j]) })
	if len(ids) == 0 {
		return ""
	}
	return ids[0]
}

func (m model) selectedProcessorName() string {
	id := m.selectedProcessorID()
	if id == "" {
		return ""
	}
	for _, p := range m.processors {
		if p.ID == id {
			return p.ID + " " + p.Name
		}
	}
	return id
}

func (m model) requirementLines(id string) []string {
	var lines []string
	if needsHashes(id) {
		lines = append(lines, fmt.Sprintf("[ ] Hash targets  %d selected", m.selectedHashCount()))
	}
	if needsWordlists(id) {
		lines = append(lines, fmt.Sprintf("[ ] Wordlists  %d selected", len(m.selectedWordlists)))
	}
	if needsSeed(id) {
		lines = append(lines, "[ ] Seed words  "+plainEmpty(m.seedText))
	}
	if id == "18" {
		lines = append(lines, "[ ] CeWL URL  "+plainEmpty(m.cewlURL))
	}
	lines = append(lines, "[ ] Options  status, device, kernel, output")
	lines = append(lines, "[ ] Preview and run queue")
	return lines
}

func (m model) stepRelevant(step int) bool {
	id := m.selectedProcessorID()
	switch step {
	case stepHome:
		return true
	case stepTargets:
		return needsHashes(id)
	case stepWordlists:
		return needsWordlists(id)
	case stepOptions:
		return id != ""
	case stepQueue:
		return id != ""
	default:
		return false
	}
}

func needsHashes(id string) bool {
	return id != "" && id != "18"
}

func needsWordlists(id string) bool {
	switch id {
	case "2", "3", "6", "7", "8", "12", "15", "17", "20", "22", "A", "H":
		return true
	default:
		return false
	}
}

func needsSeed(id string) bool {
	return id == "4" || id == "5"
}

func plainEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(empty)"
	}
	return s
}

func panelTitle(s string, active bool) string {
	if active {
		return activeStyle.Render(s)
	}
	return mutedStyle.Render(s)
}

func checkboxLine(cursor, selected bool, main, detail string, width int) string {
	box := "[ ]"
	if selected {
		box = "[" + okStyle.Render("x") + "]"
	}
	prefix := "  "
	if cursor {
		prefix = "> "
		line := truncate(fmt.Sprintf("%s%s %s  %s", prefix, box, main, detail), width)
		return highlightStyle.Render(line)
	}
	return truncate(fmt.Sprintf("%s%s %s  %s", prefix, box, main, detail), width)
}

func boolRow(label string, v bool, hint string) string {
	state := "[ ]"
	if v {
		state = "[" + okStyle.Render("x") + "]"
	}
	return fmt.Sprintf("%s %s  %s", state, label, mutedStyle.Render(hint))
}

func colorStatusLine(line string) string {
	if idx := strings.Index(line, ":"); idx > 0 {
		label := line[:idx+1]
		value := strings.TrimSpace(line[idx+1:])
		return activeStyle.Render(label) + " " + valueStyle.Render(value)
	}
	return line
}

func colorCrackLine(line string) string {
	line = strings.TrimSpace(line)
	prefix := ""
	if strings.HasPrefix(line, "* ") {
		prefix = okStyle.Render("*") + " "
		line = strings.TrimSpace(strings.TrimPrefix(line, "* "))
	}
	if idx := strings.LastIndex(line, ":"); idx > 0 && idx+1 < len(line) {
		hash := line[:idx]
		plain := line[idx+1:]
		return prefix + hashStyle.Render(hash) + mutedStyle.Render(":") + plainStyle.Render(plain)
	}
	return prefix + plainStyle.Render(line)
}

func emptyValue(s string) string {
	if strings.TrimSpace(s) == "" {
		return mutedStyle.Render("(empty)")
	}
	return s
}

func windowRange(cursor, total, size int) (int, int) {
	if total <= 0 {
		return 0, 0
	}
	if size <= 0 {
		size = 1
	}
	start := cursor - size/2
	if start < 0 {
		start = 0
	}
	if start+size > total {
		start = max(0, total-size)
	}
	end := min(total, start+size)
	return start, end
}

func fitLines(lines []string, height int) []string {
	if height <= 0 {
		return nil
	}
	if len(lines) <= height {
		return lines
	}
	return lines[:height]
}

func waitEvent(ch <-chan runner.Event) tea.Cmd {
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return runMsg{Done: true}
		}
		return runMsg(ev)
	}
}

func splitWords(s string) []string {
	return strings.Fields(s)
}

func processorOrder(id string) int {
	if n, err := strconv.Atoi(id); err == nil {
		return n
	}
	if id == "A" {
		return 100
	}
	if id == "H" {
		return 101
	}
	return 999
}

func truncate(s string, width int) string {
	if width <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 1 {
		return string(r[:width])
	}
	return string(r[:width-1]) + "..."
}

func appendWrapped(dst *[]string, s string, width int) {
	for _, line := range wrapLine(s, width) {
		*dst = append(*dst, line)
	}
}

func wrapLine(s string, width int) []string {
	if width <= 0 {
		return []string{""}
	}
	runes := []rune(s)
	if len(runes) == 0 {
		return []string{""}
	}
	var out []string
	for len(runes) > width {
		cut := width
		for i := min(width, len(runes)) - 1; i > 0; i-- {
			if runes[i] == ' ' {
				cut = i + 1
				break
			}
		}
		out = append(out, strings.TrimRight(string(runes[:cut]), " "))
		runes = runes[cut:]
		for len(runes) > 0 && runes[0] == ' ' {
			runes = runes[1:]
		}
	}
	out = append(out, string(runes))
	return out
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
