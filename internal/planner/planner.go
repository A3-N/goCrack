package planner

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"gocrack/internal/config"
	"gocrack/internal/scanner"
)

type Options struct {
	Loopback        bool
	Kernel          bool
	HwmonDisable    bool
	Status          bool
	Device          string
	CustomChars     int
	CustomIncrement bool
	MarkovNGram     int
	MarkovAmount    int
	CeWLDepth       int
	CeWLMinLength   int
}

type Selection struct {
	Config     config.Settings
	Hashes     map[int][]scanner.FileRef
	Wordlists  []scanner.FileRef
	Rules      []scanner.RuleRef
	Processors []string
	Options    Options
	SeedWords  []string
	CeWLURL    string
	TempDir    string
}

type Plan struct {
	Commands []Command
	Warnings []string
}

type Command struct {
	Exe       string
	Args      []string
	Label     string
	Processor string
	Mode      int
	Hashlist  string
	Potfile   string
}

type Processor struct {
	ID          string
	Name        string
	Source      string
	Description string
	Targetless  bool
	Build       func(*Context) ([]Command, error)
}

type Context struct {
	Config    config.Settings
	Mode      int
	Hashlist  string
	HashFiles []scanner.FileRef
	Wordlists []scanner.FileRef
	Rules     []scanner.RuleRef
	Options   Options
	SeedWords []string
	CeWLURL   string
	TempDir   string
}

func Catalog() []Processor {
	return []Processor{
		{"1", "Bruteforce masks", "SensePost 1-bruteforce.sh", "Common incremental mask attacks.", false, buildBruteforce},
		{"2", "Light rules", "SensePost 2-light.sh", "Straight wordlist plus fast rule bundle.", false, buildLight},
		{"3", "Heavy rules", "SensePost 3-heavy.sh", "Straight wordlist plus heavier rule bundle.", false, buildHeavy},
		{"4", "Seed word rules", "SensePost 4-word.sh", "Typed seed words through heavy word rules.", false, buildSeedRules},
		{"5", "Seed word hybrid", "SensePost 5-word-bruteforce.sh", "Append/prepend masks around typed seed words.", false, buildSeedHybrid},
		{"6", "Hybrid masks", "SensePost 6-hybrid.sh", "Wordlist hybrid append masks with optional capitalization.", false, buildHybrid},
		{"7", "Toggle stack", "SensePost 7-toggle.sh", "Stack toggle rules with light follow-up rules.", false, buildToggle},
		{"8", "Combinator", "SensePost 8-combinator.sh", "Pair selected wordlists with hashcat -a1.", false, buildCombinator},
		{"9", "Potfile iterate", "SensePost 9-iterate.sh", "Recycle cracked potfile words through iterate rules.", false, buildIterate},
		{"10", "Prefix/suffix", "SensePost 10-prefixsuffix.sh", "Mine potfile prefixes/suffixes and combine them both ways.", false, buildPrefixSuffix},
		{"11", "Common substrings", "SensePost 11-commonsubstring.sh", "Mine common potfile substrings and combinator them.", false, buildCommonSubstring},
		{"12", "Adaptive rulegen", "SensePost 12-pack-rule.sh", "Generate a compact analysis.rule from observed potfile endings.", false, buildAdaptiveRule},
		{"13", "Adaptive masks", "SensePost 13-pack-mask.sh", "Generate masks from observed potfile character classes.", false, buildAdaptiveMasks},
		{"14", "Fingerprint", "SensePost 14-fingerprint.sh", "Expand cracked words into reusable tokens and combine them.", false, buildFingerprint},
		{"15", "Multi wordlists", "SensePost 15-multiple-wordlists.sh", "Selected wordlists straight and with ORTRTS.", false, buildMultiWordlists},
		{"16", "Username as password", "SensePost 16-usernameaspassword.sh", "Extract usernames from hash files and run broad rules.", false, buildUsername},
		{"17", "Markov generator", "SensePost 17-markov-generator.sh", "Generate candidates from selected wordlists or potfile with a local Markov model.", false, buildMarkov},
		{"18", "CeWL wordlist", "SensePost 18-cewl.sh", "Run external cewl to create a site wordlist when a URL is configured.", true, buildCeWL},
		{"19", "Digit remover", "SensePost 19-digitremover.sh", "Strip digits from potfile words, then hybrid/rule them.", false, buildDigitRemover},
		{"20", "Rule stacker", "SensePost 20-stacker.sh", "Stack stacking58 with itself and light rules.", false, buildStacker},
		{"21", "Custom bruteforce", "SensePost 21-custom-brute-force.sh", "Configurable ?a mask length with optional increment.", false, buildCustomBrute},
		{"22", "Buka multi wordlists", "SensePost 22-multiple-wordlists-buka.sh", "Selected wordlists straight and with buka_400k.", false, buildBuka},
		{"A", "All discovered rules", "goCrack", "Sweep every .rule file found under rules recursively.", false, buildAllRules},
		{"H", "Hybrid rule folder", "goCrack", "Sweep every .rule file under rules/hybrid.", false, buildHybridRules},
	}
}

func DefaultTempDir() string {
	return filepath.Join(os.TempDir(), "goCrack")
}

func Build(sel Selection) Plan {
	if sel.TempDir == "" {
		sel.TempDir = DefaultTempDir()
	}
	_ = os.MkdirAll(sel.TempDir, 0755)

	lookup := map[string]Processor{}
	for _, p := range Catalog() {
		lookup[p.ID] = p
	}

	var plan Plan
	seenTargetless := map[string]bool{}
	for _, id := range sel.Processors {
		p, ok := lookup[id]
		if !ok {
			plan.Warnings = append(plan.Warnings, "unknown processor "+id)
			continue
		}
		if !p.Targetless || seenTargetless[id] {
			continue
		}
		seenTargetless[id] = true
		ctx := &Context{
			Config:    sel.Config,
			Mode:      sel.Config.Mode,
			Wordlists: sel.Wordlists,
			Rules:     sel.Rules,
			Options:   sel.Options,
			SeedWords: sel.SeedWords,
			CeWLURL:   sel.CeWLURL,
			TempDir:   sel.TempDir,
		}
		cmds, err := p.Build(ctx)
		if err != nil {
			plan.Warnings = append(plan.Warnings, p.Name+": "+err.Error())
			continue
		}
		plan.Commands = append(plan.Commands, cmds...)
	}

	modes := make([]int, 0, len(sel.Hashes))
	for mode := range sel.Hashes {
		modes = append(modes, mode)
	}
	sort.Ints(modes)

	for _, mode := range modes {
		files := sel.Hashes[mode]
		if len(files) == 0 {
			continue
		}
		hashTarget, err := hashTarget(sel.TempDir, mode, files)
		if err != nil {
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("mode %d: %v", mode, err))
			continue
		}
		for _, id := range sel.Processors {
			p, ok := lookup[id]
			if !ok || p.Targetless {
				continue
			}
			ctx := &Context{
				Config:    sel.Config,
				Mode:      mode,
				Hashlist:  hashTarget,
				HashFiles: files,
				Wordlists: sel.Wordlists,
				Rules:     sel.Rules,
				Options:   sel.Options,
				SeedWords: sel.SeedWords,
				CeWLURL:   sel.CeWLURL,
				TempDir:   sel.TempDir,
			}
			cmds, err := p.Build(ctx)
			if err != nil {
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s mode %d: %v", p.Name, mode, err))
				continue
			}
			plan.Commands = append(plan.Commands, cmds...)
		}
	}
	if len(modes) == 0 {
		plan.Warnings = append(plan.Warnings, "no hash files selected")
	}
	return plan
}

func hashTarget(tempDir string, mode int, files []scanner.FileRef) (string, error) {
	if len(files) == 1 {
		return files[0].Path, nil
	}
	h := sha1.New()
	h.Write([]byte(strconv.Itoa(mode)))
	h.Write([]byte{0})
	for _, f := range files {
		h.Write([]byte(f.Path))
		h.Write([]byte{0})
	}
	outDir := filepath.Join(tempDir, "hashes")
	out := filepath.Join(outDir, fmt.Sprintf("goCrack-combined-m%d-%x.hashes", mode, h.Sum(nil)[:6]))
	return out, scanner.CombineHashFiles(out, mode, files)
}

func buildBruteforce(ctx *Context) ([]Command, error) {
	masks := [][]string{
		{"?a?a?a?a?a"},
		{"?l?l?l?l?l?l?l?l"},
		{"?u?u?u?u?u?u?u?u"},
		{"?d?d?d?d?d?d?d?d?d?d"},
		{"?1?1?1?1?1?1?d?d", "-1", "?l?d?u"},
		{"?1?1?1?1?2?2?2?2?a", "-1", "?l?u", "-2", "?d"},
		{"?1?1?1?1?2?2?2?2", "-1", "?d", "-2", "?l?u"},
		{"?l?l?l?l?l?d?d?d?d"},
		{"?u?u?u?u?u?d?d?d?d"},
		{"?l?l?l?l?l?l?d?d?d"},
		{"?u?u?u?u?u?u?d?d?d"},
		{"?d?d?d?d?d?l?l?l?l"},
		{"?d?d?d?d?d?u?u?u?u"},
		{"?l?l?d?d?d?d?d?d?d"},
		{"?u?u?d?d?d?d?d?d?d"},
		{"?l?l?d?d?d?d?l?l"},
		{"?u?u?d?d?d?d?u?u"},
		{"?l?d?d?l?d?d?l?d?d"},
		{"?u?d?d?u?d?d?u?d?d"},
		{"?d?d?d?d?d?d?d?d?l?l"},
		{"?d?d?d?d?d?d?d?d?u?u"},
		{"?d?d?l?d?d?l?d?d?l"},
		{"?d?d?u?d?d?u?d?d?u"},
	}
	var cmds []Command
	for i, mask := range masks {
		args := append(baseArgs(ctx), "-a3")
		args = append(args, mask...)
		args = append(args, "--increment")
		cmds = append(cmds, hc(ctx, "Bruteforce mask "+strconv.Itoa(i+1), "1", args))
	}
	return cmds, nil
}

func buildLight(ctx *Context) ([]Command, error) {
	return ruleSweep(ctx, "2", "Light rules", []string{"rule3", "rockyou30000", "ORTRTS", "fbtop", "TOXICSP", "passwordpro", "d3ad0ne", "d3adhob0", "generated2", "toprules2020", "digits1", "digits2", "hob064", "leetspeak", "toggles1", "toggles2"}, true)
}

func buildHeavy(ctx *Context) ([]Command, error) {
	return ruleSweep(ctx, "3", "Heavy rules", []string{"hashmob150", "tenKrules", "fbfull", "NSAKEYv2", "fordyv1", "pantag", "OUTD", "techtrip2", "williamsuper", "digits3", "dive", "robotmyfavorite"}, true)
}

func buildSeedRules(ctx *Context) ([]Command, error) {
	seed, err := seedFile(ctx)
	if err != nil {
		return nil, err
	}
	rules := pickRules(ctx.Rules, []string{"tenKrules", "NSAKEYv2", "fordyv1", "pantag", "OUTD", "techtrip2", "williamsuper", "digits3", "dive"})
	if len(rules) == 0 {
		return nil, fmt.Errorf("no seed word rules found")
	}
	var cmds []Command
	for _, rule := range rules {
		args := append(baseArgs(ctx), seed, "-r", rule.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "Seed rules: "+rule.Name, "4", args))
	}
	return cmds, nil
}

func buildSeedHybrid(ctx *Context) ([]Command, error) {
	seed, err := seedFile(ctx)
	if err != nil {
		return nil, err
	}
	patterns := [][]string{
		{"-a6", seed, "?d?d?d?d?d?d?d?d", "-i"},
		{"-a6", seed, "?l?l?l?l?l?l", "-i"},
		{"-a7", "?d?d?d?d?d?d?d?d", seed, "-i"},
		{"-a7", "?l?l?l?l?l?l", seed, "-i"},
		{"-a6", seed, "?a?a?a?a?a", "-i"},
		{"-a7", "?a?a?a?a?a", seed, "-i"},
	}
	var cmds []Command
	for i, p := range patterns {
		args := append(baseArgs(ctx), p...)
		cmds = append(cmds, hc(ctx, "Seed hybrid "+strconv.Itoa(i+1), "5", args))
	}
	return cmds, nil
}

func buildHybrid(ctx *Context) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	patterns := [][]string{
		append([]string{"-a6"}, append(wls, "-j", "c", "?s?d?d?d?d", "--increment")...),
		append([]string{"-a6"}, append(wls, "-j", "c", "?d?d?d?d?s", "--increment")...),
		append([]string{"-a6"}, append(wls, "-j", "c", "?a?a", "--increment")...),
		append([]string{"-a6"}, append(wls, "?s?d?d?d?d", "--increment")...),
		append([]string{"-a6"}, append(wls, "?d?d?d?d?s", "--increment")...),
		append([]string{"-a6"}, append(wls, "?a?a", "--increment")...),
	}
	var cmds []Command
	for i, p := range patterns {
		args := append(baseArgs(ctx), p...)
		cmds = append(cmds, hc(ctx, "Hybrid mask "+strconv.Itoa(i+1), "6", args))
	}
	return cmds, nil
}

func buildToggle(ctx *Context) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	toggles := pickRules(ctx.Rules, []string{"toggles1", "toggles2"})
	rules := pickRules(ctx.Rules, []string{"rockyou30000", "ORTRTS", "OUTD", "passwordpro", "d3ad0ne", "d3adhob0", "generated2", "toprules2020", "digits1", "digits2", "hob064", "leetspeak", "toggles1", "toggles2"})
	if len(toggles) == 0 || len(rules) == 0 {
		return nil, fmt.Errorf("toggle or follow-up rules not found")
	}
	var cmds []Command
	for _, t := range toggles {
		for _, r := range rules {
			args := append(baseArgs(ctx), wls...)
			args = append(args, "-r", t.Path, "-r", r.Path)
			args = appendLoopback(ctx, args)
			cmds = append(cmds, hc(ctx, "Toggle "+t.Name+" + "+r.Name, "7", args))
		}
	}
	return cmds, nil
}

func buildCombinator(ctx *Context) ([]Command, error) {
	if len(ctx.Wordlists) < 2 {
		return nil, fmt.Errorf("select at least two wordlists")
	}
	var cmds []Command
	limit := 0
	for i := 0; i < len(ctx.Wordlists); i++ {
		for j := i + 1; j < len(ctx.Wordlists); j++ {
			args := append(baseArgs(ctx), "-a1", ctx.Wordlists[i].Path, ctx.Wordlists[j].Path)
			cmds = append(cmds, hc(ctx, "Combinator "+ctx.Wordlists[i].Name+" + "+ctx.Wordlists[j].Name, "8", args))
			limit++
			if limit >= 20 {
				return cmds, nil
			}
		}
	}
	return cmds, nil
}

func buildIterate(ctx *Context) ([]Command, error) {
	words, err := potWordsFile(ctx, "pot-iterate.txt", transformNone, 500000)
	if err != nil {
		return nil, err
	}
	rules := pickRules(ctx.Rules, []string{"rule3", "robotmyfavorite", "fbfull", "tenKrules", "NSAKEYv2", "fordyv1", "pantag", "OUTD", "TOXICSP", "techtrip2", "williamsuper", "digits3", "dive", "TOXIC10k", "big", "generated3", "huge"})
	if len(rules) == 0 {
		return nil, fmt.Errorf("iterate rules not found")
	}
	var cmds []Command
	for _, r := range rules {
		args := append(baseArgs(ctx), words, "-r", r.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "Iterate "+r.Name, "9", args))
	}
	return cmds, nil
}

func buildPrefixSuffix(ctx *Context) ([]Command, error) {
	prefix, suffix, err := prefixSuffixFiles(ctx)
	if err != nil {
		return nil, err
	}
	return []Command{
		hc(ctx, "Prefix + suffix", "10", append(baseArgs(ctx), "-a1", prefix, suffix)),
		hc(ctx, "Suffix + prefix", "10", append(baseArgs(ctx), "-a1", suffix, prefix)),
	}, nil
}

func buildCommonSubstring(ctx *Context) ([]Command, error) {
	sub, err := substringFile(ctx)
	if err != nil {
		return nil, err
	}
	return []Command{hc(ctx, "Common substring combinator", "11", append(baseArgs(ctx), "-a1", sub, sub))}, nil
}

func buildAdaptiveRule(ctx *Context) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	rule, err := adaptiveRuleFile(ctx)
	if err != nil {
		return nil, err
	}
	args := append(baseArgs(ctx), wls...)
	args = append(args, "-r", rule)
	args = appendLoopback(ctx, args)
	return []Command{hc(ctx, "Adaptive generated rule", "12", args)}, nil
}

func buildAdaptiveMasks(ctx *Context) ([]Command, error) {
	mask, err := adaptiveMaskFile(ctx)
	if err != nil {
		return nil, err
	}
	return []Command{hc(ctx, "Adaptive generated masks", "13", append(baseArgs(ctx), "-a3", mask))}, nil
}

func buildFingerprint(ctx *Context) ([]Command, error) {
	fp, err := fingerprintFile(ctx)
	if err != nil {
		return nil, err
	}
	return []Command{hc(ctx, "Fingerprint combinator", "14", append(baseArgs(ctx), "-a1", fp, fp))}, nil
}

func buildMultiWordlists(ctx *Context) ([]Command, error) {
	return ruleSweep(ctx, "15", "Multi wordlists", []string{"ORTRTS"}, true)
}

func buildUsername(ctx *Context) ([]Command, error) {
	userFile, err := usernameFile(ctx)
	if err != nil {
		return nil, err
	}
	rules := pickRules(ctx.Rules, []string{"big", "fbfull", "d3ad0ne", "d3adhob0", "digits1", "digits2", "digits3", "dive", "fordyv1", "generated2", "generated3", "hob064", "huge", "leetspeak", "NSAKEYv2", "ORTRTS", "OUTD", "pantag", "passwordpro", "rockyou30000", "techtrip2", "tenKrules", "toggles1", "toggles2", "toprules2020", "TOXIC10k", "TOXICSP", "williamsuper"})
	var cmds []Command
	cmds = append(cmds, hc(ctx, "Username straight", "16", append(baseArgs(ctx), userFile)))
	for _, r := range rules {
		args := append(baseArgs(ctx), userFile, "-r", r.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "Username "+r.Name, "16", args))
	}
	return cmds, nil
}

func buildMarkov(ctx *Context) ([]Command, error) {
	out := filepath.Join(ctx.TempDir, "markov-generated.txt")
	var inputs []string
	for _, wl := range ctx.Wordlists {
		inputs = append(inputs, wl.Path)
	}
	if len(inputs) == 0 && ctx.Config.Potfile != "" {
		inputs = append(inputs, ctx.Config.Potfile)
	}
	if len(inputs) == 0 {
		return nil, fmt.Errorf("select a wordlist or configure a potfile")
	}
	amount := ctx.Options.MarkovAmount
	if amount <= 0 {
		amount = 5000
	}
	if err := generateMarkov(inputs, out, amount); err != nil {
		return nil, err
	}
	rules := pickRules(ctx.Rules, []string{"rule3", "rockyou30000", "ORTRTS", "fbfull", "pantag", "OUTD", "techtrip2", "TOXICSP", "passwordpro", "d3ad0ne", "d3adhob0", "generated2", "toprules2020", "hob064", "leetspeak"})
	var cmds []Command
	cmds = append(cmds, hc(ctx, "Markov straight", "17", append(baseArgs(ctx), out)))
	for _, r := range rules {
		args := append(baseArgs(ctx), out, "-r", r.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "Markov "+r.Name, "17", args))
	}
	return cmds, nil
}

func buildCeWL(ctx *Context) ([]Command, error) {
	if strings.TrimSpace(ctx.CeWLURL) == "" {
		return nil, fmt.Errorf("set CeWL URL in options")
	}
	if strings.TrimSpace(ctx.Config.CeWLExe) == "" {
		return nil, fmt.Errorf("cewl binary is not configured")
	}
	depth := ctx.Options.CeWLDepth
	if depth <= 0 {
		depth = 2
	}
	minLen := ctx.Options.CeWLMinLength
	if minLen <= 0 {
		minLen = 5
	}
	host := sanitizeName(ctx.CeWLURL)
	out := filepath.Join(ctx.Config.Wordlists, "cewl-"+host+".txt")
	args := []string{"-d", strconv.Itoa(depth), "-m", strconv.Itoa(minLen), "-w", out, ctx.CeWLURL, "-u", "Mozilla/5.0"}
	return []Command{{Exe: ctx.Config.CeWLExe, Args: args, Label: "CeWL -> " + out, Processor: "18"}}, nil
}

func buildDigitRemover(ctx *Context) ([]Command, error) {
	words, err := potWordsFile(ctx, "pot-nodigits.txt", stripDigits, 500000)
	if err != nil {
		return nil, err
	}
	rules := pickRules(ctx.Rules, []string{"fbfull", "ORTRTS", "NSAKEYv2", "techtrip2"})
	patterns := [][]string{
		{"-a6", words, "-j", "c", "?s?d?d?d?d", "--increment"},
		{"-a6", words, "-j", "c", "?d?d?d?d?s", "--increment"},
		{"-a6", words, "-j", "c", "?a?a", "--increment"},
		{"-a6", words, "?s?d?d?d?d", "--increment"},
		{"-a6", words, "?d?d?d?d?s", "--increment"},
		{"-a6", words, "?a?a", "--increment"},
	}
	var cmds []Command
	for i, p := range patterns {
		cmds = append(cmds, hc(ctx, "Digit remover hybrid "+strconv.Itoa(i+1), "19", append(baseArgs(ctx), p...)))
	}
	for _, r := range rules {
		args := append(baseArgs(ctx), words, "-r", r.Path)
		cmds = append(cmds, hc(ctx, "Digit remover "+r.Name, "19", args))
	}
	return cmds, nil
}

func buildStacker(ctx *Context) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	stack := pickRules(ctx.Rules, []string{"stacking58"})
	rules := pickRules(ctx.Rules, []string{"rule3", "fbtop", "toprules2020", "digits1", "digits2", "hob064", "leetspeak", "toggles1", "toggles2", "OUTD"})
	if len(stack) == 0 {
		return nil, fmt.Errorf("stacking58.rule not found")
	}
	var cmds []Command
	args := append(baseArgs(ctx), wls...)
	args = append(args, "-r", stack[0].Path, "-r", stack[0].Path)
	args = appendLoopback(ctx, args)
	cmds = append(cmds, hc(ctx, "Stacking58 twice", "20", args))
	for _, r := range rules {
		args := append(baseArgs(ctx), wls...)
		args = append(args, "-r", stack[0].Path, "-r", r.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "Stacking58 + "+r.Name, "20", args))
	}
	return cmds, nil
}

func buildCustomBrute(ctx *Context) ([]Command, error) {
	chars := ctx.Options.CustomChars
	if chars <= 0 {
		chars = 6
	}
	if chars > 99 {
		chars = 99
	}
	mask := strings.Repeat("?a", chars)
	args := append(baseArgs(ctx), "-a3", mask)
	if ctx.Options.CustomIncrement {
		args = append(args, "--increment")
	}
	return []Command{hc(ctx, "Custom brute "+mask, "21", args)}, nil
}

func buildBuka(ctx *Context) ([]Command, error) {
	return ruleSweep(ctx, "22", "Buka", []string{"buka"}, true)
}

func buildAllRules(ctx *Context) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	if len(ctx.Rules) == 0 {
		return nil, fmt.Errorf("no .rule files discovered")
	}
	var cmds []Command
	cmds = append(cmds, hc(ctx, "All rules straight", "A", append(baseArgs(ctx), wls...)))
	for _, r := range ctx.Rules {
		args := append(baseArgs(ctx), wls...)
		args = append(args, "-r", r.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "All rules: "+r.Rel, "A", args))
	}
	return cmds, nil
}

func buildHybridRules(ctx *Context) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	var rules []scanner.RuleRef
	for _, r := range ctx.Rules {
		if strings.EqualFold(r.Group, "hybrid") || strings.Contains(strings.ToLower(r.Rel), "hybrid") {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules found under rules/hybrid")
	}
	var cmds []Command
	for _, r := range rules {
		args := append(baseArgs(ctx), wls...)
		args = append(args, "-r", r.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, "Hybrid rule: "+r.Name, "H", args))
	}
	return cmds, nil
}

func ruleSweep(ctx *Context, proc, label string, aliases []string, includeStraight bool) ([]Command, error) {
	wls, err := wordlistPaths(ctx)
	if err != nil {
		return nil, err
	}
	rules := pickRules(ctx.Rules, aliases)
	if len(rules) == 0 {
		return nil, fmt.Errorf("no matching rules found")
	}
	var cmds []Command
	if includeStraight {
		cmds = append(cmds, hc(ctx, label+" straight", proc, append(baseArgs(ctx), wls...)))
	}
	for _, rule := range rules {
		args := append(baseArgs(ctx), wls...)
		args = append(args, "-r", rule.Path)
		args = appendLoopback(ctx, args)
		cmds = append(cmds, hc(ctx, label+": "+rule.Name, proc, args))
	}
	return cmds, nil
}

func baseArgs(ctx *Context) []string {
	var args []string
	if ctx.Options.Kernel {
		args = append(args, "-O", "--bitmap-max=24")
	}
	if strings.TrimSpace(ctx.Options.Device) != "" {
		args = append(args, "-d", strings.TrimSpace(ctx.Options.Device))
	}
	if ctx.Options.HwmonDisable {
		args = append(args, "--hwmon-disable")
	}
	if ctx.Config.Potfile != "" {
		args = append(args, "--potfile-path", ctx.Config.Potfile)
	}
	if ctx.Options.Status {
		args = append(args, "--status", "--status-timer", "10")
	}
	args = append(args, "-m", strconv.Itoa(ctx.Mode), ctx.Hashlist)
	return args
}

func hc(ctx *Context, label, proc string, args []string) Command {
	return Command{
		Exe:       ctx.Config.HashcatExe,
		Args:      compact(args),
		Label:     label,
		Processor: proc,
		Mode:      ctx.Mode,
		Hashlist:  ctx.Hashlist,
		Potfile:   ctx.Config.Potfile,
	}
}

func appendLoopback(ctx *Context, args []string) []string {
	if ctx.Options.Loopback {
		return append(args, "--loopback")
	}
	return args
}

func compact(in []string) []string {
	out := in[:0]
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func wordlistPaths(ctx *Context) ([]string, error) {
	if len(ctx.Wordlists) == 0 {
		return nil, fmt.Errorf("select at least one wordlist")
	}
	out := make([]string, 0, len(ctx.Wordlists))
	for _, w := range ctx.Wordlists {
		out = append(out, w.Path)
	}
	return out, nil
}

func pickRules(rules []scanner.RuleRef, aliases []string) []scanner.RuleRef {
	aliasToFile := map[string]string{
		"big": "1big.rule", "buka": "buka_400k.rule", "d3ad0ne": "d3ad0ne.rule", "d3adhob0": "d3adhob0.rule",
		"digits1": "digits1.rule", "digits2": "digits2.rule", "digits3": "digits3.rule", "dive": "dive.rule",
		"fbfull": "facebook-firstnames-capital.rule", "fbtop": "facebook-firstnames-capital-top.rule", "fordyv1": "fordyv1.rule",
		"generated2": "generated2.rule", "generated3": "generated3.rule", "hob064": "hob064.rule", "huge": "huge.rule",
		"leetspeak": "leetspeak.rule", "NSAKEYv2": "NSAKEY.v2.dive.rule", "ORTRTA": "OneRuleToRuleThemAll.rule",
		"ORTRTS": "OneRuleToRuleThemStill.rule", "OUTD": "OptimizedUpToDate.rule", "pantag": "pantagrule.popular.rule",
		"passwordpro": "passwordspro.rule", "robotmyfavorite": "Robot_MyFavorite.rule", "rockyou30000": "rockyou-30000.rule",
		"rule3": "3.rule", "stacking58": "stacking58.rule", "techtrip2": "techtrip_2.rule", "tenKrules": "10krules.rule",
		"toggles1": "toggles1.rule", "toggles2": "toggles2.rule", "toprules2020": "toprules2020.rule",
		"TOXIC10k": "TOXIC-10krules.rule", "TOXICSP": "T0XlC-insert_space_and_special_0_F.rule", "williamsuper": "williamsuper.rule",
		"hashmob150": "HashMob.150k.rule",
	}
	byName := map[string]scanner.RuleRef{}
	for _, r := range rules {
		byName[strings.ToLower(r.Name)] = r
		byName[strings.ToLower(r.Rel)] = r
	}
	var out []scanner.RuleRef
	seen := map[string]bool{}
	for _, a := range aliases {
		name := a
		if mapped, ok := aliasToFile[a]; ok {
			name = mapped
		}
		if r, ok := byName[strings.ToLower(name)]; ok && !seen[r.Path] {
			out = append(out, r)
			seen[r.Path] = true
		}
	}
	return out
}

func seedFile(ctx *Context) (string, error) {
	if len(ctx.SeedWords) == 0 {
		return "", fmt.Errorf("set seed words in options")
	}
	out := filepath.Join(ctx.TempDir, "seed-words.txt")
	return out, writeLines(out, ctx.SeedWords)
}

func usernameFile(ctx *Context) (string, error) {
	out := filepath.Join(ctx.TempDir, "usernames.txt")
	set := map[string]bool{}
	for _, f := range ctx.HashFiles {
		_ = scanLines(f.Path, 4*1024*1024, func(line string) bool {
			line = strings.TrimSpace(line)
			if line == "" {
				return true
			}
			if i := strings.LastIndex(line, `\`); i >= 0 && i+1 < len(line) {
				line = line[i+1:]
			}
			if i := strings.IndexByte(line, ':'); i >= 0 {
				line = line[:i]
			}
			line = strings.TrimSpace(line)
			if line != "" && len(line) < 128 {
				set[line] = true
			}
			return len(set) < 500000
		})
	}
	if len(set) == 0 {
		return "", fmt.Errorf("no usernames extracted from selected hashes")
	}
	return out, writeSet(out, set)
}

type potTransform func(string) string

func transformNone(s string) string { return s }

func stripDigits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func potWordsFile(ctx *Context, name string, tx potTransform, limit int) (string, error) {
	if ctx.Config.Potfile == "" {
		return "", fmt.Errorf("potfile not configured")
	}
	out := filepath.Join(ctx.TempDir, name)
	set := map[string]bool{}
	err := scanLines(ctx.Config.Potfile, 16*1024*1024, func(line string) bool {
		pw := tx(potPassword(line))
		if pw != "" && len(pw) < 256 {
			set[pw] = true
		}
		return len(set) < limit
	})
	if err != nil {
		return "", err
	}
	if len(set) == 0 {
		return "", fmt.Errorf("no usable potfile words found")
	}
	return out, writeSet(out, set)
}

func prefixSuffixFiles(ctx *Context) (string, string, error) {
	words, err := collectPotWords(ctx, 200000)
	if err != nil {
		return "", "", err
	}
	prefixes := rankedParts(words, true, 3, 8, 1000)
	suffixes := rankedParts(words, false, 3, 8, 1000)
	if len(prefixes) == 0 || len(suffixes) == 0 {
		return "", "", fmt.Errorf("not enough potfile data for prefixes/suffixes")
	}
	p := filepath.Join(ctx.TempDir, "pot-prefixes.txt")
	s := filepath.Join(ctx.TempDir, "pot-suffixes.txt")
	if err := writeLines(p, prefixes); err != nil {
		return "", "", err
	}
	if err := writeLines(s, suffixes); err != nil {
		return "", "", err
	}
	return p, s, nil
}

func substringFile(ctx *Context) (string, error) {
	words, err := collectPotWords(ctx, 100000)
	if err != nil {
		return "", err
	}
	counts := map[string]int{}
	for _, w := range words {
		r := []rune(w)
		for n := 3; n <= 8; n++ {
			if len(r) < n {
				continue
			}
			for i := 0; i+n <= len(r); i++ {
				part := string(r[i : i+n])
				if validToken(part) {
					counts[part]++
				}
			}
		}
	}
	lines := topCounts(counts, 1000)
	if len(lines) == 0 {
		return "", fmt.Errorf("no common substrings mined")
	}
	out := filepath.Join(ctx.TempDir, "pot-substrings.txt")
	return out, writeLines(out, lines)
}

func adaptiveRuleFile(ctx *Context) (string, error) {
	words, err := collectPotWords(ctx, 100000)
	if err != nil {
		return "", err
	}
	prefixes := rankedParts(words, true, 1, 4, 40)
	suffixes := rankedParts(words, false, 1, 4, 80)
	rules := []string{":", "c", "u", "l", "T0", "T1", "r", "d"}
	for _, p := range prefixes {
		rules = append(rules, prependRule(p))
	}
	for _, s := range suffixes {
		rules = append(rules, appendRule(s))
	}
	out := filepath.Join(ctx.TempDir, "analysis.rule")
	return out, writeLines(out, uniqueNonEmpty(rules))
}

func adaptiveMaskFile(ctx *Context) (string, error) {
	words, err := collectPotWords(ctx, 200000)
	if err != nil {
		return "", err
	}
	counts := map[string]int{}
	for _, w := range words {
		m := maskFromWord(w)
		if m != "" && len(m) <= 64 {
			counts[m]++
		}
	}
	lines := topCounts(counts, 500)
	if len(lines) == 0 {
		return "", fmt.Errorf("no masks mined from potfile")
	}
	out := filepath.Join(ctx.TempDir, "analysis.hcmask")
	return out, writeLines(out, lines)
}

func fingerprintFile(ctx *Context) (string, error) {
	words, err := collectPotWords(ctx, 100000)
	if err != nil {
		return "", err
	}
	set := map[string]bool{}
	re := regexp.MustCompile(`[A-Za-z]+|[0-9]+|[^A-Za-z0-9\s]+`)
	for _, w := range words {
		for _, m := range re.FindAllString(w, -1) {
			if len(m) >= 2 && len(m) <= 32 {
				set[m] = true
				set[strings.ToLower(m)] = true
				set[strings.Title(strings.ToLower(m))] = true
			}
		}
	}
	if len(set) == 0 {
		return "", fmt.Errorf("no fingerprint tokens mined")
	}
	out := filepath.Join(ctx.TempDir, "fingerprint.txt")
	return out, writeSet(out, set)
}

func collectPotWords(ctx *Context, limit int) ([]string, error) {
	if ctx.Config.Potfile == "" {
		return nil, fmt.Errorf("potfile not configured")
	}
	var words []string
	seen := map[string]bool{}
	err := scanLines(ctx.Config.Potfile, 16*1024*1024, func(line string) bool {
		pw := potPassword(line)
		if pw != "" && len(pw) < 256 && !seen[pw] {
			seen[pw] = true
			words = append(words, pw)
		}
		return len(words) < limit
	})
	if err != nil {
		return nil, err
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("no usable potfile words found")
	}
	return words, nil
}

func generateMarkov(inputs []string, out string, amount int) error {
	start := map[rune]int{}
	trans := map[rune]map[rune]int{}
	lengths := map[int]int{}
	samples := 0
	for _, input := range inputs {
		err := scanLines(input, 16*1024*1024, func(line string) bool {
			word := potPassword(line)
			if word == "" || len(word) > 48 {
				return true
			}
			rs := []rune(word)
			if len(rs) == 0 {
				return true
			}
			start[rs[0]]++
			lengths[len(rs)]++
			for i := 0; i+1 < len(rs); i++ {
				if trans[rs[i]] == nil {
					trans[rs[i]] = map[rune]int{}
				}
				trans[rs[i]][rs[i+1]]++
			}
			samples++
			return samples < 200000
		})
		if err != nil {
			return err
		}
	}
	if len(start) == 0 {
		return fmt.Errorf("not enough input to build Markov model")
	}
	rng := rand.New(rand.NewSource(1337))
	set := map[string]bool{}
	for tries := 0; len(set) < amount && tries < amount*20; tries++ {
		targetLen := weightedInt(lengths, rng)
		if targetLen < 4 {
			targetLen = 4
		}
		if targetLen > 24 {
			targetLen = 24
		}
		cur := weightedRune(start, rng)
		var b strings.Builder
		b.WriteRune(cur)
		for i := 1; i < targetLen; i++ {
			nexts := trans[cur]
			if len(nexts) == 0 {
				cur = weightedRune(start, rng)
			} else {
				cur = weightedRune(nexts, rng)
			}
			b.WriteRune(cur)
		}
		set[b.String()] = true
	}
	return writeSet(out, set)
}

func scanLines(path string, maxToken int, fn func(string) bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), maxToken)
	for sc.Scan() {
		if !fn(sc.Text()) {
			break
		}
	}
	return sc.Err()
}

func potPassword(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if i := strings.LastIndexByte(line, ':'); i >= 0 && i+1 < len(line) {
		line = line[i+1:]
	}
	if strings.HasPrefix(line, "$HEX[") && strings.HasSuffix(line, "]") {
		raw := strings.TrimSuffix(strings.TrimPrefix(line, "$HEX["), "]")
		if b, err := hex.DecodeString(raw); err == nil {
			return string(b)
		}
	}
	return line
}

func writeLines(path string, lines []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriterSize(f, 1<<20)
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if _, err := w.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func writeSet(path string, set map[string]bool) error {
	lines := make([]string, 0, len(set))
	for s := range set {
		if strings.TrimSpace(s) != "" {
			lines = append(lines, s)
		}
	}
	sort.Strings(lines)
	return writeLines(path, lines)
}

func rankedParts(words []string, prefix bool, minLen, maxLen, limit int) []string {
	counts := map[string]int{}
	for _, w := range words {
		r := []rune(w)
		for n := minLen; n <= maxLen; n++ {
			if len(r) < n {
				continue
			}
			var part string
			if prefix {
				part = string(r[:n])
			} else {
				part = string(r[len(r)-n:])
			}
			if validToken(part) {
				counts[part]++
			}
		}
	}
	return topCounts(counts, limit)
}

func topCounts(counts map[string]int, limit int) []string {
	type kv struct {
		K string
		V int
	}
	var items []kv
	for k, v := range counts {
		if k != "" {
			items = append(items, kv{k, v})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].V == items[j].V {
			return items[i].K < items[j].K
		}
		return items[i].V > items[j].V
	})
	if len(items) > limit {
		items = items[:limit]
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.K)
	}
	return out
}

func validToken(s string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func uniqueNonEmpty(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if strings.TrimSpace(s) != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func appendRule(s string) string {
	var b strings.Builder
	for _, r := range s {
		b.WriteByte('$')
		b.WriteRune(r)
	}
	return b.String()
}

func prependRule(s string) string {
	runes := []rune(s)
	var b strings.Builder
	for i := len(runes) - 1; i >= 0; i-- {
		b.WriteByte('^')
		b.WriteRune(runes[i])
	}
	return b.String()
}

func maskFromWord(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case unicode.IsLower(r):
			b.WriteString("?l")
		case unicode.IsUpper(r):
			b.WriteString("?u")
		case unicode.IsDigit(r):
			b.WriteString("?d")
		default:
			b.WriteString("?s")
		}
	}
	return b.String()
}

func weightedRune(m map[rune]int, rng *rand.Rand) rune {
	total := 0
	for _, v := range m {
		total += v
	}
	if total <= 0 {
		return 'a'
	}
	pick := rng.Intn(total)
	for r, v := range m {
		pick -= v
		if pick < 0 {
			return r
		}
	}
	return 'a'
}

func weightedInt(m map[int]int, rng *rand.Rand) int {
	total := 0
	for _, v := range m {
		total += v
	}
	if total <= 0 {
		return 8
	}
	pick := rng.Intn(total)
	for n, v := range m {
		pick -= v
		if pick < 0 {
			return n
		}
	}
	return 8
}

func sanitizeName(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "http://")
	var b strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
		} else if b.Len() > 0 {
			b.WriteByte('-')
		}
		if b.Len() >= 40 {
			break
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "site"
	}
	return out
}

func FormatCommand(cmd Command) string {
	parts := append([]string{cmd.Exe}, cmd.Args...)
	for i, p := range parts {
		parts[i] = quoteArg(p)
	}
	return strings.Join(parts, " ")
}

func quoteArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"'()[]{}&|;") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}
