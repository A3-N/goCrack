package main

import (
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"gocrack/internal/config"
	"gocrack/internal/scanner"
	"gocrack/internal/setup"
	"gocrack/internal/tui"
)

func main() {
	configPath, err := config.DefaultPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	cfg, found, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	setupRan := false
	if !found || len(config.RequiredIssues(cfg)) > 0 {
		var ok bool
		cfg, ok, err = setup.Run(cfg, configPath, !found)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "setup cancelled")
			os.Exit(1)
		}
		setupRan = true
	}

	if !found || setupRan {
		if err := config.Save(configPath, cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}

	cfg = config.Prepare(cfg)
	if issues := config.RequiredIssues(cfg); len(issues) > 0 {
		for _, issue := range issues {
			fmt.Fprintf(os.Stderr, "%s: %s\n", issue.Label, issue.Message)
		}
		os.Exit(1)
	}

	inventory, err := scanner.Scan(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	tempDir, err := os.MkdirTemp("", "goCrack-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(tempDir)

	appDir, err := config.AppDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	p := tea.NewProgram(tui.New(appDir, cfg, inventory, tempDir), tea.WithAltScreen(), tea.WithMouseCellMotion())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
