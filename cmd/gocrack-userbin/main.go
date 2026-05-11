package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"gocrack/internal/config"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	binDir, err := installBinDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return err
	}

	cfgDir, err := config.ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		return err
	}

	dest := filepath.Join(binDir, executableName())
	cmd := exec.Command("go", "build", "-o", dest, ".")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	if err := cmd.Run(); err != nil {
		return err
	}

	cfgPath, err := config.DefaultPath()
	if err != nil {
		return err
	}
	fmt.Println("installed:", dest)
	fmt.Println("config:", cfgPath)
	fmt.Println("add to PATH if needed:", binDir)
	return nil
}

func installBinDir() (string, error) {
	if dir := strings.TrimSpace(os.Getenv("BINDIR")); dir != "" {
		return filepath.Abs(expandInstallPath(dir))
	}
	if prefix := strings.TrimSpace(os.Getenv("PREFIX")); prefix != "" {
		return filepath.Abs(filepath.Join(expandInstallPath(prefix), "bin"))
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".local", "bin"), nil
}

func executableName() string {
	if runtime.GOOS == "windows" {
		return "goCrack.exe"
	}
	return "goCrack"
}

func expandInstallPath(path string) string {
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
