package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/lipgloss"
)

func TestSplitPaneWidthsFitTerminal(t *testing.T) {
	for _, width := range []int{48, 60, 80, 100, 140} {
		left, right := splitPaneWidths(width, width/3, 24, 30)
		if left < 1 || right < 1 {
			t.Fatalf("splitPaneWidths(%d) returned invalid widths %d/%d", width, left, right)
		}
		if got := left + right + 5; got > width {
			t.Fatalf("splitPaneWidths(%d) overflows: left=%d right=%d total=%d", width, left, right, got)
		}
	}
}

func TestRenderBoxClampsLines(t *testing.T) {
	const boxWidth = 24
	rendered := renderBox(boxWidth, []string{
		strings.Repeat("x", 200),
		okStyle.Render(strings.Repeat("y", 200)),
	}, 2)
	for _, line := range strings.Split(rendered, "\n") {
		if got, want := lipgloss.Width(line), boxWidth+2; got > want {
			t.Fatalf("rendered line width = %d, want <= %d: %q", got, want, line)
		}
	}
}

func TestCompactCrackRecordFitsWidth(t *testing.T) {
	record := "* " + strings.Repeat("a", 32) + ":P@ssw0rd@12"
	for width := 6; width < 48; width++ {
		got := compactCrackRecord(record, width)
		if cells := lipgloss.Width(got); cells > width {
			t.Fatalf("compactCrackRecord width = %d, want <= %d: %q", cells, width, got)
		}
	}
}

func TestNormalizeManualHashes(t *testing.T) {
	got := normalizeManualHashes("  hash1\r\n\r\nhash2\n  hash3  \n")
	want := "hash1\nhash2\nhash3"
	if got != want {
		t.Fatalf("normalizeManualHashes() = %q, want %q", got, want)
	}
}

func TestManualHashFileWritesAllLines(t *testing.T) {
	m := model{
		tempDir:        t.TempDir(),
		manualHashMode: 1000,
		manualHash:     "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n",
	}
	ref, err := m.manualHashFile()
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(ref.Path)
	if err != nil {
		t.Fatal(err)
	}
	want := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n"
	if string(body) != want {
		t.Fatalf("manual hash file body = %q, want %q", string(body), want)
	}
}
