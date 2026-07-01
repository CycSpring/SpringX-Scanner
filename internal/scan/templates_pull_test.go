package scan

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

// makeBareRepo creates a bare git repository at dst containing one yaml
// template file, and returns its path. PullTemplates can clone from this via
// the file:// scheme without touching the network.
func makeBareRepo(t *testing.T, dst string) string {
	t.Helper()
	// Build the content in a temporary work repo, then push to a bare repo.
	work := t.TempDir()
	repo, err := git.PlainInit(work, false)
	if err != nil {
		t.Fatalf("init work repo: %v", err)
	}
	tpl := []byte("id: springx-test\ntemplate-id: springx-test\ninfo:\n  name: test\n\nhttp:\n  - method: GET\n    path: ['{{BaseURL}}']\n")
	if err := os.WriteFile(filepath.Join(work, "test.yaml"), tpl, 0o644); err != nil {
		t.Fatalf("write template: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("test.yaml"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := wt.Commit("add test template", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com"},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir bare parent: %v", err)
	}
	if _, err := git.PlainClone(dst, true, &git.CloneOptions{
		URL: work,
	}); err != nil {
		t.Fatalf("clone to bare: %v", err)
	}
	return dst
}

func TestPullTemplates_Clone(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "bare.git")
	makeBareRepo(t, bare)

	dst := filepath.Join(t.TempDir(), "nuclei")
	var logs []string
	logf := func(format string, args ...any) {
		logs = append(logs, strings.TrimSpace(format))
	}
	res, err := PullTemplates(context.Background(), PullTemplatesOptions{
		Dir:    dst,
		Repo:   bare, // file path works as a clone source
		Branch: "master",
		Depth:  1,
		Logf:   logf,
	})
	if err != nil {
		t.Fatalf("PullTemplates: %v", err)
	}
	if res.Action != "cloned" {
		t.Errorf("action = %q, want cloned", res.Action)
	}
	if res.Count < 1 {
		t.Errorf("count = %d, want >=1", res.Count)
	}
	if res.Commit == "" {
		t.Errorf("commit is empty")
	}
	if _, err := os.Stat(filepath.Join(dst, "test.yaml")); err != nil {
		t.Errorf("template file missing after clone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "VERSION")); err != nil {
		t.Errorf("VERSION file missing after clone: %v", err)
	}
	// TemplateStatus should agree with the pulled result.
	count, version, exists := TemplateStatus(dst)
	if !exists {
		t.Errorf("TemplateStatus exists=false, want true")
	}
	if count != res.Count {
		t.Errorf("TemplateStatus count=%d != pull count=%d", count, res.Count)
	}
	if version == "" {
		t.Errorf("TemplateStatus version empty")
	}
}

func TestPullTemplates_Update(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "bare.git")
	makeBareRepo(t, bare)

	dst := filepath.Join(t.TempDir(), "nuclei")
	if _, err := PullTemplates(context.Background(), PullTemplatesOptions{
		Dir: dst, Repo: bare, Branch: "master", Depth: 1,
	}); err != nil {
		t.Fatalf("first pull: %v", err)
	}

	// Second pull on the same dir should report "updated" and succeed even
	// when the upstream is unchanged (already up to date).
	res, err := PullTemplates(context.Background(), PullTemplatesOptions{
		Dir: dst, Repo: bare, Branch: "master", Depth: 1,
	})
	if err != nil {
		t.Fatalf("second pull: %v", err)
	}
	if res.Action != "updated" {
		t.Errorf("action = %q, want updated", res.Action)
	}
	if res.Count < 1 {
		t.Errorf("count = %d, want >=1", res.Count)
	}
}

func TestPullTemplates_ForceReplaces(t *testing.T) {
	bare := filepath.Join(t.TempDir(), "bare.git")
	makeBareRepo(t, bare)

	dst := filepath.Join(t.TempDir(), "nuclei")
	// Seed a non-git directory with a stray file; without --force the pull
	// must refuse, and with --force it must replace it.
	if err := os.MkdirAll(dst, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dst, "stray.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := PullTemplates(context.Background(), PullTemplatesOptions{
		Dir: dst, Repo: bare, Branch: "master", Depth: 1,
	})
	if err == nil {
		t.Fatalf("expected error for non-empty non-git dir, got nil")
	}
	if !strings.Contains(err.Error(), "force") {
		t.Errorf("error should mention --force, got: %v", err)
	}

	res, err := PullTemplates(context.Background(), PullTemplatesOptions{
		Dir: dst, Repo: bare, Branch: "master", Depth: 1, Force: true,
	})
	if err != nil {
		t.Fatalf("force pull: %v", err)
	}
	if res.Action != "cloned" {
		t.Errorf("action = %q, want cloned", res.Action)
	}
	if _, err := os.Stat(filepath.Join(dst, "stray.txt")); !os.IsNotExist(err) {
		t.Errorf("stray file should be gone after --force, got err=%v", err)
	}
}

func TestPullTemplates_RequiresDir(t *testing.T) {
	_, err := PullTemplates(context.Background(), PullTemplatesOptions{})
	if err == nil {
		t.Fatalf("expected error for empty dir, got nil")
	}
}
