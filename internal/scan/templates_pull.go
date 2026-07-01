package scan

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// DefaultTemplateRepo is the canonical source of public Nuclei POC templates.
// Pulling it populates the local pocs/nuclei directory so scans do not run with
// an empty template set. Users may override it with a fork or mirror.
const (
	DefaultTemplateRepo   = "https://github.com/projectdiscovery/nuclei-templates.git"
	DefaultTemplateBranch = "main"
)

// PullTemplatesOptions configures a template pull (clone or update) operation.
type PullTemplatesOptions struct {
	Dir    string // target directory (required)
	Repo   string // git remote URL (default: official nuclei-templates)
	Branch string // branch to track (default: main)
	Force  bool   // remove an existing dir before cloning
	Depth  int    // clone depth; 0 defaults to 1 (shallow)
	// Logf, when set, receives human-readable progress lines (clone/pull).
	Logf func(format string, args ...any)
}

// PullTemplatesResult summarizes a clone or update.
type PullTemplatesResult struct {
	Action  string // "cloned" or "updated"
	Dir     string // absolute target directory
	Commit  string // short HEAD hash
	Count   int    // number of .yaml/.yml/.json files found after pull
	Version string // VERSION file contents written after pull
}

// PullTemplates clones the official nuclei-templates repo into dir, or updates
// it if dir already contains a git worktree. On success it writes a VERSION
// file recording the HEAD commit so countTemplates can report template_version.
//
// The operation respects ctx for cancellation. A shallow clone (Depth=1) is
// used by default because nuclei-templates is large and history is not needed.
func PullTemplates(ctx context.Context, opts PullTemplatesOptions) (*PullTemplatesResult, error) {
	if opts.Dir == "" {
		return nil, errors.New("template dir is required")
	}
	if opts.Repo == "" {
		opts.Repo = DefaultTemplateRepo
	}
	if opts.Branch == "" {
		opts.Branch = DefaultTemplateBranch
	}
	if opts.Depth == 0 {
		opts.Depth = 1
	}
	logf := opts.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}

	absDir, err := filepath.Abs(opts.Dir)
	if err != nil {
		return nil, err
	}

	if opts.Force {
		logf("[INF] --force: removing existing %s", absDir)
		if err := os.RemoveAll(absDir); err != nil {
			return nil, fmt.Errorf("remove existing dir: %w", err)
		}
	}

	gitDir := filepath.Join(absDir, ".git")
	_, statErr := os.Stat(gitDir)
	hasGit := statErr == nil

	if hasGit {
		return updateTemplates(ctx, absDir, opts, logf)
	}

	// Refuse to clobber a non-empty, non-git directory. An empty dir is fine:
	// git clone into it.
	if entries, err := os.ReadDir(absDir); err == nil && len(entries) > 0 {
		return nil, fmt.Errorf("%s already exists and is not a git repository; pass --force to replace it", absDir)
	}

	return cloneTemplates(ctx, absDir, opts, logf)
}

func cloneTemplates(ctx context.Context, dir string, opts PullTemplatesOptions, logf func(string, ...any)) (*PullTemplatesResult, error) {
	ref := plumbing.NewBranchReferenceName(opts.Branch)
	logf("[INF] 克隆 Nuclei 模板仓库 %s（分支 %s，depth=%d）-> %s", opts.Repo, opts.Branch, opts.Depth, dir)
	cloneOpts := &git.CloneOptions{
		URL:           opts.Repo,
		ReferenceName: ref,
		SingleBranch:  true,
		Depth:         opts.Depth,
	}
	repo, err := git.PlainCloneContext(ctx, dir, false, cloneOpts)
	if err != nil {
		// Clean up a partial clone so a retry is not blocked by leftover .git.
		_ = os.RemoveAll(dir)
		return nil, fmt.Errorf("clone %s: %w", opts.Repo, err)
	}
	logf("[INF] 克隆完成，正在统计模板…")
	return finalizePull("cloned", dir, repo)
}

func updateTemplates(ctx context.Context, dir string, opts PullTemplatesOptions, logf func(string, ...any)) (*PullTemplatesResult, error) {
	repo, err := git.PlainOpen(dir)
	if err != nil {
		return nil, fmt.Errorf("open repo: %w", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("worktree: %w", err)
	}
	logf("[INF] 更新已存在的模板仓库 %s（分支 %s）", dir, opts.Branch)
	pullOpts := &git.PullOptions{
		RemoteName:    "origin",
		RemoteURL:     opts.Repo,
		ReferenceName: plumbing.NewBranchReferenceName(opts.Branch),
		SingleBranch:  true,
		Depth:         opts.Depth,
		Force:         true,
	}
	err = wt.PullContext(ctx, pullOpts)
	if err != nil && !errors.Is(err, git.NoErrAlreadyUpToDate) {
		return nil, fmt.Errorf("pull: %w (use --force to re-clone)", err)
	}
	if errors.Is(err, git.NoErrAlreadyUpToDate) {
		logf("[INF] 模板已是最新")
	} else {
		logf("[INF] 更新完成，正在统计模板…")
	}
	return finalizePull("updated", dir, repo)
}

// TemplateStatus reports the current template count and version for a directory.
// exists is false when the directory is absent. It reuses countTemplates so the
// reported numbers match what a scan's POC phase would record.
func TemplateStatus(dir string) (count int, version string, exists bool) {
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return 0, "", false
	}
	count, version = countTemplates(dir)
	return count, version, true
}

// finalizePull reads HEAD, writes a VERSION file with the commit so later scans
// can report template_version, then counts the template files present.
func finalizePull(action, dir string, repo *git.Repository) (*PullTemplatesResult, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("read HEAD: %w", err)
	}
	commit := head.Hash().String()
	short := commit
	if len(short) > 7 {
		short = short[:7]
	}
	version := fmt.Sprintf("nuclei-templates@%s (pulled %s)", short, time.Now().UTC().Format("2006-01-02"))
	if err := os.WriteFile(filepath.Join(dir, "VERSION"), []byte(version), 0o644); err != nil {
		return nil, fmt.Errorf("write VERSION: %w", err)
	}
	count, _ := countTemplates(dir)
	return &PullTemplatesResult{
		Action:  action,
		Dir:     dir,
		Commit:  short,
		Count:   count,
		Version: version,
	}, nil
}
