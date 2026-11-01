package watcher

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
)

const debounce = 200 * time.Millisecond

type Watcher struct {
	fs     *fsnotify.Watcher
	files  map[string]struct{}
	reload func() error
	log    *slog.Logger
}

func New(files []string, reload func() error, log *slog.Logger) (*Watcher, error) {
	fs, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	w := &Watcher{fs: fs, files: make(map[string]struct{}), reload: reload, log: log}
	dirs := make(map[string]struct{})
	for _, file := range files {
		abs, err := filepath.Abs(file)
		if err != nil {
			_ = fs.Close()
			return nil, err
		}
		abs = filepath.Clean(abs)
		w.files[abs] = struct{}{}
		dirs[filepath.Dir(abs)] = struct{}{}
	}
	for dir := range dirs {
		if err := fs.Add(dir); err != nil {
			_ = fs.Close()
			return nil, err
		}
	}
	return w, nil
}

func (w *Watcher) Run(ctx context.Context) {
	defer w.fs.Close()

	var timer *time.Timer
	for {
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case event, ok := <-w.fs.Events:
			if !ok {
				return
			}
			if !w.watched(event.Name) {
				continue
			}
			if timer != nil {
				timer.Stop()
			}
			timer = time.AfterFunc(debounce, w.run)
		case err, ok := <-w.fs.Errors:
			if !ok {
				return
			}
			w.log.Error("file watcher error", "err", err)
		}
	}
}

func (w *Watcher) run() {
	if err := w.reload(); err != nil {
		w.log.Error("rules reload failed", "err", err)
		return
	}
	w.log.Info("rules reloaded")
}

func (w *Watcher) watched(name string) bool {
	_, ok := w.files[filepath.Clean(name)]
	return ok
}
