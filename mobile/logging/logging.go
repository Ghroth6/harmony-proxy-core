// Package logging exposes the upstream log stream to a process-owned host sink.
// Display, filtering, retention and export policies belong to the host application.
package logging

import (
	"sync/atomic"

	"github.com/metacubex/mihomo/log"
	"github.com/sirupsen/logrus"
)

var installed atomic.Bool

// Install accepts one process-lifetime callback. It receives upstream levels
// 0=debug, 1=info, 2=warning, 3=error, plus 4=fatal and 5=panic. The callback
// must be concurrency-safe, must return promptly, and must not log recursively.
// It is independent of proxy start/stop and does not alter upstream log levels.
func Install(output func(level int, message string)) bool {
	if output == nil || !installed.CompareAndSwap(false, true) {
		return false
	}
	subscription := log.Subscribe()
	go func() {
		for event := range subscription {
			output(int(event.LogLevel), event.Payload)
		}
	}()
	// Upstream fatal/panic messages go directly through logrus rather than the
	// observable stream. Deliver these synchronously before process termination.
	logrus.AddHook(terminalHook{output: output})
	return true
}

type terminalHook struct{ output func(int, string) }

func (terminalHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.FatalLevel, logrus.PanicLevel}
}
func (hook terminalHook) Fire(entry *logrus.Entry) error {
	level := 4
	if entry.Level == logrus.PanicLevel {
		level = 5
	}
	hook.output(level, entry.Message)
	return nil
}
