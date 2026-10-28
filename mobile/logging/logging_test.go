package logging_test

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/mobile/logging"
)

func TestOriginalMessagesReachHostIndependentlyOfConsoleLevel(t *testing.T) {
	type item struct {
		level int
		text  string
	}
	events := make(chan item, 8)
	if logging.Install(nil) || !logging.Install(func(level int, message string) { events <- item{level, message} }) || logging.Install(func(int, string) {}) {
		t.Fatal("process output ownership")
	}
	old := log.Level()
	log.SetLevel(log.SILENT)
	defer log.SetLevel(old)
	want := strings.Repeat("原始记录", 2000) + " endpoint=example.test:443 error=certificate mismatch"
	log.Debugln("%s", want)
	log.Warnln("source %s", "unaltered")
	for _, expected := range []item{{int(log.DEBUG), want}, {int(log.WARNING), "source unaltered"}} {
		select {
		case got := <-events:
			if got != expected {
				t.Fatal("host log content or level changed")
			}
		case <-time.After(time.Second):
			t.Fatal("host log missing")
		}
	}
}

func TestFatalMessageReachesHostBeforeExit(t *testing.T) {
	if os.Getenv("CLASHOH_LOG_FATAL_CHILD") == "1" {
		logging.Install(func(level int, message string) { fmt.Printf("HOST:%d:%s\n", level, message) })
		log.Fatalln("original fatal detail")
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestFatalMessageReachesHostBeforeExit$")
	cmd.Env = append(os.Environ(), "CLASHOH_LOG_FATAL_CHILD=1")
	output, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "HOST:4:original fatal detail") {
		t.Fatalf("fatal delivery: %s %v", output, err)
	}
}
