// Command sshush-agent is the SSHush server-side agent.
//
// This is a stub. It exists so sshush-agent.service has a real process to
// supervise while the install and removal layer is built out. It reads no
// configuration, opens no sockets, and touches no files.
//
// On SIGTERM or SIGINT it returns from main, exiting 0. That matters to the
// unit: Restart=on-failure means a clean exit leaves the service stopped
// rather than looping.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Deliberately not called a heartbeat. This only writes a line to the journal;
// there is no protocol, no peer, and nothing goes over the wire. The heartbeat
// is a separate piece of work that does not exist yet, and reusing the word here
// would make later readers think it had already been built and tested.
const livenessLogInterval = 60 * time.Second

func main() {
	// systemd stamps its own timestamp and unit name onto every journal line,
	// so emit bare messages rather than duplicating that.
	log.SetFlags(0)
	log.SetOutput(os.Stdout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	// Log once on start so the journal shows the process came up, without
	// waiting a full interval for the first line.
	log.Print("sshush-agent alive")

	ticker := time.NewTicker(livenessLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Print("sshush-agent stopping")
			return
		case <-ticker.C:
			log.Print("sshush-agent alive")
		}
	}
}
