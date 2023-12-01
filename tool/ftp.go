package tool

import (
	"context"
	"fmt"
	"time"

	"github.com/jlaffaye/ftp"
)

// Connect to FTP server
func Connect(target string, port int, user string, password string) (*ftp.ServerConn, error) {
	host := fmt.Sprintf("%s:%d", target, port)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Connect to FTP server
	// support for FTP servers in NAT environments
	// source: https://github.com/jlaffaye/ftp/issues/305#issuecomment-1397735147
	// var d net.Dialer
	// var firstHost string
	// dialFunc := func(network, address string) (net.Conn, error) {
	// 	fmt.Printf("Dialing network: %s address: %s\n", network, address)
	// 	host, port, err := net.SplitHostPort(address)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("ftp.Open: Failed to split address %s: %w", address, err)
	// 	}
	// 	fmt.Printf("Dialing host: %s port: %s firstHost: %s\n", host, port, firstHost)
	// 	if len(firstHost) == 0 {
	// 		fmt.Printf("Setting firstHost: %s\n", host)
	// 		firstHost = host
	// 	}
	// 	return d.DialContext(ctx, "tcp", net.JoinHostPort(firstHost, port))
	// }

	// debug writer
	//debugWriter := os.Stdout

	conn, err := ftp.Dial(host, ftp.DialWithContext(ctx))
	//ftp.DialWithDialFunc(dialFunc),
	//ftp.DialWithDebugOutput(debugWriter))
	if err != nil {
		return nil, err
	}

	return conn, nil
}
