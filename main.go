package main

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"

	"github.com/ChristianSch/titan/lib"
	"github.com/ChristianSch/titan/reporting"
	"github.com/ChristianSch/titan/tool"
	"github.com/c-bata/go-prompt"
	"github.com/fatih/color"
	"github.com/jlaffaye/ftp"
	"github.com/pkg/term/termios"
	"github.com/rodaine/table"
	"golang.org/x/sys/unix"
)

// GlobalConfig stores the configuration for the tool
type GlobalConfig struct {
	Target string
}

type FtpConfig struct {
	Port     *int
	User     *string
	Password *string
}

type ShellConfig struct {
	Port  *int
	Shell *string
}

var (
	config      GlobalConfig
	ftpConfig   FtpConfig
	ftpConn     *ftp.ServerConn
	shellConfig ShellConfig
	discoveries []reporting.Discovery
	// save original terminal config to allow ctrl-c to work
	fd                     int
	originalTerminalConfig *unix.Termios
)

func banner() {
	banner := "████████╗██╗████████╗ █████╗ ███╗   ██╗\n╚══██╔══╝██║╚══██╔══╝██╔══██╗████╗  ██║\n   ██║   ██║   ██║   ███████║██╔██╗ ██║\n   ██║   ██║   ██║   ██╔══██║██║╚██╗██║\n   ██║   ██║   ██║   ██║  ██║██║ ╚████║\n   ╚═╝   ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═══╝\n"
	lib.Green(banner)
	lib.Yellow("      >> Automated attack suite <<\n\n")
}

func main() {
	banner()

	// before we run anything, we need to save the original terminal config to allow ctrl-c to work
	saveTerminalConfig()

	fmt.Println("Use >tab for an overview of commands. Ctrl+D or exit to leave.")
	p := prompt.New(
		executor,
		completer,
		prompt.OptionPrefix(">>> "),
		prompt.OptionTitle("titan"),
	)
	p.Run()

	// clean up
	if ftpConn != nil {
		ftpConn.Quit()
	}
}

func saveTerminalConfig() {
	fd, err := syscall.Open("/dev/tty", syscall.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}

	// get the original settings
	originalTerminalConfig, err = termios.Tcgetattr(uintptr(fd))
	if err != nil {
		panic(err)
	}
}

// restoreTerminalConfig restores the original terminal config
func restoreTerminalConfig() {
	if err := termios.Tcsetattr(uintptr(fd), termios.TCSANOW, (*unix.Termios)(originalTerminalConfig)); err != nil {
		panic(err)
	}
}

func executor(in string) {
	in = strings.TrimSpace(in)
	args := strings.Fields(in)

	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "exit":
		fmt.Println("Exiting...")
		os.Exit(0)
	case "lookup":
		if len(args) < 3 {
			fmt.Println("Usage: lookup [subcommand] [domain]")
			return
		}
		switch args[1] {
		case "ip":
			ip, err := tool.ResolveDomain(args[2])
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				return
			}
			fmt.Println(ip)
		default:
			fmt.Printf("Unknown lookup subcommand: %s\n", args[1])
		}
	case "enum":
		if len(args) < 2 {
			fmt.Println("Usage: enum [os|services]")
			return
		}
		switch args[1] {
		case "os":
			// Implement OS enumeration logic here
			fmt.Println("Enumerating Operating System...")
			enumOs()
		case "services":
			// Implement services enumeration logic here
			fmt.Println("Enumerating services...")
			enumServices()
		case "ftp":
			ftpEnum()
			// FIXME:
		default:
			fmt.Printf("Unknown enum command: %s\n", args[1])
		}
	case "ftp":
		// Call FTP interaction function here
		ftpMode()
		if ftpConn != nil {
			fmt.Println("Closing connection...")
			if err := ftpConn.Quit(); err != nil {
				fmt.Println("Error closing connection:", err)
			}
		}

	case "shell":
		shellMode()

	case "disco":
		// Print all discoveries
		handleDiscoverySelection(discoveries)
	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: set [key] [value]")
			return
		}
		setCommand(args[1], args[2])
	default:
		fmt.Printf("Unknown command: %s\n", in)
	}
}

func completer(d prompt.Document) []prompt.Suggest {
	commands := []prompt.Suggest{
		{Text: "enum", Description: "Enumerate targets using nmap"},
		{Text: "ftp", Description: "Interact with an FTP server"},
		{Text: "shell", Description: "Start a reverse shell"},
		{Text: "set", Description: "Set a global variable"},
		{Text: "exit", Description: "Exit the program"},
		{Text: "disco", Description: "Show all discoveries so far"},
		{Text: "lookup", Description: "DNS lookup tools"},
	}

	// Auto-completion for the 'set' command
	setSubcommands := []prompt.Suggest{
		{Text: "target", Description: "Set the target IP or hostname"},
		// Add more settings here
	}

	// If the user is typing 'set', suggest the subcommands for 'set'
	if strings.HasPrefix(d.TextBeforeCursor(), "set ") {
		return prompt.FilterHasPrefix(setSubcommands, d.GetWordAfterCursorWithSpace(), true)
	}

	enumSubcommands := []prompt.Suggest{
		{Text: "os", Description: "Enumerate Operating System of the target"},
		{Text: "services", Description: "Enumerate services running on the target"},
		{Text: "ftp", Description: "Enumerate FTP server"},
	}

	lookupSubcommands := []prompt.Suggest{
		{Text: "ip", Description: "Resolve domain name to IP address"},
	}

	// Check if the current line starts with 'enum'
	if strings.HasPrefix(d.TextBeforeCursor(), "enum ") {
		return prompt.FilterHasPrefix(enumSubcommands, d.GetWordAfterCursorWithSpace(), true)
	}

	// Check if the current line starts with 'lookup'
	if strings.HasPrefix(d.TextBeforeCursor(), "lookup ") {
		return prompt.FilterHasPrefix(lookupSubcommands, d.GetWordAfterCursorWithSpace(), true)
	}

	// For all other inputs, suggest the main commands
	return prompt.FilterHasPrefix(commands, d.GetWordBeforeCursor(), true)
}

func setCommand(key, value string) {
	switch key {
	case "target":
		config.Target = value
		fmt.Printf("Target set to %s\n", value)
	default:
		fmt.Println("Unknown setting:", key)
	}
}

func enumOs() {
	if config.Target == "" {
		fmt.Println("Target not set")
		return
	}

	// loading animation
	stopLoading := lib.StartLoadingAnimation()

	os := tool.DetectOS(config.Target)

	stopLoading <- true

	if os == nil {
		lib.Red("Unable to detect OS\n")
	} else {
		discoveries = append(discoveries, *os)
		fmt.Printf("Detected OS: %s\n", os.Description)
	}
}

func enumServices() {
	if config.Target == "" {
		fmt.Println("Target not set")
		return
	}

	// loading animation
	stopLoading := lib.StartLoadingAnimation()

	services := tool.DetectServices(config.Target)

	stopLoading <- true

	if len(services) == 0 {
		lib.Red("Unable to detect services\n")
	} else {
		discoveries = append(discoveries, services...)
		fmt.Printf("Detected %d services\n", len(services))
	}
}

func handleDiscoverySelection(discoveries []reporting.Discovery) {
	fmt.Println("Select a discovery to view details:")
	lib.Bold(fmt.Sprintf("[%d] ", 0))
	fmt.Println("All")

	for i, d := range discoveries {
		lib.Bold(fmt.Sprintf("[%d] ", i+1))
		fmt.Printf("%s - %s\n", d.Target, d.Summary)
	}

	var selection int
	fmt.Print("Enter selection (number): ")
	_, err := fmt.Scan(&selection)
	if err != nil || selection < 0 || selection > len(discoveries) {
		fmt.Println("Invalid selection")
		return
	}

	if selection == 0 {
		fmt.Println("All discoveries:")
		for i, d := range discoveries {
			lib.Bold(fmt.Sprintf("\nDiscovery #%d:\n", i+1))
			printDiscoveryDetails(d)
		}
		return
	}

	selectedDiscovery := discoveries[selection-1]
	lib.Bold(fmt.Sprintf("\nDetails for Discovery #%d:\n", selection))
	printDiscoveryDetails(selectedDiscovery)
}

func printDiscoveryDetails(d reporting.Discovery) {
	headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
	columnFmt := color.New(color.FgYellow).SprintfFunc()

	// Create and configure a table
	tbl := table.New("Field", "Value")
	tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

	// Add rows to the table
	tbl.AddRow("Target", d.Target)
	tbl.AddRow("Affected Resource", d.AffectedResource)
	tbl.AddRow("Summary", d.Summary)
	tbl.AddRow("Description", d.Description)
	tbl.AddRow("Severity Score", fmt.Sprintf("%d", d.Score))

	// Print the table
	tbl.Print()
}

// FTP mode functions
func setFtpCommand(key, value string) {
	switch key {
	case "user":
		ftpConfig.User = &value
		fmt.Printf("User set to %s\n", value)
	case "password":
		ftpConfig.Password = &value
		fmt.Printf("Password set to %s\n", value)
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil {
			fmt.Println("Invalid port:", value)
			return
		}

		ftpConfig.Port = &port
		fmt.Printf("Port set to %d\n", port)
	default:
		fmt.Println("Unknown setting:", key)
	}
}

func ftpMode() {
	fmt.Println("Entering FTP mode. Type 'exit' to return.")

	p := prompt.New(
		ftpExecutor,
		ftpCompleter,
		prompt.OptionPrefix("ftp> "),
		prompt.OptionTitle("FTP mode"),
	)
	p.Run()
}

func ftpExecutor(in string) {
	in = strings.TrimSpace(in)
	args := strings.Fields(in)

	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "exit":
		fmt.Println("Exiting FTP mode...")
		// close connection, if any
		return // Exit FTP mode
	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: set [key] [value]")
			return
		}
		setFtpCommand(args[1], args[2])
	case "connect":
		// Implement FTP connect logic here
		fmt.Println("Connecting to FTP server...")
		var (
			port int
			user string
			pass string
		)

		if ftpConfig.Port != nil {
			port = *ftpConfig.Port
		} else {
			port = 21
		}

		if ftpConfig.User != nil {
			user = *ftpConfig.User
		} else {
			user = "anonymous"
		}

		if ftpConfig.Password != nil {
			pass = *ftpConfig.Password
		} else {
			pass = "anonymous"
		}

		fmt.Printf("Connecting to FTP server %s:%s@%s:%d\n", user, pass, config.Target, port)
		conn, err := tool.Connect(config.Target, port, user, pass)
		if err != nil {
			fmt.Println("Error connecting to FTP server:", err)
			return
		}
		ftpConn = conn

		err = conn.Login(user, pass)
		if err != nil {
			fmt.Println("Error logging in:", err)
			if err := conn.Quit(); err != nil {
				fmt.Println("Error closing connection:", err)
			}
			fmt.Println("Closed connection")
		}

		fmt.Printf("Logged in as %s\n", user)

	// FTP commands
	case "ls":
		if ftpConn == nil {
			fmt.Println("Not connected to FTP server")
			return
		}

		entries, err := ftpConn.List(".")
		if err != nil {
			fmt.Println("Error listing directory:", err)
			return
		}

		for _, entry := range entries {
			fmt.Println(entry.Name)
		}

	case "cd":
		if ftpConn == nil {
			fmt.Println("Not connected to FTP server")
			return
		}

		if len(args) < 2 {
			fmt.Println("Usage: cd [directory]")
			return
		}

		err := ftpConn.ChangeDir(args[1])
		if err != nil {
			fmt.Println("Error changing directory:", err)
			return
		}
	case "close":
		if ftpConn == nil {
			fmt.Println("Not connected to FTP server")
			return
		}

		err := ftpConn.Quit()
		if err != nil {
			fmt.Println("Error closing connection:", err)
			return
		}
		ftpConn = nil
	case "get":
		if ftpConn == nil {
			fmt.Println("Not connected to FTP server")
			return
		}

		if len(args) < 3 {
			fmt.Println("Usage: get [file] [destination]")
			return
		}

		r, err := ftpConn.Retr(args[1])
		if err != nil {
			fmt.Println("Error downloading file:", err)
			return
		}

		fmt.Printf("Downloading file %s...\n", args[2])
		defer r.Close()

		buf, err := io.ReadAll(r)
		if err != nil {
			fmt.Println("Error reading file:", err)
			return
		}

		// write file to disk
		err = os.WriteFile(args[2], buf, 0644)
		if err != nil {
			fmt.Println("Error writing file:", err)
			return
		}
	case "pwd":
		if ftpConn == nil {
			fmt.Println("Not connected to FTP server")
			return
		}

		pwd, err := ftpConn.CurrentDir()
		if err != nil {
			fmt.Println("Error getting current directory:", err)
			return
		}

		fmt.Println(pwd)

	default:
		fmt.Printf("Unknown FTP command: %s\n", in)
	}
}

func ftpCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "connect", Description: "Connect to an FTP server"},
		{Text: "ls", Description: "List files in the current directory"},
		{Text: "cd", Description: "Change directory"},
		{Text: "set", Description: "Set a local variable"},
		{Text: "get", Description: "Download file"},
		{Text: "pwd", Description: "Print working directory"},
		// {Text: "put", Description: "Upload file"},
		// {Text: "bg", Description: "Move open connection to the background"},
		// Add more FTP command suggestions here
		{Text: "exit", Description: "Exit FTP mode"},
	}

	// Auto-completion for the 'set' command
	setSubcommands := []prompt.Suggest{
		{Text: "user", Description: "Set the FTP username"},
		{Text: "password", Description: "Set the FTP password"},
		{Text: "port", Description: "Set the FTP port"},
	}

	// If the user is typing 'set', suggest the subcommands for 'set'
	if strings.HasPrefix(d.TextBeforeCursor(), "set ") {
		return prompt.FilterHasPrefix(setSubcommands, d.GetWordAfterCursorWithSpace(), true)
	}

	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

// FTP enumeration functions
func ftpEnumExecutor(in string) {
	in = strings.TrimSpace(in)
	args := strings.Fields(in)

	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "exit":
		fmt.Println("Exiting FTP mode...")
		// close connection, if any
		return // Exit FTP mode

	case "anon":
		if config.Target == "" {
			fmt.Println("Target not set")
			return
		}

		stop := lib.StartLoadingAnimation()
		enumFtpAnon()
		stop <- true

	case "auto":
		if config.Target == "" {
			fmt.Println("Target not set")
			return
		}

		stop := lib.StartLoadingAnimation()
		enumFtpAnon()
		stop <- true

	case "users":
		fmt.Println("Enumerating users... (not implemented)")
		// FIXME:

	default:
		fmt.Printf("Unknown FTP command: %s\n", in)
	}
}

func ftpEnumCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "auto", Description: "Automatically detect FTP server"},
		{Text: "anon", Description: "Attempt anonymous login"},
		{Text: "users", Description: "Enumerate users"},
		{Text: "exit", Description: "Exit FTP enumeration mode"},
	}
	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func ftpEnum() {
	fmt.Println("Entering FTP enumeration mode. Type 'exit' to return.")

	p := prompt.New(
		ftpEnumExecutor,
		ftpEnumCompleter,
		prompt.OptionPrefix("enum/ftp> "),
		prompt.OptionTitle("FTP enumeration mode"),
	)
	p.Run()
}

func enumFtpAnon() {
	disc := tool.EnumAnonymousFtp(config.Target)

	if len(disc) == 0 {
		lib.Red("Unable to enumerate anonymous FTP\n")
	} else {
		for _, d := range disc {
			printDiscoveryDetails(d)
		}
	}

	discoveries = append(discoveries, disc...)
}

// Reverse shell
func shellMode() {
	fmt.Println("Entering shell mode. Type 'exit' to return or 'run' to start listening.")

	p := prompt.New(
		shellExecutor,
		shellCompleter,
		prompt.OptionPrefix("rev> "),
		prompt.OptionTitle("Reverse shell"),
	)
	p.Run()
}

func shellExecutor(in string) {
	in = strings.TrimSpace(in)
	args := strings.Fields(in)

	if len(args) == 0 {
		return
	}

	switch args[0] {
	case "exit":
		fmt.Println("Exiting reverse shell mode...")
		// close connection, if any
		return // Exit FTP mode

	case "set":
		if len(args) < 3 {
			fmt.Println("Usage: set [key] [value]")
			return
		}
		setShellCommand(args[1], args[2])

	case "run":
		restoreTerminalConfig()
		reverseShell()

	default:
		fmt.Printf("Unknown reverse shell command: %s\n", in)
	}
}

func shellCompleter(d prompt.Document) []prompt.Suggest {
	s := []prompt.Suggest{
		{Text: "set", Description: "Set a local variable"},
		{Text: "run", Description: "Start reverse shell"},
		{Text: "exit", Description: "Exit reverse shell mode"},
	}

	// Auto-completion for the 'set' command
	setSubcommands := []prompt.Suggest{
		{Text: "port", Description: "Set the port to listen on"},
		{Text: "shell", Description: "Set the shell to use"},
	}

	// If the user is typing 'set', suggest the subcommands for 'set'
	if strings.HasPrefix(d.TextBeforeCursor(), "set ") {
		return prompt.FilterHasPrefix(setSubcommands, d.GetWordAfterCursorWithSpace(), true)
	}

	return prompt.FilterHasPrefix(s, d.GetWordBeforeCursor(), true)
}

func setShellCommand(key, value string) {
	switch key {
	case "port":
		port, err := strconv.Atoi(value)
		if err != nil {
			fmt.Println("Invalid port:", value)
			return
		}

		shellConfig.Port = &port
		fmt.Printf("Port set to %d\n", port)
	case "shell":
		shellConfig.Shell = &value
		fmt.Printf("Shell set to %s\n", value)
	default:
		fmt.Println("Unknown setting:", key)
	}
}

func reverseShell() {
	fmt.Println("Starting reverse shell...")
	var port int
	var shell string

	// check for config
	if shellConfig.Port == nil {
		port = 4045
	} else {
		port = *shellConfig.Port
	}

	if shellConfig.Shell == nil {
		shell = "/bin/bash"
	} else {
		shell = *shellConfig.Shell
	}

	// check if we have port and shell set
	if err := tool.ReverseShell(port, shell); err != nil {
		fmt.Println("Error starting reverse shell:", err)
	}
}
