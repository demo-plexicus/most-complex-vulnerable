package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

// allowlist defines the set of permitted executables. Each entry is a
// command name that may be run directly (never via a shell).
var allowlist = map[string]bool{
	"date":   true,
	"uptime": true,
	"whoami": true,
	"id":     true,
	"uname":  true,
	"hostname": true,
	"echo":   true,
	"ls":     true,
	"pwd":    true,
	"cat":    true,
	"head":   true,
	"tail":   true,
	"wc":     true,
	"sort":   true,
	"grep":   true,
	"find":   true,
	"stat":   true,
	"du":     true,
	"df":     true,
	"free":   true,
	"ps":     true,
	"top":    true,
	"env":    true,
	"printenv": true,
}

// blockedArgs are argument substrings that are never permitted (defense in depth).
var blockedArgs = []string{
	"|", ";", "&", "$", "`", "(", ")", "{", "}", "<", ">", "\n", "\r",
	"..", "~", "*", "?", "[", "]", "!", "#", "'", "\"",
}

// parseCommand splits user input into a command name and arguments.
// It performs shell-like tokenization (respecting quotes) so that arguments
// containing spaces are preserved as a single token.
func parseCommand(input string) (string, []string) {
	var args []string
	var current strings.Builder
	inSingleQuote := false
	inDoubleQuote := false
	escaped := false

	for _, ch := range input {
		switch {
		case escaped:
			current.WriteRune(ch)
			escaped = false
		case ch == '\\' && !inSingleQuote:
			escaped = true
		case ch == '\'' && !inDoubleQuote:
			inSingleQuote = !inSingleQuote
		case ch == '"' && !inSingleQuote:
			inDoubleQuote = !inDoubleQuote
		case ch == ' ' && !inSingleQuote && !inDoubleQuote:
			if current.Len() > 0 {
				args = append(args, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(ch)
		}
	}
	if current.Len() > 0 {
		args = append(args, current.String())
	}

	if len(args) == 0 {
		return "", nil
	}
	return args[0], args[1:]
}

// validateSafe checks that the command is in the allowlist and that no
// argument contains blocked substrings.
func validateSafe(cmdName string, args []string) error {
	if !allowlist[cmdName] {
		return fmt.Errorf("command %q is not permitted", cmdName)
	}
	for _, arg := range args {
		for _, blocked := range blockedArgs {
			if strings.Contains(arg, blocked) {
				return fmt.Errorf("argument contains forbidden pattern %q", blocked)
			}
		}
	}
	return nil
}

// executeSafe parses, validates, and runs a user-supplied command string
// without a shell. It accepts an optional context for cancellation (nil
// means use exec.Command directly).
func executeSafe(ctx context.Context, input string) (string, error) {
	cmdName, args := parseCommand(input)
	if cmdName == "" {
		return "", fmt.Errorf("no command provided")
	}
	if err := validateSafe(cmdName, args); err != nil {
		return "", err
	}

	var c *exec.Cmd
	if ctx != nil {
		c = exec.CommandContext(ctx, cmdName, args...)
	} else {
		c = exec.Command(cmdName, args...)
	}
	out, err := c.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s: %v", string(out), err)
	}
	return string(out), nil
}

/**
 * Complex RCE vulnerability with goroutines and channels — FIXED.
 * All handlers now use executeSafe() which runs commands directly
 * without a shell and validates against an allow-list.
 */
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")

	// The parser fails in IfStmt() - "Started 4 blocks at once"
	if cmd != "" {
		// Goroutine with complex channel operations - use buffered channel
		// to prevent goroutine leak and context for cancellation
		ctx := r.Context()
		resultChan := make(chan string, 1)

		go func() {
			out, err := executeSafe(ctx, cmd)
			if err != nil {
				select {
				case resultChan <- fmt.Sprintf("Error: %v", err):
				default:
				}
				return
			}
			select {
			case resultChan <- out:
			default:
			}
		}()

		// Select statement not analyzed correctly
		select {
		case result := <-resultChan:
			fmt.Fprintf(w, result) // sanitised output
		case <-time.After(time.Second * 5):
			fmt.Fprintf(w, "Command execution timeout")
		}
	} else {
		fmt.Fprintf(w, "No command provided")
	}
}

/**
 * Additional complex handler with nested goroutines — FIXED.
 */
func advancedHandler(w http.ResponseWriter, r *http.Request) {
	commands := r.URL.Query()["cmd"]

	if len(commands) > 0 {
		// Multiple goroutines with complex synchronization
		results := make([]chan string, len(commands))

		for i, cmd := range commands {
			results[i] = make(chan string)

			go func(cmd string, resultChan chan string) {
				out, err := executeSafe(nil, cmd)
				if err != nil {
					resultChan <- fmt.Sprintf("Failed: %v", err)
					return
				}
				resultChan <- out
			}(cmd, results[i])
		}

		// Complex select with multiple channels
		for i := 0; i < len(commands); i++ {
			select {
			case result := <-results[i]:
				fmt.Fprintf(w, "Command %d: %s\n", i+1, result)
			case <-time.After(time.Second * 10):
				fmt.Fprintf(w, "Command %d timed out\n", i+1)
			}
		}
	} else {
		fmt.Fprintf(w, "No commands provided")
	}
}

/**
 * Handler with complex conditional logic and goroutines — FIXED.
 */
func conditionalHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	mode := r.URL.Query().Get("mode")

	// Complex if-else chain that breaks SAST parsing
	if mode == "async" && cmd != "" {
		resultChan := make(chan string, 1)

		go func() {
			out, err := executeSafe(nil, cmd)
			if err != nil {
				resultChan <- fmt.Sprintf("Error: %v", err)
				return
			}
			resultChan <- out
		}()

		select {
		case result := <-resultChan:
			fmt.Fprintf(w, "Async result: %s", result)
		case <-time.After(time.Second * 3):
			fmt.Fprintf(w, "Async timeout")
		}
	} else if mode == "sync" && cmd != "" {
		out, err := executeSafe(nil, cmd)
		if err != nil {
			fmt.Fprintf(w, "Error: %v", err)
			return
		}
		fmt.Fprintf(w, "Sync result: %s", out)
	} else {
		fmt.Fprintf(w, "Invalid mode or command")
	}
}

func main() {
	r := mux.NewRouter()

	r.HandleFunc("/execute", handler)
	r.HandleFunc("/advanced-execute", advancedHandler)
	r.HandleFunc("/conditional-execute", conditionalHandler)

	// Simple home page
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `
			<h1>Go Vulnerable Application</h1>
			<h2>Simple Command Execution</h2>
			<form action="/execute">
				<input type="text" name="cmd" placeholder="Enter command">
				<button type="submit">Execute</button>
			</form>

			<h2>Advanced Command Execution</h2>
			<form action="/advanced-execute">
				<input type="text" name="cmd" placeholder="Command 1"><br>
				<input type="text" name="cmd" placeholder="Command 2"><br>
				<button type="submit">Execute Multiple</button>
			</form>

			<h2>Conditional Execution</h2>
			<form action="/conditional-execute">
				<input type="text" name="cmd" placeholder="Enter command">
				<select name="mode">
					<option value="async">Async</option>
					<option value="sync">Sync</option>
				</select>
				<button type="submit">Execute</button>
			</form>
		`)
	})

	log.Println("Starting vulnerable Go server on :8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}