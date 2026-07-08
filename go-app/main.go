package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/mux"
)

/**
 * Complex RCE vulnerability with goroutines and channels
 * This demonstrates parser failures in IfStmt() and SelectStmt()
 */
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")

	// The parser fails in IfStmt() - "Started 4 blocks at once"
	if cmd != "" {
		// Goroutine with complex channel operations
		resultChan := make(chan string)

		go func() {
			// Command execution not detected by SAST
			out, err := safeExec(cmd)
			if err != nil {
				resultChan <- fmt.Sprintf("Error: %v", err)
				return
			}
			resultChan <- string(out) // RCE vulnerability
		}()

		// Select statement not analyzed correctly
		select {
		case result := <-resultChan:
			fmt.Fprintf(w, result) // Command output rendered directly
		case <-time.After(time.Second * 5):
			fmt.Fprintf(w, "Command execution timeout")
		}
	} else {
		fmt.Fprintf(w, "No command provided")
	}
}

/**
 * Additional complex handler with nested goroutines
 */
func advancedHandler(w http.ResponseWriter, r *http.Request) {
	commands := r.URL.Query()["cmd"]

	if len(commands) > 0 {
		// Multiple goroutines with complex synchronization
		results := make([]chan string, len(commands))

		for i, cmd := range commands {
			results[i] = make(chan string)

			go func(cmd string, resultChan chan string) {
				// Complex command execution with error handling
				out, err := safeExec(cmd)
				if err != nil {
					resultChan <- fmt.Sprintf("Failed: %v", err)
					return
				}
				resultChan <- string(out)
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
 * Handler with complex conditional logic and goroutines
 */
func conditionalHandler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	mode := r.URL.Query().Get("mode")

	// Complex if-else chain that breaks SAST parsing
	if mode == "async" && cmd != "" {
		resultChan := make(chan string, 1)

		go func() {
			out, _ := safeExec(cmd)
			resultChan <- string(out)
		}()

		select {
		case result := <-resultChan:
			fmt.Fprintf(w, "Async result: %s", result)
		case <-time.After(time.Second * 3):
			fmt.Fprintf(w, "Async timeout")
		}
	} else if mode == "sync" && cmd != "" {
		// Direct execution without goroutine
		out, err := safeExec(cmd)
		if err != nil {
			fmt.Fprintf(w, "Error: %v", err)
			return
		}
		fmt.Fprintf(w, "Sync result: %s", string(out))
	} else {
		fmt.Fprintf(w, "Invalid mode or command")
	}
}

// safeExec runs a command from user input without a shell, using an allow-list
// of permitted commands. The input string is split on whitespace into the command
// name and its arguments, and passed directly to exec.Command (no shell invocation).
func safeExec(input string) ([]byte, error) {
	if input == "" {
		return nil, fmt.Errorf("empty command")
	}

	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	cmdName := parts[0]
	var args []string
	if len(parts) > 1 {
		args = parts[1:]
	}

	// Allow-list of permitted commands — only these may be executed.
	allowedCommands := map[string]bool{
		"echo":   true,
		"date":   true,
		"whoami": true,
		"hostname": true,
		"uptime": true,
		"uname":  true,
		"id":     true,
		"ls":     true,
		"pwd":    true,
		"cat":    true,
		"head":   true,
		"tail":   true,
		"wc":     true,
		"du":     true,
		"df":     true,
		"ps":     true,
		"env":    true,
	}

	if !allowedCommands[cmdName] {
		return nil, fmt.Errorf("command not allowed: %s", cmdName)
	}

	return exec.Command(cmdName, args...).CombinedOutput()
}

func main() {
	r := mux.NewRouter()


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