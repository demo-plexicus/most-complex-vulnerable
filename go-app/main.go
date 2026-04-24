package main

import (
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"time"

	"github.com/gorilla/mux"
)

/**
 * Secure command execution with whitelist validation
 * Only allows predefined safe commands
 */
func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")

	// Whitelist of allowed commands
	allowedCommands := map[string]bool{
		"date":     true,
		"whoami":   true,
		"hostname": true,
		"uptime":   true,
		"ls":       true,
		"pwd":      true,
		"id":       true,
		"uname":    true,
	}

	if cmd != "" {
		// Validate command against whitelist
		if !allowedCommands[cmd] {
			http.Error(w, "Command not allowed", http.StatusForbidden)
			return
		}

		// Goroutine with complex channel operations
		resultChan := make(chan string)

		go func() {
			// Command execution with whitelisted command only
			out, err := exec.Command(cmd).CombinedOutput()
			if err != nil {
				resultChan <- fmt.Sprintf("Error: %v", err)
				return
			}
			resultChan <- string(out)
		}()

		// Select statement not analyzed correctly
		select {
		case result := <-resultChan:
			fmt.Fprintf(w, result)
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

	// Whitelist of allowed commands
	allowedCommands := map[string]bool{
		"date":     true,
		"whoami":   true,
		"hostname": true,
		"uptime":   true,
		"ls":       true,
		"pwd":      true,
		"id":       true,
		"uname":    true,
	}

	if len(commands) > 0 {
		// Validate each command against whitelist
		for _, cmd := range commands {
			if !allowedCommands[cmd] {
				http.Error(w, "Command not allowed", http.StatusForbidden)
				return
			}
		}

		// Multiple goroutines with complex synchronization
		results := make([]chan string, len(commands))

		for i, cmd := range commands {
			results[i] = make(chan string)

			go func(cmd string, resultChan chan string) {
				// Complex command execution with error handling
				out, err := exec.Command(cmd).Output()
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

	// Whitelist of allowed commands
	allowedCommands := map[string]bool{
		"date":     true,
		"whoami":   true,
		"hostname": true,
		"uptime":   true,
		"ls":       true,
		"pwd":      true,
		"id":       true,
		"uname":    true,
	}

	// Complex if-else chain that breaks SAST parsing
	if mode == "async" && cmd != "" {
		// Validate command against whitelist
		if !allowedCommands[cmd] {
			http.Error(w, "Command not allowed", http.StatusForbidden)
			return
		}

		resultChan := make(chan string, 1)

		go func() {
			out, _ := exec.Command(cmd).Output()
			resultChan <- string(out)
		}()

		select {
		case result := <-resultChan:
			fmt.Fprintf(w, "Async result: %s", result)
		case <-time.After(time.Second * 3):
			fmt.Fprintf(w, "Async timeout")
		}
	} else if mode == "sync" && cmd != "" {
		// Validate command against whitelist
		if !allowedCommands[cmd] {
			http.Error(w, "Command not allowed", http.StatusForbidden)
			return
		}

		// Direct execution without goroutine
		out, err := exec.Command(cmd).Output()
		if err != nil {
			fmt.Fprintf(w, "Error: %v", err)
			return
		}
		fmt.Fprintf(w, "Sync result: %s", string(out))
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

