# SAST Testing Guide

This document provides guidance for testing SAST (Static Application Security Testing) tools against the complex vulnerabilities implemented in this monorepo.

## Expected Detection Challenges

### Java Application
- **Vulnerability**: Cross-Site Scripting (XSS)
- **Location**: `java-app/src/main/java/com/vulnerableapp/SearchController.java`
- **Complexity Factors**:
  - Lambda expressions (`p -> p.getName().contains(query)`)
  - Stream processing (`Stream.of(products).filter().map().collect()`)
  - Java 21 string templates (`STR."Results: \\{result}"`)
  - **Expected SAST Failure**: Parser errors in `LambdaLHS()` and string template handling

### PHP Application
- **Vulnerability**: SQL Injection (SQLi)
- **Location**: `php-app/src/UserController.php`
- **Complexity Factors**:
  - Dynamic function calls (`$func = "get_" . $table . "_data"`)
  - Complex casting (`(string)($_GET['type'] ?? 'users')`)
  - String interpolation (`"SELECT * FROM {$table} WHERE name LIKE '%{$input}%'"`)
  - **Expected SAST Failure**: Parser errors in `CastExpression()` and dynamic function resolution

### Go Application
- **Vulnerability**: Remote Code Execution (RCE)
- **Location**: `go-app/main.go`
- **Complexity Factors**:
  - Goroutines (`go func() { ... }`)
  - Channels (`resultChan := make(chan string)`)
  - Select statements (`select { case result := <-resultChan: ... }`)
  - Complex control flow with timeouts
  - **Expected SAST Failure**: Parser errors in `IfStmt()` and `SelectStmt()`

## Testing Procedure

### 1. Build All Applications
```bash
npm run build
```

### 2. Run SAST Tool
Run your SAST tool against the entire monorepo:

```bash
# Example with a generic SAST tool
sast-tool scan . --language java,php,go --output results.json
```

### 3. Analyze Results
Check if the SAST tool detects:
- [ ] Java XSS in SearchController.search() method
- [ ] Java XSS in SearchController.advancedSearch() method
- [ ] PHP SQLi in UserController.search() method
- [ ] PHP SQLi in UserController.advancedSearch() method
- [ ] Go RCE in handler() function
- [ ] Go RCE in advancedHandler() function
- [ ] Go RCE in conditionalHandler() function

### 4. Check for Parser Errors
Look for SAST tool output indicating:
- "Started 2/4 blocks at once" errors
- "Tried to end blocks" errors
- "Unable to fully structure code" messages
- "Could not resolve type clashes"

## Common SAST Limitations Demonstrated

1. **Parser Complexity**: Modern language features (lambdas, templates, goroutines) break traditional parsing
2. **Control Flow Analysis**: Asynchronous operations and dynamic calls evade static analysis
3. **String Analysis**: Complex string concatenation and interpolation patterns
4. **Type Resolution**: Dynamic function calls and method invocations

## Expected Outcome

Most SAST tools should:
- ❌ Fail to detect the Java XSS due to lambda and template complexity
- ❌ Fail to detect the PHP SQLi due to dynamic function calls
- ❌ Fail to detect the Go RCE due to goroutine and channel complexity
- ⚠️ Show parser errors and incomplete analysis

## Improving SAST Detection

To improve detection of these vulnerabilities, SAST tools need:
- Better support for modern language features
- Enhanced control flow analysis for asynchronous operations
- Improved string analysis for complex concatenation patterns
- Advanced type inference for dynamic function calls