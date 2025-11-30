# Complex Vulnerable Monorepo

A monorepo containing advanced vulnerabilities designed to test SAST (Static Application Security Testing) tools. These vulnerabilities leverage complex language features that often evade detection due to parser limitations and fractal complexity.

## Vulnerabilities Implemented

### 1. Java: XSS with Lambda Expressions and String Templates
- **Location**: `java-app/src/main/java/com/vulnerableapp/`
- **Vulnerability**: Cross-Site Scripting (XSS)
- **Complexity**: Lambda expressions, stream processing, Java 21 string templates
- **Why it evades detection**: Parser fails on `LambdaLHS()` and string templates

### 2. PHP: SQLi with Dynamic Functions and Complex Strings
- **Location**: `php-app/src/`
- **Vulnerability**: SQL Injection (SQLi)
- **Complexity**: Dynamic function calls, string interpolation, complex casting
- **Why it evades detection**: Parser fails on `CastExpression()` and dynamic function resolution

### 3. Go: RCE with Goroutines and Channels
- **Location**: `go-app/src/`
- **Vulnerability**: Remote Code Execution (RCE)
- **Complexity**: Goroutines, channels, select statements
- **Why it evades detection**: Parser fails on `IfStmt()` and complex control flow

## Testing SAST Tools

To test your SAST tool against these vulnerabilities:

```bash
# Clone and build the monorepo
npm install
npm run build

# Run your SAST tool against the entire monorepo
# Example with a hypothetical SAST tool:
sast-tool scan . --language java,php,go
```

## Expected Results

Most SAST tools should struggle to detect these vulnerabilities due to:

1. **Parser Limitations**: "Started 2/4 blocks at once" errors
2. **Modern Language Features**: Lambdas, templates, goroutines
3. **Complex Control Flow**: Asynchronous operations, dynamic calls
4. **String Complexity**: Interpolated strings, template literals

## Structure

```
complex-vulnerable-monorepo/
├── java-app/          # Java Spring Boot application
├── php-app/           # PHP web application
├── go-app/            # Go HTTP server
├── package.json       # Monorepo configuration
└── README.md          # This file
```

## Security Note

This repository contains intentionally vulnerable code for security testing purposes only. Do not deploy this code in production environments.