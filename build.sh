#!/bin/bash

# Complex Vulnerable Monorepo Build Script
# This script builds all applications in the monorepo

echo "Building Complex Vulnerable Monorepo..."

# Build Java application
echo "Building Java application..."
cd java-app
if command -v mvn &> /dev/null; then
    mvn compile
    if [ $? -eq 0 ]; then
        echo "✓ Java application built successfully"
    else
        echo "✗ Java application build failed"
    fi
else
    echo "⚠ Maven not found, skipping Java build"
fi
cd ..

# Build PHP application
echo "Building PHP application..."
cd php-app
if command -v composer &> /dev/null; then
    composer install --no-dev
    if [ $? -eq 0 ]; then
        echo "✓ PHP dependencies installed"
    else
        echo "✗ PHP dependencies installation failed"
    fi
else
    echo "⚠ Composer not found, skipping PHP dependency installation"
fi
cd ..

# Build Go application
echo "Building Go application..."
cd go-app
if command -v go &> /dev/null; then
    go build -o app
    if [ $? -eq 0 ]; then
        echo "✓ Go application built successfully"
    else
        echo "✗ Go application build failed"
    fi
else
    echo "⚠ Go compiler not found, skipping Go build"
fi
cd ..

echo ""
echo "Build complete!"
echo ""
echo "Applications ready for SAST testing:"
echo "- Java: java-app/src/main/java/"
echo "- PHP: php-app/src/"
echo "- Go: go-app/main.go"
echo ""
echo "Run your SAST tool against this directory to test detection capabilities."