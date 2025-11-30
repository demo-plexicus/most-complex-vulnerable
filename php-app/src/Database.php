<?php

namespace VulnerableApp;

/**
 * Mock database class for demonstration
 */
class Database {
    public function query($sql) {
        // In a real application, this would execute the SQL
        // For demonstration, we just return mock data
        return [
            ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            ['id' => 2, 'name' => 'Another User', 'email' => 'another@example.com']
        ];
    }
}