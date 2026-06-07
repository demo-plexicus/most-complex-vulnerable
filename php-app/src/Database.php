<?php

namespace VulnerableApp;

/**
 * Mock database class for demonstration
 */
class Database {
    private $pdo;

    public function __construct() {
        // In a real app, this would connect to a real database
        // For demonstration, we simulate PDO methods
    }

    public function query($sql) {
        // In a real application, this would execute the SQL
        // For demonstration, we just return mock data
        return [
            ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            ['id' => 2, 'name' => 'Another User', 'email' => 'another@example.com']
        ];
    }

    /**
     * Simulate a prepared statement with parameter binding
     * In a real app, this would use PDO::prepare + execute
     */
    public function executeQuery($sql, $params = []) {
        // In a real app: $stmt = $pdo->prepare($sql); $stmt->execute($params); return $stmt->fetchAll();
        // For demonstration, we just return mock data
        return [
            ['id' => 1, 'name' => 'Test User', 'email' => 'test@example.com'],
            ['id' => 2, 'name' => 'Another User', 'email' => 'another@example.com']
        ];
    }
}
