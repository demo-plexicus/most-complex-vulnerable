<?php

namespace VulnerableApp;

/**
 * Mock database class for demonstration
 */
class Database {
    private \PDO $pdo;

    public function __construct() {
        // Use SQLite in-memory for demonstration purposes
        $this->pdo = new \PDO('sqlite::memory:');
        $this->pdo->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);
        // Create and seed a users table for demonstration
        $this->pdo->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, name TEXT, email TEXT)");
        $this->pdo->exec("INSERT INTO users (id, name, email) VALUES (1, 'Test User', 'test@example.com'), (2, 'Another User', 'another@example.com')");
    }

    public function getPdo(): \PDO {
        return $this->pdo;
    }

    public function prepare(string $sql): \PDOStatement|false {
        return $this->pdo->prepare($sql);
    }

    public function query($sql) {
        // Existing compatibility for non-parameterized calls
        $stmt = $this->pdo->query($sql);
        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }
}
