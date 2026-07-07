<?php

namespace VulnerableApp;

/**
 * Mock database class with secure parameterized query support
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

    /**
     * Execute a parameterized SQL query.
     * @param string $sql The SQL query with ? placeholders
     * @param array $params The parameter values to bind
     * @return array The query results
     */
    public function queryParams($sql, $params = []) {
        // Build the effective SQL by safely replacing placeholders with quoted values.
        // In a real PDO implementation this would use prepare/execute.
        foreach ($params as $val) {
            $pos = strpos($sql, '?');
            if ($pos !== false) {
                $sql = substr_replace($sql, "'" . addslashes((string)$val) . "'", $pos, 1);
            }
        }
        return $this->query($sql);
    }
}
