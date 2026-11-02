<?php

namespace VulnerableApp;

/**
 * UserController with complex SQLi vulnerability using dynamic functions and complex strings
 * This demonstrates parser failures in CastExpression() and dynamic function resolution
 */
class UserController {
    private $db;

    public function __construct($db) {
        $this->db = $db;
    }

    /**
     * Complex SQLi vulnerability with dynamic function calls and string interpolation
     * The parser fails in CastExpression() - "Started 4 blocks at once"
     */
    public function search($input) {
        // Complex casting that breaks SAST parsers
        $table = (string)($_GET['type'] ?? 'users'); // Cast expression complexity

        // Dynamic function construction - not traced by LSTUsagesVisitor
        $func = "get_" . $table . "_data"; // String concatenation for function name

        // Call dynamic function - SAST cannot resolve this
        $data = $this->$func($input); // Method call through variable

        // Complex string interpolation with SQL injection
        $sql = "SELECT * FROM {$table} WHERE name LIKE '%{$input}%'"; // SQLi vulnerability

        return $this->db->query($sql);
    }

    /**
     * Dynamic method that gets called through variable
     */
    private function get_users_data($input) {
        return [];
    }

    /**
     * Another dynamic method
     */
    private function get_products_data($input) {
        return [];
    }

    /**
     * Additional complex method with nested string operations
     */
    public function advancedSearch($filters) {
        // Complex variable handling with multiple operations
        $tableName = (string)($_POST['entity'] ?? 'users');
        $searchTerm = (string)($filters['q'] ?? '');

        // Whitelist the table name; it cannot be a bound parameter
        $allowedTables = ['users', 'products'];
        $tableName = in_array($tableName, $allowedTables, true) ? $tableName : 'users';

        // Build conditions with placeholders; values are never interpolated into the SQL
        $conditions = [];
        $params = [];
        foreach ($filters as $field => $value) {
            if ($field !== 'q') {
                $safeField = preg_replace('/[^a-zA-Z0-9_]/', '', $field);
                if ($safeField !== '') {
                    $conditions[] = "{$safeField} = ?";
                    $params[] = $value;
                }
            }
        }

        $sql = "SELECT * FROM {$tableName}";
        if (!empty($conditions)) {
            $sql .= " WHERE " . implode(" AND ", $conditions);
        }

        if (!empty($searchTerm)) {
            $sql .= " AND (name LIKE ? OR description LIKE ?)";
            $params[] = '%' . $searchTerm . '%';
            $params[] = '%' . $searchTerm . '%';
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);
        return $stmt;
    }
}
