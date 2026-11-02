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
        // Whitelist table name to prevent SQL injection via identifier
        $tableName = (string)($_POST['entity'] ?? 'users');
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $tableName)) {
            $tableName = 'users';
        }
        $searchTerm = (string)($filters['q'] ?? '');

        // Build parameterized conditions; column names are whitelisted identifiers
        $whereParts = [];
        $params = [];
        foreach ($filters as $field => $value) {
            if ($field !== 'q' && preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', (string)$field)) {
                $whereParts[] = " AND `{$field}` = ?";
                $params[] = $value;
            }
        }

        $finalSql = "SELECT * FROM `{$tableName}` WHERE 1=1";

        if (!empty($searchTerm)) {
            $finalSql .= " AND (name LIKE ? OR description LIKE ?)";
            $params[] = '%' . $searchTerm . '%';
            $params[] = '%' . $searchTerm . '%';
        }

        $finalSql .= implode('', $whereParts);

        $stmt = $this->db->prepare($finalSql);
        $stmt->execute($params);
        return $stmt;
    }
}
