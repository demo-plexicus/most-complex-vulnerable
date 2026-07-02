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

        // Allow-list for table names to prevent SQL injection on dynamic identifiers
        $allowedTables = ['users', 'products'];
        if (!in_array($table, $allowedTables, true)) {
            $table = 'users';
        }

        // Dynamic function construction - not traced by LSTUsagesVisitor
        $func = "get_" . $table . "_data"; // String concatenation for function name

        // Call dynamic function - SAST cannot resolve this
        $data = $this->$func($input); // Method call through variable

        // Parameterized query to prevent SQL injection
        $sql = "SELECT * FROM {$table} WHERE name LIKE ?"; // SQLi vulnerability fixed with prepared statement
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['%' . $input . '%']);
        return $stmt;
    }

    /**

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

        // Multiple string concatenations and interpolations
        $whereClause = "";
        foreach ($filters as $field => $value) {
            if ($field !== 'q') {
                $whereClause .= " AND {$field} = '{$value}'"; // Additional SQLi
            }
        }

        // Complex SQL construction with multiple vulnerabilities
        $finalSql = "SELECT * FROM {$tableName} WHERE 1=1 {$whereClause}";

        if (!empty($searchTerm)) {
            $finalSql .= " AND (name LIKE '%{$searchTerm}%' OR description LIKE '%{$searchTerm}%')";
        }

        return $this->db->query($finalSql);
    }
}