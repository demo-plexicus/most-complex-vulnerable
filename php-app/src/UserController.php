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
        $table = (string)($_GET['type'] ?? 'users');

        // Allow-list the table name to prevent SQL injection on dynamic identifiers
        $allowedTables = ['users', 'products'];
        if (!in_array($table, $allowedTables, true)) {
            $table = 'users';
        }

        // Dynamic function construction
        $func = "get_" . $table . "_data";

        // Call dynamic function
        $data = $this->$func($input);

        // Use parameterized query instead of string interpolation
        $sql = "SELECT * FROM {$table} WHERE name LIKE ?";

        return $this->db->executeQuery($sql, ['%' . $input . '%']);
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

        // Allow-list the table name
        $allowedTables = ['users', 'products'];
        if (!in_array($tableName, $allowedTables, true)) {
            $tableName = 'users';
        }

        // Use parameterized query with bound parameters
        $params = [];
        $conditions = [];

        // Allow-listed fields for dynamic column names
        $allowedFields = ['category', 'status', 'name', 'description'];

        foreach ($filters as $field => $value) {
            if ($field !== 'q' && $field !== 'entity' && $field !== 'action') {
                if (in_array($field, $allowedFields, true)) {
                    $conditions[] = "{$field} = ?";
                    $params[] = $value;
                }
            }
        }

        $whereClause = '';
        if (!empty($conditions)) {
            $whereClause = ' AND ' . implode(' AND ', $conditions);
        }

        $finalSql = "SELECT * FROM {$tableName} WHERE 1=1{$whereClause}";

        if (!empty($searchTerm)) {
            $finalSql .= " AND (name LIKE ? OR description LIKE ?)";
            $params[] = '%' . $searchTerm . '%';
            $params[] = '%' . $searchTerm . '%';
        }

        return $this->db->executeQuery($finalSql, $params);
    }
}

