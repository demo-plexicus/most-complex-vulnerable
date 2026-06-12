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

        // Allow-list for table names to prevent SQL injection on dynamic identifiers
        $allowedTables = ['users', 'products'];
        $tableName = in_array($table, $allowedTables, true) ? $table : 'users';

        // Use a prepared statement to prevent SQL injection
        $sql = "SELECT * FROM {$tableName} WHERE name LIKE ?";
        $stmt = $this->db->prepare($sql);
        $stmt->execute(['%' . $input . '%']);

        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
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
     * Now fixed to use prepared statements and input validation
     */
    public function advancedSearch($filters) {
        // Allow-list for table names
        $allowedTables = ['users', 'products'];
        $rawTable = (string)($filters['entity'] ?? 'users');
        $tableName = in_array($rawTable, $allowedTables, true) ? $rawTable : 'users';

        $searchTerm = (string)($filters['q'] ?? '');

        // Build parameterized query
        $sql = "SELECT * FROM {$tableName} WHERE 1=1";
        $params = [];

        // Only allow known, safe filter fields
        $allowedFields = ['category', 'status'];
        foreach ($filters as $field => $value) {
            if ($field !== 'q' && $field !== 'entity' && in_array($field, $allowedFields, true)) {
                $sql .= " AND {$field} = ?";
                $params[] = $value;
            }
        }

        if (!empty($searchTerm)) {
            $sql .= " AND (name LIKE ? OR description LIKE ?)";
            $params[] = '%' . $searchTerm . '%';
            $params[] = '%' . $searchTerm . '%';
        }

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        return $stmt->fetchAll(\PDO::FETCH_ASSOC);
    }
}

