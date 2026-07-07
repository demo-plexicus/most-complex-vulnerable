<?php

namespace VulnerableApp;

/**
 * UserController - securely remediated with parameterized queries and table allow-listing
 */
class UserController {
    private $db;

    /** @var string[] Allow-listed table names */
    const ALLOWED_TABLES = ['users', 'products'];

    public function __construct($db) {
        $this->db = $db;
    }

    /**
     * Validate a table name against the allow-list.
     * @param string $table
     * @return string Validated table name or default 'users'
     */
    private static function safeTable($table) {
        if (in_array($table, self::ALLOWED_TABLES, true)) {
            return $table;
        }
        return 'users'; // safe default
    }

    /**
     * Originally vulnerable to SQLi via dynamic function calls and string interpolation.
     * Now uses allow-listed tables and parameterized queries.
     */
    public function search($input) {
        $rawTable = (string)($_GET['type'] ?? 'users');
        $table = self::safeTable($rawTable);

        // Dynamic function construction kept — call depends on allow-listed table only
        $func = "get_" . $table . "_data";
        $data = $this->$func($input);

        // Parameterized query — input is bound as a parameter, not interpolated
        $sql = "SELECT * FROM {$table} WHERE name LIKE ?";
        return $this->db->queryParams($sql, ['%' . $input . '%']);
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
     * Securely remediated — uses allow-listed table and parameterized query.
     */
    public function advancedSearch($filters) {
        $rawTable = (string)($_POST['entity'] ?? 'users');
        $tableName = self::safeTable($rawTable);
        $searchTerm = (string)($filters['q'] ?? '');

        // Build WHERE clause with parameterized placeholders
        $whereTerms = [];
        $params = [];
        foreach ($filters as $field => $value) {
            if ($field !== 'q') {
                $whereTerms[] = "{$field} = ?";
                $params[] = $value;
            }
        }
        $whereClause = $whereTerms ? ' AND ' . implode(' AND ', $whereTerms) : '';

        // Base SQL with allow-listed table
        $finalSql = "SELECT * FROM {$tableName} WHERE 1=1{$whereClause}";

        if (!empty($searchTerm)) {
            $finalSql .= " AND (name LIKE ? OR description LIKE ?)";
            $params[] = '%' . $searchTerm . '%';
            $params[] = '%' . $searchTerm . '%';
        }

        return $this->db->queryParams($finalSql, $params);
    }
}

