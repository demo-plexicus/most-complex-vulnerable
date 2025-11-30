<?php

require_once 'vendor/autoload.php';

use VulnerableApp\UserController;
use VulnerableApp\Database;

// Simple router for demonstration
$db = new Database();
$controller = new UserController($db);

// Handle search request
if (isset($_GET['action']) && $_GET['action'] === 'search') {
    $input = $_GET['query'] ?? '';
    $results = $controller->search($input);

    header('Content-Type: application/json');
    echo json_encode($results);
    exit;
}

// Handle advanced search
if (isset($_POST['action']) && $_POST['action'] === 'advanced-search') {
    $results = $controller->advancedSearch($_POST);

    header('Content-Type: application/json');
    echo json_encode($results);
    exit;
}

?>
<!DOCTYPE html>
<html>
<head>
    <title>PHP Vulnerable App</title>
</head>
<body>
    <h1>PHP Vulnerable Application</h1>

    <h2>Simple Search</h2>
    <form method="get">
        <input type="hidden" name="action" value="search">
        <input type="text" name="query" placeholder="Search query">
        <select name="type">
            <option value="users">Users</option>
            <option value="products">Products</option>
        </select>
        <button type="submit">Search</button>
    </form>

    <h2>Advanced Search</h2>
    <form method="post">
        <input type="hidden" name="action" value="advanced-search">
        <input type="text" name="q" placeholder="Search term">
        <input type="text" name="category" placeholder="Category">
        <input type="text" name="status" placeholder="Status">
        <select name="entity">
            <option value="users">Users</option>
            <option value="products">Products</option>
        </select>
        <button type="submit">Advanced Search</button>
    </form>
</body>
</html>