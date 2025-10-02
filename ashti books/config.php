<?php
// پەیوەندی بە بنکەی داتاوە
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "db_ashti";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname;charset=utf8mb4", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    echo "هەڵەی پەیوەندی: " . $e->getMessage();
    die();
}

// Start session at the very beginning
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Helper functions
function isLoggedIn() {
    return isset($_SESSION['admin_id']);
}

function getAdminInfo() {
    if (!isLoggedIn()) {
        return null;
    }
    return [
        'id' => $_SESSION['admin_id'],
        'name' => $_SESSION['admin_name'],
        'admin_type' => $_SESSION['admin_type']
    ];
}

function clean_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data);
    return $data;
}

// فەنکشنی چەکردنی سیشن
function check_admin_session() {
    if (!isset($_SESSION['admin_id'])) {
        header("Location: admin.php");
        exit();
    }
}

// Site constants
define('GOOGLE_MAPS_EMBED', 'https://www.google.com/maps/embed?pb=YOUR_MAPS_EMBED_CODE');
define('SITE_NAME_KURDISH', 'کتێبخانەی ئاشتی - هەولێر');
define('SITE_NAME_ENGLISH', 'Ashti Books - Erbil');
?>