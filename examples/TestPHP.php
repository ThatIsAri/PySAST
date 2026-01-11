<?php
// Уязвимость: SQL Injection
$user_input = $_GET['username'];
$query = "SELECT * FROM users WHERE username = '" . $user_input . "'";
mysqli_query($connection, $query); // Должно обнаружиться как PHP-SQLI-001

// Уязвимость: File Inclusion
$page = $_GET['page'];
include($page . '.php'); // Должно обнаружиться как PHP-FI-001

// Уязвимость: Command Injection
$filename = $_POST['filename'];
system("rm " . $filename); // Должно обнаружиться как PHP-CMD-001

// Уязвимость: XSS
echo $_GET['message']; // Должно обнаружиться как PHP-XSS-001

// Уязвимость: RCE
eval($_GET['code']); // Должно обнаружиться как PHP-RCE-001

// Безопасный код
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username");
$stmt->execute(['username' => $user_input]); // Безопасно

$safe_filename = escapeshellarg($filename);
system("rm " . $safe_filename); // Безопасно

echo htmlspecialchars($_GET['message'], ENT_QUOTES, 'UTF-8'); // Безопасно
?>