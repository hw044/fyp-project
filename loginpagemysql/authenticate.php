<?php
session_start();
$servername = "localhost";
$username = "root";
$password = "toor";
$dbname = "login_system";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$username = $_POST['username'];
$password = $_POST['password'];

// Here, you should use prepared statements to avoid SQL injection
$sql = "SELECT * FROM users WHERE username = ? AND password = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    $_SESSION['loggedin'] = true;
    $_SESSION['username'] = $username;
    echo "Login successful!";
} else {
    echo "Invalid username or password";
}
$conn->close();
?>
