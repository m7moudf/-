<?php
// Check if the form has been submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Retrieve form data
    $name = test_input($_POST["name"]);
    $email = test_input($_POST["email"]);
    $password = test_input($_POST["password"]);
    $gender = test_input($_POST["gender"]);
    $remember_me = test_input($_POST["remember_me"]);

    // Validate name
    if (!preg_match("/^[a-zA-Z ]*$/", $name)) {
        die("Invalid name format");
    }

    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format");
    }

    // Validate password
    if (strlen($password) < 8) {
        die("Password must be at least 8 characters long");
    }

    // Validate gender
    if ($gender != "male" && $gender != "female" && $gender != "other") {
        die("Invalid gender value");
    }

    // Validate image size
    if ($_FILES["image"]["size"] > 1000000) {
        die("Image size must be less than 1MB");
    }

    // Save image to server
    $image_path = "uploads/" . basename($_FILES["image"]["name"]);
    if (!move_uploaded_file($_FILES["image"]["tmp_name"], $image_path)) {
        die("Failed to upload image");
    }
    // Hash password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Connect to database
    $servername = "localhost";
    $username = "username";
    $password = "password";
    $dbname = "database_name";

    $conn = new mysqli($servername, $username, $password, $dbname);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Insert data into database
    $stmt = $conn->prepare("INSERT INTO users (name, email, password, gender, remember_me, image_path) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssss", $name, $email, $password_hash, $gender, $remember_me, $image_path);

    if ($stmt->execute()) {
        echo "Registration successful";
    } else {
        echo "Error: " . $stmt->error;
    }
}

// Check if the form has been submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {

    // Retrieve form data and sanitize input
    $name = htmlspecialchars($_POST["name"]);
    $email = htmlspecialchars($_POST["email"]);
    $password = htmlspecialchars($_POST["password"]);
    $gender = htmlspecialchars($_POST["gender"]);
    $remember_me = isset($_POST["remember_me"]) ? 1 : 0;

    // Validate name
    if (!preg_match("/^[a-zA-Z ]*$/", $name)) {
        die("Invalid name format");
    }

    // Validate email
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die("Invalid email format");
    }

    // Validate password
    if (strlen($password) < 8) {
        die("Password must be at least 8 characters long");
    }

    // Validate gender
    if ($gender != "male" && $gender != "female" && $gender != "other") {
        die("Invalid gender value");
    }

    // Validate image size
    if ($_FILES["image"]["size"] > 1000000) {
        die("Image size must be less than 1MB");
    }

    // Save image to server
    $image_path = "uploads/" . basename($_FILES["image"]["name"]);
    if (!move_uploaded_file($_FILES["image"]["tmp_name"], $image_path)) {
        die("Failed to upload image");
    }

    // Hash password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Connect to database
    $servername = "localhost";
    $username = "username";
    $password = "password";
    $dbname = "database_name";

    $conn = new mysqli($servername, $username, $password, $dbname);

    // Check connection
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }

    // Use prepared statements to prevent SQL Injection
    $stmt = $conn->prepare("INSERT INTO users (name, email, password, gender, remember_me, image_path) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("ssssis", $name, $email, $password_hash, $gender, $remember_me, $image_path);

    if ($stmt->execute()) {
        echo "Registration successful";
    } else {
        echo "Error: " . $stmt->error;
    }

    // Close statement and connection
    $stmt->close();
    $conn->close();
}
