<?php
// Include the configuration file
include 'config.php';

// Start the session
session_start();

// Create connection to the database
$con = new mysqli(DB_HOST, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Set the timezone to Asia/Jakarta
date_default_timezone_set('Asia/Jakarta');

// Check connection
if ($con->connect_error) {
    die("Connection failed: " . $con->connect_error);
}

//echo "User ID: ";
?>