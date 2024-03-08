<?php

require_once 'connection.php';
require 'functions.php';

// Get client IP
$client_ip = getClientIp();

// Rate limit settings
$max_attempts = 3;
$lockout_time = 300; // seconds

// Retrieve stored attempts and timestamp from the database for the client IP address
// And check if the IP address is already in the database with a failed login attempt which is result = 0
// So that we can update the last attempt time and the number of attempts
// So the client IP with successful login attempt won't be affected
$stmt = mysqli_prepare($con, "SELECT id_attempts, attempts, last_attempt_time, result FROM login_attempts WHERE ip_address = ? AND result = ? LIMIT 1");
mysqli_stmt_bind_param($stmt, "s", $client_ip, 0);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);

// Check if the IP address is already in the database
if (mysqli_stmt_num_rows($stmt) > 0) {
    mysqli_stmt_bind_result($stmt, $id_attempts, $attempts, $last_attempt_time, $result);
    mysqli_stmt_fetch($stmt);

    // Set id_attempts in the session
    $_SESSION['id_attempts'] = $id_attempts;

    // Update the last attempt count and time
    $_SESSION['login_attempts'] = $attempts;
    $_SESSION['last_login_attempt_time'] = $last_attempt_time;

    // Calculate the elapsed time since the last attempt
    $elapsed_time = time() - $last_attempt_time;

    // Check if the lockout time has expired
    if ($elapsed_time < $lockout_time && $attempts >= $max_attempts) {
        $remaining_time = $lockout_time - $elapsed_time;

        // Send a JSON response indicating failure with an error message
        $error_message = "You cannot log in for " . floor($remaining_time / 60) . " minutes and " . $remaining_time % 60 . " seconds. Please try again later.";
        echo json_encode(['success' => false, 'error_message' => $error_message]);
        exit();
    }
}

// Set the session counter for login attempts
if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
}

// Check if there is a previous delay that needs to be reset
if (isset($_SESSION['last_login_attempt_time'])) {
    $elapsed_time = time() - $_SESSION['last_login_attempt_time'];
    if ($elapsed_time >= 300) {
        // Reset login attempts after 5 minutes
        $_SESSION['login_attempts'] = 0;
        unset($_SESSION['last_login_attempt_time']);
    }
}

// Initialize the error message
$error_message = "";

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Get the form data
    $username_email = mysqli_real_escape_string($con, $_POST['username_email']);
    $password = mysqli_real_escape_string($con, $_POST['password']);

    // Check if login attempts exceed a threshold
    if ($_SESSION['login_attempts'] >= 3) {
        $remaining_time = 300 - (time() - $_SESSION['last_login_attempt_time']);
        
        if ($remaining_time > 0) {
            // Add a delay to discourage brute-force attacks
            sleep($remaining_time);
            $_SESSION['last_login_attempt_time'] = time();
            
            // Calculate the remaining time in minutes and seconds
            $minutes = floor($remaining_time / 60);
            $seconds = $remaining_time % 60;
            
            $error_message = "You cannot log in for $minutes minutes and $seconds seconds. Please try again later.";
            
            // Send a JSON response indicating failure with an error message
            echo json_encode(['success' => false, 'error_message' => $error_message]);

            // Exit the script to stop further execution and reject the login attempt
            exit();
        }
    }

    // Check in user database
    $stmt_user = mysqli_prepare($con, "SELECT * FROM userdata WHERE (username=? OR email=?) LIMIT 1");
    mysqli_stmt_bind_param($stmt_user, "ss", $username_email, $username_email);
    mysqli_stmt_execute($stmt_user);
    $result_user = mysqli_stmt_get_result($stmt_user);

    // Check in admin database
    $stmt_admin = mysqli_prepare($con, "SELECT * FROM admindata WHERE AdminUserName=? LIMIT 1");
    mysqli_stmt_bind_param($stmt_admin, "s", $username_email);
    mysqli_stmt_execute($stmt_admin);
    $result_admin = mysqli_stmt_get_result($stmt_admin);

    // Check if the user exists in either database
    if (mysqli_num_rows($result_user) > 0) {
        $user = mysqli_fetch_assoc($result_user);
        $userid = $user['UserID'];
        $user_type = 'user';
    } elseif (mysqli_num_rows($result_admin) > 0) {
        $admin = mysqli_fetch_assoc($result_admin);
        $adminid = $admin['AdminID'];
        $user_type = 'admin';
    } else {
        $error_message = "Invalid_attempts username or email";
        // Session adding counter for login attempts
        $_SESSION['login_attempts']++;

        // Check if the $id_attempts is set
        if (isset($_SESSION['id_attempts'])) {
            // Update the last attempt count and time
            $stmt_update_attempt = mysqli_prepare($con, "UPDATE login_attempts SET attempts = ?, last_attempt_time = ? WHERE id_attempts = ?");
            mysqli_stmt_bind_param($stmt_update_attempt, "iii", $_SESSION['login_attempts'], time(), $_SESSION['id_attempts']);
            mysqli_stmt_execute($stmt_update_attempt);
        } else {
            // Log the login attempt with the result which is unknown user or email into the database
            $stmt_log_attempt = mysqli_prepare($con, "INSERT INTO login_attempts (ip_address, attempts, last_attempt_time, result) VALUES (?, ?, ?, 0)");
            mysqli_stmt_bind_param($stmt_log_attempt, "sii", $client_ip, $_SESSION['login_attempts'], time());
            mysqli_stmt_execute($stmt_log_attempt);
        }

        // Send a JSON response indicating failure
        echo json_encode(['success' => false, 'error_message' => $error_message]);
        exit();
    }

    // Authenticate the user based on the determined type
    if (isset($user_type)) {
        $auth_result = ($user_type === 'user') ? password_verify($password, $user['password']) : password_verify($password, $admin['AdminPassword']);

        if ($auth_result) {
            // Reset login attempts on successful login
            $_SESSION['login_attempts'] = 0;

            // Check if the $id_attempts is set
            if (isset($_SESSION['id_attempts'])) {
                // Update the last attempt count and time
                $stmt_update_attempt = mysqli_prepare($con, "UPDATE login_attempts SET attempts = ?, last_attempt_time = ?, result = 1 WHERE id_attempts = ?");
                mysqli_stmt_bind_param($stmt_update_attempt, "iii", $_SESSION['login_attempts'], time(), $_SESSION['id_attempts']);
                mysqli_stmt_execute($stmt_update_attempt);
            } else {
                // Log the successful login attempt
                $stmt_log_attempt = mysqli_prepare($con, "INSERT INTO login_attempts (ip_address, attempts, last_attempt_time, result) VALUES (?, ?, ?, 1)");
                mysqli_stmt_bind_param($stmt_log_attempt, "sii", $client_ip, $_SESSION['login_attempts'], time());
                mysqli_stmt_execute($stmt_log_attempt);
            }

            // Set session based on user type
            $_SESSION['user_type'] = $user_type;

            if ($user_type === 'user') {
                // Set the user ID in the session
                $_SESSION['user'] = $userid;

                // insert successful login attempt into login_records table for user and admin set to 0
                $stmt_login_record = mysqli_prepare($con, "INSERT INTO login_records (id_attempts, AdminID, UserID) VALUES (?, ?, ?)");
                mysqli_stmt_bind_param($stmt_login_record, "iii", $_SESSION['id_attempts'], 0, $userid);
                mysqli_stmt_execute($stmt_login_record);

            } elseif ($user_type === 'admin') {
                // Set the admin ID in the session
                $_SESSION['admin'] = $adminid;

                // insert successful login attempt into login_records table for admin and user set to 0
                $stmt_login_record = mysqli_prepare($con, "INSERT INTO login_records (id_attempts, AdminID, UserID) VALUES (?, ?, ?)");
                mysqli_stmt_bind_param($stmt_login_record, "iii", $_SESSION['id_attempts'], $adminid, 0);
                mysqli_stmt_execute($stmt_login_record);
            }

            // Send a JSON response indicating success and the user type
            echo json_encode(['success' => true, 'user_type' => $user_type, 'user' => $userid]);
            exit();
        } else {
            // Session adding counter for login attempts
            $_SESSION['login_attempts']++;

            // Check if the $id_attempts is set
            if (isset($_SESSION['id_attempts'])) {
                // Update the last attempt count and time
                $stmt_update_attempt = mysqli_prepare($con, "UPDATE login_attempts SET attempts = ?, last_attempt_time = ? WHERE id_attempts = ?");
                mysqli_stmt_bind_param($stmt_update_attempt, "iii", $_SESSION['login_attempts'], time(), $_SESSION['id_attempts']);
                mysqli_stmt_execute($stmt_update_attempt);
            } else {
                // Log the login attempt with the result
                $stmt_log_attempt = mysqli_prepare($con, "INSERT INTO login_attempts (ip_address, attempts, last_attempt_time, result) VALUES (?, ?, ?, 0)");
                mysqli_stmt_bind_param($stmt_log_attempt, "sii", $client_ip, $_SESSION['login_attempts'], time());
                mysqli_stmt_execute($stmt_log_attempt);
            }

            // Set the error message
            $error_message = "Invalid_attempts password. Current login attempts: " . $_SESSION['login_attempts'] . "/3";
            // Send a JSON response indicating failure
            echo json_encode(['success' => false, 'error_message' => $error_message]);
            exit();
        }
    }
}

// In case there's an unexpected issue, send a generic JSON response
echo json_encode(['success' => false, 'error_message' => 'Unexpected error']);
exit();
?>