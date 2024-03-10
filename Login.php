<?php

require 'connection.php';
require 'functions.php';

// Get client IP
$client_ip = getClientIp();

// Rate limit settings
$max_attempts = 3;
$lockout_time = 300; // seconds

// Set 0 and 1
$zero = 0;
$one = 1;

// Retrieve stored attempts and timestamp from the database for the client IP address
// And check if the IP address is already in the database with a failed login attempt which is result = 0
// So that we can update the last attempt time and the number of attempts
// So the client IP with successful login attempt won't be affected
$stmt = mysqli_prepare($con, "SELECT id_attempts, attempts, last_attempt_time, result FROM login_attempts WHERE ip_address = ? AND result = ? LIMIT 1");
mysqli_stmt_bind_param($stmt, "si", $client_ip, $zero);
mysqli_stmt_execute($stmt);
mysqli_stmt_store_result($stmt);

// Check if the IP address is already in the database
if (mysqli_stmt_num_rows($stmt) > 0) {
    mysqli_stmt_bind_result($stmt, $id_attempts, $attempts, $last_attempt_time, $result);
    mysqli_stmt_fetch($stmt);

    // Set id_attempts in the local session
    $local_session_id_attempts = $id_attempts;

    // Update the last attempt count and time
    $local_session_login_attempts = $attempts;
    $local_session_last_login_attempt_time = $last_attempt_time;

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

// Set the local session counter for login attempts
if (!isset($local_session_login_attempts)) {
    $local_session_login_attempts = 0;
}

// Check if there is a previous delay that needs to be reset
if (isset($local_session_last_login_attempt_time)) {
    $elapsed_time = time() - $local_session_last_login_attempt_time;
    if ($elapsed_time >= 300) {
        // Reset login attempts after 5 minutes
        $local_session_login_attempts = 0;
        unset($local_session_last_login_attempt_time);
    }
}

// Initialize the error message
$error_message = "";

// Check if the form is submitted
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // Set the input time
    $input_time = time();

    // Get the form data
    $username_email = mysqli_real_escape_string($con, $_POST['username_email']);
    $password = mysqli_real_escape_string($con, $_POST['password']);

    // Check if login attempts exceed a threshold
    if ($local_session_login_attempts >= 3) {
        $remaining_time = 300 - (time() - $local_session_last_login_attempt_time);
        
        if ($remaining_time > 0) {
            // Add a delay to discourage brute-force attacks
            sleep($remaining_time);
            $local_session_last_login_attempt_time = time();
            
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
        // Local session adding counter for login attempts
        $local_session_login_attempts++;

        // Set the current login attempts
        $cur_log_attempts = $local_session_login_attempts;

        // Check if the $id_attempts is set
        if (isset($local_session_id_attempts)) {
            // Set the current id_attempts
            $cur_id_attempts = $local_session_id_attempts;

            // Update the last attempt count and time
            $stmt_update_attempt = mysqli_prepare($con, "UPDATE login_attempts SET attempts = ?, last_attempt_time = ? WHERE id_attempts = ?");
            mysqli_stmt_bind_param($stmt_update_attempt, "iii", $cur_log_attempts, $input_time, $cur_id_attempts);
            mysqli_stmt_execute($stmt_update_attempt);
        } else {
            // Log the login attempt with the result which is unknown user or email into the database
            $stmt_log_attempt = mysqli_prepare($con, "INSERT INTO login_attempts (ip_address, attempts, last_attempt_time, result) VALUES (?, ?, ?, $zero)");
            mysqli_stmt_bind_param($stmt_log_attempt, "sii", $client_ip, $cur_log_attempts, $input_time);
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
            $reset_log_attempts = 0;

            // Check if the $id_attempts is set
            if (isset($local_session_id_attempts)) {
                // Set the current id_attempts
                $res_id_attempts = $local_session_id_attempts;
                // Update the last attempt count and time
                $stmt_update_attempt = mysqli_prepare($con, "UPDATE login_attempts SET attempts = ?, last_attempt_time = ?, result = ? WHERE id_attempts = ?");
                mysqli_stmt_bind_param($stmt_update_attempt, "iiii", $reset_log_attempts, $input_time, $one, $res_id_attempts);
                mysqli_stmt_execute($stmt_update_attempt);
            } else {
                // Log the successful login attempt
                $stmt_log_attempt = mysqli_prepare($con, "INSERT INTO login_attempts (ip_address, attempts, last_attempt_time, result) VALUES (?, ?, ?, $one)");
                mysqli_stmt_bind_param($stmt_log_attempt, "sii", $client_ip, $reset_log_attempts, $input_time);
                mysqli_stmt_execute($stmt_log_attempt);

                // Get the id_attempts of the last inserted record
                $local_session_id_attempts = mysqli_insert_id($con);
            }

            // Set local session based on user type
            $local_session['user_type'] = $user_type;

            // Set success_id_attempts from the local session
            $success_id_attempts = $local_session_id_attempts;

            if ($user_type === 'user') {
                // Set the user ID in the local session
                $local_session['user'] = $userid;

                // insert successful login attempt into login_records table for user and admin set to 0
                $stmt_login_record = mysqli_prepare($con, "INSERT INTO login_records (id_attempts, AdminID, UserID) VALUES (?, ?, ?)");
                $id_param = $success_id_attempts;
                $admin_param = $zero;
                $user_param = $userid;
                mysqli_stmt_bind_param($stmt_login_record, "iii", $id_param, $admin_param, $user_param);
                mysqli_stmt_execute($stmt_login_record);

                // Send a JSON response indicating success and the user type
                echo json_encode(['success' => true, 'error_message' => $userid]);
                exit();

            } elseif ($user_type === 'admin') {
                // Set the admin ID in the local session
                $local_session['admin'] = $adminid;

                // insert successful login attempt into login_records table for admin and user set to 0
                $stmt_login_record = mysqli_prepare($con, "INSERT INTO login_records (id_attempts, AdminID, UserID) VALUES (?, ?, ?)");
                $id_param = $success_id_attempts;
                $admin_param = $adminid;
                $user_param = $zero;
                mysqli_stmt_bind_param($stmt_login_record, "iii", $id_param, $admin_param, $user_param);
                mysqli_stmt_execute($stmt_login_record);

                // Send a JSON response indicating success and the user type
                echo json_encode(['success' => true, 'error_message' => $adminid]);
                exit();
            }

        } else {
            // Local session adding counter for login attempts for invalid password
            $local_session_login_attempts++;

            // Set the current login attempts
            $current_login_attempts = $local_session_login_attempts;

            // Check if the $id_attempts is set
            if (isset($local_session_id_attempts)) {
                // Set the current id_attempts
                $current_id_attempts = $local_session_id_attempts;

                // Update the last attempt count and time
                $stmt_update_attempt = mysqli_prepare($con, "UPDATE login_attempts SET attempts = ?, last_attempt_time = ? WHERE id_attempts = ?");
                mysqli_stmt_bind_param($stmt_update_attempt, "iii", $current_login_attempts, $input_time, $current_id_attempts);
                mysqli_stmt_execute($stmt_update_attempt);
            } else {
                // Log the login attempt with the result
                $stmt_log_attempt = mysqli_prepare($con, "INSERT INTO login_attempts (ip_address, attempts, last_attempt_time, result) VALUES (?, ?, ?, $zero)");
                mysqli_stmt_bind_param($stmt_log_attempt, "sii", $client_ip, $current_login_attempts, $input_time);
                mysqli_stmt_execute($stmt_log_attempt);
            }

            // Set the error message
            $error_message = "Invalid password. Current login attempts: " . $local_session_login_attempts . "/3";
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