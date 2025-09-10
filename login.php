<?php
session_start();
include "connection.php";

$message = "";
$alertType = "";
$redirect = "";

// LOGIN FORM SUBMISSION

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['form_type']) && $_POST['form_type'] === 'login') {
    $username = trim($_POST['username']);
    $password = trim($_POST['password']);

    $stmt = $conn->prepare("SELECT id, username, password, role FROM users WHERE username = ? LIMIT 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result && $result->num_rows > 0) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id']  = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['role']     = $user['role'];

            $message = "Welcome back, " . htmlspecialchars($user['username']) . "!";
            $alertType = "success";

            // Redirect only admin to add_product.php
            $redirect = ($user['role'] === 'admin') ? "add_product.php" : "";
        } else {
            $message = "Invalid password!";
            $alertType = "error";
        }
    } else {
        $message = "User not found!";
        $alertType = "error";
    }
    $stmt->close();
}


// REGISTRATION FORM SUBMISSION

if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['form_type']) && $_POST['form_type'] === 'register') {
    $username = trim($_POST['username']);
    $email    = trim($_POST['email']);
    $password = password_hash(trim($_POST['password']), PASSWORD_DEFAULT);

    // Check if username already exists
    $stmt = $conn->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
    $stmt->bind_param("s", $username);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        $message = "Username already exists!";
        $alertType = "error";
    } else {
        $stmt->close();
        $stmt = $conn->prepare("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, 'user')");
        $stmt->bind_param("sss", $username, $email, $password);
        if ($stmt->execute()) {
            $message = "Registration successful! You can now login.";
            $alertType = "success";

            // Automatically switch to login form after registration
            echo "<script>document.addEventListener('DOMContentLoaded', ()=>{ switchForm('login'); });</script>";
        } else {
            $message = "Registration failed. Try again!";
            $alertType = "error";
        }
    }
    $stmt->close();
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Login & Register</title>
<link rel="stylesheet" href="login.css">
<script src="https://cdn.jsdelivr.net/npm/sweetalert2@11"></script>
</head>
<body>
    <!-- Modal (hidden by default) -->
<div class="modal" id="authModal">
    <div class="modal-content">
        <span class="close" onclick="closeModal()">&times;</span>

        <!-- Login Form -->
        <div class="form-box active" id="loginBox">
            <h2>Login</h2>
            <form action="" method="POST">
                <input type="hidden" name="form_type" value="login">
                <i class="fa-solid fa-user"></i>
                <input type="text" name="username" placeholder="Username" required>
                <i class="fa-solid fa-lock"></i>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Login</button>
                <p>Don’t have an account? 
                   <a href="#" onclick="switchForm('register')">Register</a></p>
            </form>
        </div>

        <!-- Register Form -->
        <div class="form-box" id="registerBox">
            <h2>Register</h2>
            <form action="" method="POST">
                <input type="hidden" name="form_type" value="register">
                <i class="fa-solid fa-user"></i>
                <input type="text" name="username" placeholder="Username" required>
                <i class="fa-solid fa-envelope"></i>
                <input type="email" name="email" placeholder="Email" required>
                <i class="fa-solid fa-lock"></i>
                <input type="password" name="password" placeholder="Password" required>
                <button type="submit">Register</button>
                <p>Already have an account? 
                   <a href="#" onclick="switchForm('login')">Login</a></p>
            </form>
        </div>
    </div>
</div>

<script>
function openModal() {
    document.getElementById("authModal").style.display = "flex";
}
function closeModal() {
    document.getElementById("authModal").style.display = "none";
}
function switchForm(form) {
    if(form === "register") {
        document.getElementById("loginBox").classList.remove("active");
        document.getElementById("registerBox").classList.add("active");
    } else {
        document.getElementById("registerBox").classList.remove("active");
        document.getElementById("loginBox").classList.add("active");
    }
}

// Close modal when clicking outside content
window.onclick = function(e) {
    if(e.target == document.getElementById("authModal")) {
        closeModal();
    }
}


// SweetAlert2 popup after form submission
<?php if(!empty($message)) { ?>
Swal.fire({
    icon: '<?= $alertType ?>',
    title: '<?= $message ?>',
    timer: 2000,
    showConfirmButton: false,
    didClose: () => {
        // Close the modal for all users
        closeModal();

        // Redirect only for admin
        <?php if(!empty($redirect)) { ?>
            window.location.href = "<?= $redirect ?>";
        <?php } ?>
    }
});
<?php } ?>
</script>

</body>
</html>