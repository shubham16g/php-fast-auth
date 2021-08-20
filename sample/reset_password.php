<?php
$withKey = false;
if (isset($_GET['passwordUpdateKey'])) {
    $withKey = true;
}

require_once dirname(__FILE__, 2) . '/PHPFastAuth.php';
require_once dirname(__FILE__, 1) . '/config.php';


if (isset($_POST['submit'])) {
    if (isset($_POST['currentPassword'])) {
        // todo
    } elseif (isset($_GET['passwordUpdateKey'])) {
        $passwordUpdateKey = $_GET['passwordUpdateKey'];
        try {
            $auth = new PHPFastAuth($db);
            $auth->updatePassword($passwordUpdateKey, $_POST['password']);
            // $auth->signOutAllDevices($uid);

            $title = urlencode("Password Reset Successful");
            $content = urlencode("You can now sign in with your new password.");
            $redirect = urlencode("signin.php");
            header("Location: ./message.php?title=$title&content=$content&redirect=$redirect");
        } catch (Exception $e) {
            die($e->getMessage());
        }
    } else {
        echo "Error";
    }
    die();
}

?>


<!DOCTYPE html>

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>

    <form action="" accept-charset="UTF-8" method="post" onsubmit="return validateForm(event);">
        <?php
        if (!$withKey) {
        ?>
            <label for="oldPassword">Old Password</label>
            <input type="password" name="oldPassword" id="oldPassword" class="input-block">
        <?php
        }
        ?>
        <label for="password">New Password</label>
        <input type="password" name="password" id="password" class="input-block">

        <label for="confirmPassword">Confirm Password</label>
        <input type="password" name="confirmPassword" id="confirmPassword" class="input-block">

        <input type="submit" name="submit" value="Reset" class="btn">
    </form>

    <script>
        function validateForm(event) {
            var formData = new FormData(event.target);
            <?php
            if (!$withKey) {
            ?>
                const oldPassword = formData.get('oldPassword');
                if (oldPassword === '') {
                    alert("Please enter old password");
                    return false;
                }

            <?php
            }
            ?>

            const password = formData.get('password');
            const confirmPassword = formData.get('confirmPassword');


            if (password === '') {
                alert("Please enter new password");
                return false;
            }
            if (password.length < 6) {
                alert("Atleast 6-digit password is required");
                return false;
            }
            if (confirmPassword === '') {
                alert("Please enter confirm password");
                return false;
            }
            if (password !== confirmPassword) {
                alert("Password doesn't match");
                return false;
            }

            return true;
        }
    </script>
    <script src="./js/main.js"></script>

</body>

</html>