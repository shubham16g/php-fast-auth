<?php
session_start();

$countryCodeList = ['+91', '+1', '+12', '+2'];

if (isset($_SESSION['userID']) && isset($_SESSION['token'])) {
    header("Location: index.php");
}

require '../class.FastAuth.php';

if (isset($_POST['submit'])) {
    $auth = new FastAuth();

    $name = $_POST['name'];
    $emailOrMobile = $_POST['emailOrMobile'];
    $password = $_POST['password'];
    $countryCode = $_POST['countryCode'];

    $userID;
    try {
        if (is_numeric($emailOrMobile)) {
            $userID = $auth->createUserWithMobile($countryCode, $emailOrMobile, $password, $name);
        } else {
            $userID = $auth->createUserWithEmail($emailOrMobile, $password, $name);
        }
        $otp = $auth->getOtpToRegisterUser($userID);

        /* send this otp to provided mobile or email
        */

        $title = urlencode("Verify Account, an OTP sent to $emailOrMobile");
        $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: $otp");
        $redirect = urlencode("verify_otp.php?uid=" . urlencode($userID) . "&for=" . urlencode(FastAuth::FOR_VERIFY_CREATED_ACCOUNT));
        header("Location: message.php?title=$title&content=$content&redirect=$redirect");

        // header("Location: ./index.php");
    } catch (Exception $e) {
        echo $e->getMessage();
        die();
    }
}

?>

<!DOCTYPE html>

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign In</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>

    <form action="" accept-charset="UTF-8" method="post" onsubmit="return validateForm(event);">
        <label for="name">Full Name</label>
        <div>
            <input type="text" name="name" id="name" class="input-block" autofocus="autofocus" autocomplete="off">
        </div>

        <label for="emailOrMobile">Email or Mobile Number</label>
        <div id="emailMobileContainer" class="input-block">
            <select name="countryCode" class="input-block cc-block" id="countryCode">
                <?php
                foreach ($countryCodeList as $countryCode) {
                    echo "<option>$countryCode</option>";
                }
                ?>
            </select>
            <input type="text" name="emailOrMobile" id="emailOrMobile" autocomplete="off" class="input-block" style="visibility: hidden;">
        </div>

        <label for="password">Password</label>
        <input type="password" name="password" id="password" class="input-block">

        <label for="confirmPassword">Confirm Password</label>
        <input type="password" name="confirmPassword" id="confirmPassword" class="input-block">

        <input type="submit" name="submit" value="Sign up" class="btn">
        <br>
        <span>Already a User? </span><a href="./signin.php">Sign in.</a>
    </form>

    <script>
        window.onload = () => {
            handleCountryCodeVisibility('countryCode', 'emailOrMobile');
        }

        function validateForm(event) {
            var formData = new FormData(event.target);
            const name = formData.get('name');
            const emailOrMobile = formData.get('emailOrMobile');
            const password = formData.get('password');
            const confirmPassword = formData.get('confirmPassword');

            if (name === '') {
                alert("Please enter your full name.");
                return false;
            }

            if (!validateEmailOrMobile(emailOrMobile)) {
                return false;
            }

            if (password === '') {
                alert("Please enter password");
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