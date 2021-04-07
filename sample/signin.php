<?php
session_start();

$countryCodeList = ['+91', '+1', '+12', '+2'];

if (isset($_SESSION['uid']) && isset($_SESSION['token'])) {
    header("Location: index.php");
}

require '../class.FastAuth.php';
require './autoload.php';

if (isset($_POST['submit'])) {
    $auth = new FastAuth($fastAuthOptions);

    $password = $_POST['password'];

    // todo validate these post methods
    try {
        $signInResult;
        if (isset($_POST['mobile'])) {
            $signInResult = $auth->signInWithMobileAndPassword($_POST['mobile'], $password);
        } else {
            $signInResult = $auth->signInWithEmailAndPassword($_POST['email'], $password);
        }

        $_SESSION['uid'] = $signInResult['uid'];
        $_SESSION['token'] = $signInResult['token'];
        $_SESSION['isAnonymous'] = $signInResult['isAnonymous'];
        header("Location: ./index.php");
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

    <form action="" autocomplete="off" accept-charset="UTF-8" method="post" onsubmit="return validateForm(event);">

        <label for="emailOrMobile">Email or Mobile Number</label>
        <div id="emailMobileContainer" class="input-block">
            <select name="countryCode" class="input-block cc-block" id="countryCode">
                <?php
                foreach ($countryCodeList as $countryCode) {
                    echo "<option>$countryCode</option>";
                }
                ?>
            </select>
            <input type="text" name="emailOrMobile" id="emailOrMobile" autocomplete="off" class="input-block field" style="visibility: hidden;">
        </div>

        <label for="password">Password</label>
        <input type="password" name="password" id="password" class="input-block">

        <a href="./forget_password.php">Forgot password?</a>
        <br>
        <input type="submit" name="submit" value="Sign in" class="btn">
        <br>
        <span>New User? </span><a href="./signup.php">Create new account.</a>
    </form>

    <script>
        window.onload = () => {
            handleCountryCodeVisibility('countryCode', 'emailOrMobile');
        }

        function validateForm(event) {
            const form = event.target;
            const emailOrMobile = form.emailOrMobile.value;
            const password = form.password.value;

            var isMobile = false;
            var isError = false;
            handleEmailOrMobile(emailOrMobile, (b) => {
                isMobile = b;
            }, (errorCode, message) => {
                alert(message);
                isError = true;
            });
            if (isError) {
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

            /* eveything is now fine */
            if (isMobile) {
                form.emailOrMobile.name = 'mobile';
                form.mobile.value = form.countryCode.value + emailOrMobile;
            } else {
                form.emailOrMobile.name = 'email';
            }
            form.countryCode.remove();
            return true;
        }
    </script>
    <script src="./js/main.js"></script>
</body>

</html>
