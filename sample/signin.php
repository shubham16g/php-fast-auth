<?php
session_start();

$countryCodeList = ['+91', '+1', '+12', '+2'];

if (isset($_SESSION['userID']) && isset($_SESSION['token'])) {
    header("Location: index.php");
}

require '../class.FastAuth.php';

if (isset($_POST['submit'])) {
    $auth = new FastAuth();

    $emailOrMobile = $_POST['emailOrMobile'];
    $password = $_POST['password'];
    $countryCode = $_POST['countryCode'];

    // todo validate these post methods

    $enteredType;
    if (is_numeric($emailOrMobile)) {
        $enteredType = 'mobile';
    } else {
        $enteredType = 'email';
    }
    try {
        $signInResult;
        if ($enteredType === 'mobile') {
            $signInResult = $auth->signInWithMobileAndPassword($countryCode, $emailOrMobile, $password);
        } else {
            $signInResult = $auth->signInWithEmailAndPassword($emailOrMobile, $password);
        }
        $userID = $signInResult['userID'];
        $token = $signInResult['token'];

        $_SESSION['userID'] = $userID;
        $_SESSION['token'] = $token;

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

        <input type="password" style="opacity: 0;position: absolute;">

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
            var formData = new FormData(event.target);
            const emailOrMobile = formData.get('emailOrMobile');
            const password = formData.get('password');

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

            return true;
        }
    </script>
    <script src="./js/main.js"></script>
</body>

</html>