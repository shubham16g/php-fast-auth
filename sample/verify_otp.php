<?php
session_start();
require '../class.FastAuth.php';

if (!isset($_GET['for']) && !isset($_GET['uid'])) {
    die('Error');
}
$for = $_GET['for'];
$userID = $_GET['uid'];
$auth = new FastAuth();

try {
    if (isset($_POST['submit'])) {
        $otp = $_POST['otp'];
        if ($for == FastAuth::FOR_RESET_PASSWORD) {
            $auth->verifyResetPassword($userID, $otp);
            header("Location: reset_password.php?uid=$userID&otp=$otp");
        } else {
            $title = '';
            $content = '';
            $redirect = 'index.php';
            if ($for == FastAuth::FOR_VERIFY_MOBILE) {
                $auth->verifyMobile($userID, $otp);
                $title = "Mobile number verification successful";
            } elseif ($for == FastAuth::FOR_VERIFY_EMAIL) {
                $auth->verifyEmail($userID, $otp);
                $title = "Email verification successful";
            } elseif ($for == FastAuth::FOR_VERIFY_CREATED_ACCOUNT) {
                $auth->verifyRegisterUser($userID, $otp);

                $signInResult = $auth->forceSignIn($userID);
                /* $signInResult = [
                    'userID' => <int>,
                    'token' => <string>,
                    'isSigned' => <bool>
                ] */
                $_SESSION['userID'] = $signInResult['userID'];
                $_SESSION['token'] = $signInResult['token'];
                $_SESSION['isSigned'] = $signInResult['isSigned'];
                // $content = json_encode($signInResult);
                $title = "Account verification successful";
            }
            header("Location: message.php?title=" . urlencode($title) . '&content=' . urlencode($content) . '&redirect=' . urlencode($redirect));
        }
    } elseif (isset($_POST['resend'])) {
        header("Location: generate_otp.php?resend=1&uid=" . urlencode($userID) . "&for=" . urlencode($for));
        
    }
} catch (Exception $e) {
    die($e->getMessage());
}




?>

<!DOCTYPE html>

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify OTP</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>

    <form action="" accept-charset="UTF-8" method="post" onsubmit="return validateForm(event);">
        <label for="otp">Enter OTP</label>
        <input type="number" name="otp" id="otp" class="input-block" autofocus="autofocus" maxlength="6" minlength="6">

        <input type="submit" name="submit" value="Verify OTP" class="btn">
        <input type="submit" name="resend" value="Resend OTP" class="btn">
    </form>

    <script>
        function validateForm(event) {
            var formData = new FormData(event.target);
            const emailOrMobile = formData.get('emailOrMobile');
            return validateEmailOrMobile(emailOrMobile);
            return true;
        }
    </script>
    <script src="./js/main.js"></script>
</body>

</html>