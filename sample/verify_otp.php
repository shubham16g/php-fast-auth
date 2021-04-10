<?php
session_start();
require '../class.FastAuth.php';
require './autoload.php';

if (!isset($_GET['key'])) {
    die('Error');
}
$key = $_GET['key'];
$auth = new FastAuth($host, $username, $password, $dbname);
$options = new FastAuth\Options();
$options->otpLength = 8;
$auth->setOptions($options);

try {
    if (isset($_POST['submit'])) {

        $title = '';
        $content = '';
        $redirect = 'index.php';

        $otp = $_POST['otp'];
        $result = $auth->verifyOTP($key, $otp);

        switch ($result['case']) {
            case FastAuth::CASE_UPDATE_PASSWORD:
                $passwordUpdateKey = $result['passwordUpdateKey'];
                header("Location: reset_password.php?passwordUpdateKey=" . urlencode($passwordUpdateKey));
                die();
                break;
            case FastAuth::CASE_NEW_USER:
                $uid = $result['uid'];
                $signInResult = $auth->forceSignIn($uid);
                $_SESSION['uid'] = $signInResult['uid'];
                $_SESSION['token'] = $signInResult['token'];
                $_SESSION['isAnonymous'] = $signInResult['isAnonymous'];
                // $content = json_encode($signInResult);
                $title = "Account verification successful";
                break;
            case FastAuth::CASE_UPDATE_EMAIL:
                $title = "Email update successful";
                break;
            case FastAuth::CASE_UPDATE_MOBILE:
                $title = "Mobile number update successful";
                break;
            default:
                throw new Exception("Error in verify_otp.php: no such case", 1);
                break;
        }

        header("Location: message.php?title=" . urlencode($title) . '&content=' . urlencode($content) . '&redirect=' . urlencode($redirect));
    } elseif (isset($_POST['resend'])) {
        $otpArr = $auth->generateOTP($key);
        /* $otpArr = [
            otp => <string> '865454',
            sendTo => <string> '+917778887778',
            sendType => <string> 'mobile',
        ] */

        $title = urlencode("OTP re-sent to " . $otpArr['sendType'] . ': ' . $otpArr['sendTo']);
        $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: " . $otpArr['otp']);
        $redirect = urlencode("verify_otp.php?key=" . urlencode($key));
        header("Location: message.php?title=$title&content=$content&redirect=$redirect");
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
        <input type="text" name="otp" id="otp" class="input-block" autofocus="autofocus" maxlength="6" minlength="6">

        <input type="submit" name="submit" value="Verify OTP" class="btn">
        <input type="submit" name="resend" value="Resend OTP" class="btn">
    </form>

    <script>
        function validateForm(event) {
            return true;
        }
    </script>
    <script src="./js/main.js"></script>
</body>

</html>