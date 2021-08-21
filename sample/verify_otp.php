<?php

session_start();
require_once dirname(__FILE__, 2) . '/PHPFastAuth.php';
require_once dirname(__FILE__, 1) . '/config.php';

if (!isset($_GET['key'])) {
    die('Error');
}
$key = $_GET['key'];

try {
    $auth = new PHPFastAuth($db);
    if (isset($_POST['submit'])) {

        $title = '';
        $content = '';
        $redirect = 'index.php';

        $otp = $_POST['otp'];
        $result = $auth->verifyOTP($key, $otp);

        switch ($result['case']) {
            case PHPFastAuth::CASE_UPDATE_PASSWORD:
                $passwordUpdateKey = $result['passwordUpdateKey'];
                header("Location: reset_password.php?passwordUpdateKey=" . urlencode($passwordUpdateKey));
                die();
                break;
            case PHPFastAuth::CASE_NEW_USER:
                $signIn = new PHPFastAuth\SignInWithUID($result['uid']);
                $signInResult = $auth->signInWithoutPassword($signIn);
                $_SESSION['uid'] = $signInResult['uid'];
                $_SESSION['token'] = $signInResult['token'];
                $_SESSION['isAnonymous'] = $signInResult['isAnonymous'];
                // $content = json_encode($signInResult);
                $title = "Account verification successful";
                break;
            case PHPFastAuth::CASE_UPDATE_EMAIL:
                $title = "Email update successful";
                break;
            case PHPFastAuth::CASE_UPDATE_MOBILE:
                $title = "Mobile number update successful";
                break;
            default:
                throw new Exception("Error in verify_otp.php: no such case", 1);
                break;
        }

        header("Location: message.php?title=" . urlencode($title) . '&content=' . urlencode($content) . '&redirect=' . urlencode($redirect));
    } elseif (isset($_POST['resend'])) {
        $otpData = $auth->decodeOTP($key);

        $title = '';
        if ($otpData->getType() === 'mobile') {
            $title = urlencode("OTP re-sent to Mobile No. : " . $otpData->getMobile());
        } else {
            $title = urlencode("OTP re-sent to Email : " . $otpData->getEmail());
        }
        $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: " . $otpData->getOTP());
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