<?php

require '../class.FastAuthConstants.php';
require '../class.FastAuth.php';

if (isset($_POST['submit'])) {
    $otp = $_POST['otp'];
    $for = $_GET['for'];
    $userID = $_GET['uid'];

    $auth = new FastAuth();
    try {
        if ($for == FastAuth::FOR_RESET_PASSWORD) {
            $auth->verifyOTP($otp, $userID, $for);
            header("Location: reset_password.php?uid=$userID&otp=$otp");
        } else {
            $title = '';
            $content = '';
            $redirect = 'index.php';
            if ($for == FastAuth::FOR_VERIFY_MOBILE) {
                $auth->verifyMobile($userID, $otp);
                $title = "Mobile number verification successful";
            } elseif ($for == FastAuth::FOR_VERIFY_EMAIL) {
                $auth->verifyMobile($userID, $otp);
                $title = "Email verification successful";
            }
            header("Location: message.php?title=" . urlencode($title) . '&content=' . urlencode($content) . '&redirect=' . urlencode($redirect));
        }
        
    } catch (Exception $e) {
        die($e->getMessage());
    }
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