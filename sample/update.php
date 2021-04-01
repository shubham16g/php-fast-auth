<?php

if (!isset($_GET['uid'])) {
    echo 'error';
}
$uid = $_GET['uid'];

require '../class.FastAuth.php';

$auth = new FastAuth();
$userData;
try {
    $userData = $auth->getUser($uid);
} catch (Exception $e) {
    die($e->getMessage());
}

$toVerify = [];
if (isset($userData['mobile'])) {
    $toVerify[] = $userData['countryCode'] . ' ' . $userData['mobile'];
} else {
    $toVerify[] = $userData['email'];
}

if (isset($_POST['submit'])) {

    try {
        $postVerify = $_POST['toVerify'];
        $otp;
        if (strpos($postVerify, '@')) { //email contain @, you can do you own logic
            $otp = $auth->getOtpToVerifyEmail($uid);
        } else {
            $otp = $auth->getOtpToVerifyMobile($uid);
        }

        $title = urlencode("OTP sent to " . $postVerify);
        $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: $otp");
        $redirect = urlencode("verify_otp.php?uid=" . urlencode($uid) . "&for=" . urlencode($for));
        header("Location: message.php?title=$title&content=$content&redirect=$redirect");
        die();
    } catch (Exception $e) {
        die($e->getMessage());
    }
}

?>
<!DOCTYPE html>

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Verify Account</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>

    <h4>You have to first verify your account, we will send an OTP.</h4>

    <form action="" accept-charset="UTF-8" method="post">
        <select name="toVerify" class="input-block" id="toVerify">
            <?php
            foreach ($toVerify as $option) {
                echo "<option>$option</option>";
            }
            ?>
        </select>
        <input type="submit" name="submit" value="Get OTP" class="btn">
    </form>

    <script src="./js/main.js"></script>
</body>

</html>