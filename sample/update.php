<?php

session_start();
$countryCodeList = ['+91', '+1', '+12', '+2'];

if (!isset($_SESSION['uid']) || !isset($_SESSION['token'])) {
    header("Location: signin.php");
}

if (!isset($_GET['type'])) {
    header("Location: index.php");
}
$type = $_GET['type'];
$uid = $_SESSION['uid'];

require_once dirname(__FILE__, 2) . '/PHPFastAuth.php';
require_once dirname(__FILE__, 1) . '/config.php';

try {

    $auth = new PHPFastAuth($db);


    if (isset($_POST['submit'])) {
        $key;
        if ($type === 'mobile') {
            $key = $auth->updateMobileRequest($uid, $_POST['mobile']);
        } elseif ($type === 'email') {
            $key = $auth->updateEmailRequest($uid, $_POST['email']);
        } elseif ($type === 'name') {
            $auth->updateName($uid, $_POST['text']);
            header("Location: index.php");
            die();
        }
        $otpData = $auth->decodeOTP($key);

        $title = '';
        if ($otpData->getType() === 'mobile') {
            $title = urlencode("OTP sent to Mobile No. : " . $otpData->getMobile());
        } else {
            $title = urlencode("OTP sent to Email : " . $otpData->getEmail());
        }
        $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: " . $otpData->getOTP());
        $redirect = urlencode("verify_otp.php?key=" . urlencode($key));
        header("Location: message.php?title=$title&content=$content&redirect=$redirect");
    }

} catch (Exception $e) {
    echo $e->getMessage();
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

    <form action="" accept-charset="UTF-8" method="post" onsubmit="return <?= ($type === 'email' || $type === 'mobile') ? 'validateForm(event)' : 'validateText(event)'; ?>;">
        <label>New <?= $type ?></label>
        <div id="emailMobileContainer" class="input-block" style="display: <?= ($type === 'email' || $type === 'mobile') ? 'flex' : 'none'; ?>;">
            <select name="countryCode" class="input-block cc-block" id="countryCode" style="display: <?= ($type === 'email') ? 'none' : 'block'; ?>;">
                <?php
                foreach ($countryCodeList as $countryCode) {
                    echo "<option>$countryCode</option>";
                }
                ?>
            </select>
            <input type="text" name="emailOrMobile" id="emailOrMobile" autocomplete="off" class="input-block field">
        </div>
        <input type="text" name="text" id="text" autocomplete="off" class="input-block" style="display: <?= ($type === 'email' || $type === 'mobile') ? 'none' : 'block'; ?>;">
        <input type="submit" name="submit" value="<?= ($type === 'email' || $type === 'mobile') ? 'Get OTP' : 'Submit'; ?>" class="btn">
    </form>

    <script>
        function validateText(event) {
            const form = event.target;
            const text = form.text.value;
            if (text === '') {
                alert("Please Enter a valid <?= $type ?>")
                return false;
            }
            return true;
        }

        function validateForm(event) {
            const form = event.target;
            const emailOrMobile = form.emailOrMobile.value;

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