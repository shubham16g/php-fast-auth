<?php
if (isset($_SESSION['userID']) && isset($_SESSION['token'])) {
    header("Location: index.php");
}

$countryCodeList = ['+91', '+1', '+12', '+2'];

require '../class.FastAuth.php';



if (isset($_POST['submit'])) {
    $emailOrMobile = $_POST['emailOrMobile'];
    $countryCode = $_POST['countryCode'];

    $auth = new FastAuth();
    try {
        $userData;
        if (is_numeric($emailOrMobile)) {
            $userData = $auth->getUserByMobileNumber($countryCode, $emailOrMobile);
        } else {
            $userData = $auth->getUserByEmail($emailOrMobile);
        }
        $userID = $userData['userID'];
        $otp = $auth->getOtpToResetPassword($userID);

        $title = urlencode("OTP sent to $emailOrMobile");
        $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: $otp");
        $redirect = urlencode("verify_otp.php?uid=" . urlencode($userID) . "&for=" . urlencode(FastAuth::FOR_RESET_PASSWORD));
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
    <title>Forget Password</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>

    <form action="" accept-charset="UTF-8" method="post" onsubmit="return validateForm(event);">
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

        <input type="submit" name="submit" value="Get OTP" class="btn">
    </form>

    <script>
        window.onload = () => {
            handleCountryCodeVisibility('countryCode', 'emailOrMobile');
        }

        function validateForm(event) {
            var formData = new FormData(event.target);
            const emailOrMobile = formData.get('emailOrMobile');
            if (!validateEmailOrMobile(emailOrMobile)) {
                return false;
            }
            return true;
        }
    </script>
    <script src="./js/main.js"></script>
</body>

</html>