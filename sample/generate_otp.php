<?php

if (!isset($_GET['for']) && !isset($_GET['uid'])) {
    die('Error');
}

$for = $_GET['for'];
$userID = $_GET['uid'];
$isResend = false;
if (isset($_GET['resend'])) {
    $isResend = true;
}

$title = '';
$otp;

require '../class.FastAuth.php';

$auth = new FastAuth();
try {

    switch ($for) {
        case FastAuth::FOR_VERIFY_MOBILE:
            $otp = $auth->getOtpToVerifyMobile($userID);
            $title = "Mobile number verification successful";
            break;
        case FastAuth::FOR_VERIFY_EMAIL:
            $otp = $auth->getOtpToVerifyEmail($userID);
            $title = "Email verification successful";
            break;
        case FastAuth::FOR_VERIFY_CREATED_ACCOUNT:
            $otp = $auth->getOtpToRegisterUser($userID);
            break;
        case FastAuth::FOR_RESET_PASSWORD:
            $otp = $auth->getOtpToResetPassword($userID);
            break;
    }
    if ($isResend) {
        $title = urlencode("OTP re-sent to $emailOrMobile");
    } else {
        $title = urlencode("OTP sent to $emailOrMobile");
    }
    $content = urlencode("Note: For testing purpose the otp is visible on this page. OTP: $otp");
    $redirect = urlencode("verify_otp.php?uid=" . urlencode($userID) . "&for=" . urlencode($for));
    header("Location: message.php?title=$title&content=$content&redirect=$redirect");
} catch (Exception $e) {
    die($e->getMessage());
}
