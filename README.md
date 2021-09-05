# Fast-Auth
Easy and Fast PHP authentication (MySQL Database)

## Docs

### Initialize
PHPFastAuth requires mysqli object to connect with your MYSQL database.

You can use $mysqli_db = new mysqli($host, $username, $password, $dbname);

try {
    $auth = new PHPFastAuth($mysqli_db);
} catch (Exception $e) {
    echo $e->getMessage();
}

or

try {
    $options = new PHPFastAuth\Options();
    $options->setOTPLength(4);

    $auth = new PHPFastAuth($mysqli_db, $options);
} catch (Exception $e) {
    echo $e->getMessage();
}

### Install
This code must be called once to create required tables in your database.

try {
    $auth = new PHPFastAuth($mysqli_db);
    $auth->install();
} catch (Exception $e) {
    echo $e->getMessage();
}

### OTP Sign up with Mobile

try {
    $auth = new PHPFastAuth($db);

    $signUp = new PHPFastAuth\SignUpWithMobile($mobile);
    $signUp->setName($name);
    $signUp->setPassword($password);

<!-- this key used to decode and verify OTP-->
    $key = $auth->signUpRequest($signUp);

<!-- OTPData contains the otp, case, name, type ("mobile" or "email"), mobile, email-->
    $otpData = $auth->decodeOTP($key);

    $mobile = $otpData->getMobile();            
    $otp = $otpData->getOTP();

<!-- your custom method to send OTP -->
    sendOTPviaSMS($mobile, $otp);

} catch (Exception $e) {
    echo $e->getMessage();
}

### OTP Sign up with Email

try {
    $auth = new PHPFastAuth($db);

    $signUp = new PHPFastAuth\SignUpWithEmail($email);
    $signUp->setName($name);
    $signUp->setPassword($password);

<!-- this key used to decode and verify OTP-->
    $key = $auth->signUpRequest($signUp);

<!-- OTPData contains the otp, case, name, type ("mobile" or "email"), mobile, email-->
    $otpData = $auth->decodeOTP($key);

    $email = $otpData->getEmail();            
    $otp = $otpData->getOTP();

<!-- your custom method to send OTP -->
    sendOTPviaEmail($email, $otp);

} catch (Exception $e) {
    echo $e->getMessage();
}

### Verify OTP
<!-- restul is a array conatinig info based on case. -->
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