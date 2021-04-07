<?php
// header('Content-type: application/json');

use FastAuth\Options;

$time = microtime(true);






require './class.FastAuth.php';
require './class.FastAuthConstants.php';


$option = new FastAuth\Options("localhost", 'root', '', 'eleamapi');

$auth = new FastAuth($option);

$user = [
    // 'mobile' => "+919336508098",
    'email' => "s@gmail.com",
    'password' => '123456',
    // 'userType' => 4,
    'extraJson' => '{"hello":"hai"}'
];
session_start();

$countryCodeList = ['+91', '+1', '+12', '+2'];

if (isset($_SESSION['uid']) && isset($_SESSION['token'])) {
    header("Location: index.php");
}


if (isset($_POST['submit'])) {

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
        $uid = $signInResult['uid'];
        $token = $signInResult['token'];

        $_SESSION['uid'] = $uid;
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
try {
    echo json_encode($auth->getUserByEmail('samddd@gmail.com'), JSON_PRETTY_PRINT);

    echo '

';
        // return openssl_decrypt($otpHash, "AES-128-ECB", "__^!@XQ@z#$&*^%%Y&$&*^__");
    // $key = $auth->createUserWithEmail('samddd@gmail.com', '123456', 'Sam');
    // echo $key;
    
    echo '

'; 
    // $otp = $auth->generateOTP($key);
    // echo $otp;
    echo '

';
    // $result = $auth->verifyOTP($key, $otp);
    // print_r($result);
    // 477145
    // $res = $auth->verfiyCreatedUser('10002', '477145');
    // var_dump($res);
    // $user = $auth->signInWithEmailAndPassword('s@gmail.com', '123456');
    // echo $auth->generateOTP(10000, FastAuth::FOR_RESET_PASSWORD);
    // echo $auth->verifyOTP(682078, 10033, 0);
    // $auth->disableUser(10000);
    // $auth->enableUser(10000);
    // $auth->resetPassword(10000, '111111', 999211);
    // $auth->signOutAllDevices(10000, '/qjMtK8Pqs6ZIYE8ZVgEV.fVUHQM2faKgjy6HnWN32362V.fVUHQM2faKgjy6HnWN5bbLAFBpRQIue');
    // $token = $auth->verifyUser(10000, '/qjMtK8Pqs6ZIYE8ZVgEV.fVUHQM2faKgjy6HnWN32362V.fVUHQM2faKgjy6HnWN5bbLAFBpRQIue');
} catch (Exception $e) {
    echo $e->getMessage();
}
$newTime = microtime(true);
echo '
' . round(($newTime - $time) * 1000) . 'ms';
die();
$key = "__^!@__";
$otp = "454";
$enc = openssl_encrypt($otp, "AES-128-ECB", $key);
echo $enc;
echo '<br><br>';
$dec = openssl_decrypt($enc, "AES-128-ECB", $key);
echo $dec;
echo '<br><br>';
echo bin2hex(openssl_random_pseudo_bytes(16));
echo '<br><br>';
$jsonEncode = json_encode(['user' => [['data' => 65], 'hello']]);
$jsonEncode = json_encode(['user' => ['{"data":65}', 'hello']]);
// $jsonEncode = json_decode('{"user":[{"data":65}, "hello"]}');
print_r($jsonEncode);