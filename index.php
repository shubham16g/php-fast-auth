<?php
header('Content-type: application/json');
$time = microtime(true);






require './class.FastAuth.php';
$auth = new FastAuth();

$user = [
    // 'mobile' => "+919336508098",
    'email' => "s@gmail.com",
    'password' => '123456',
    // 'userType' => 4,
    'extraJson' => '{"hello":"hai"}'
];

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