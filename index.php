<?php
header("type: application/json");
$time = microtime(true);
require 'fastAuth.php';

$auth = new FastAuth(new DatabaseCredentials('eleamapi'));

$user = [
    // 'mobile' => "+919336508098",
    'email' => "s@gmail.com",
    'password' => '123456',
    // 'userType' => 4,
    'extraJson' => '{"hello":"hai"}'
];

try {
    // echo $auth->createUser($user);
    $user = $auth->signInWithEmailAndPassword('s@gmail.com', '123456');
    // echo $auth->generateOTP(10000, FastAuth::FOR_RESET_PASSWORD);
    // echo $auth->verifyOTP(682078, 10033, 0);
    // $auth->disableUser(10000);
    // $auth->enableUser(10000);
    // $auth->resetPassword(10000, '111111', 999211);
    // $auth->signOutAllDevices(10000, '/qjMtK8Pqs6ZIYE8ZVgEV.fVUHQM2faKgjy6HnWN32362V.fVUHQM2faKgjy6HnWN5bbLAFBpRQIue');
    // $token = $auth->verifyUser(10000, '/qjMtK8Pqs6ZIYE8ZVgEV.fVUHQM2faKgjy6HnWN32362V.fVUHQM2faKgjy6HnWN5bbLAFBpRQIue');
    var_dump($user);
    
} catch (Exception $e) {
    echo $e->getMessage();
}

$newTime = microtime(true);

echo '<br><br>' . round(($newTime - $time) * 1000) . 'ms';
