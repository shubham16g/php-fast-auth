<?php

session_start();

if (!isset($_SESSION['userID']) || !isset($_SESSION['token'])) {
    header("Location: signin.php");
}
require '../class.FastAuth.php';

$auth = new FastAuth();

$userJson;
try {
    $userID = $_SESSION['userID'];
    $auth->verifyUser($userID, $_SESSION['token']);
    $userData = $auth->getUser($userID);

    $userJson = json_encode($userData, JSON_PRETTY_PRINT);
} catch (Exception $e) {
    echo $e->getMessage();
    die();
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>
    <a href="./signout.php" class="btn">Sign out</a>
    <h4>Current User Data:</h4>
    <pre><?= $userJson ?></pre>


</body>

</html>