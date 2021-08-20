<?php

session_start();

if (!isset($_SESSION['uid']) || !isset($_SESSION['token'])) {
    header("Location: signin.php");
}
require_once dirname(__FILE__, 2) . '/PHPFastAuth.php';
require_once dirname(__FILE__, 1) . '/config.php';


$userData;
try {
    $auth = new PHPFastAuth($db);
    $uid = $_SESSION['uid'];
    $auth->verifyToken($_SESSION['token']);
    $userData = $auth->getUser($uid);

    if (isset($_POST['updateMobile'])) {
        header("Location: update.php?type=mobile");
    } elseif (isset($_POST['updateEmail'])) {
        header("Location: update.php?type=email");
    } elseif (isset($_POST['updateName'])) {
        header("Location: update.php?type=name");
    }
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
    <form action="" accept-charset="UTF-8" method="post" style="margin-bottom: 10px; max-width:100vw;">
        <input type="submit" name="updateEmail" value="<?= ($userData['email'] != null) ? 'Update Email' : "Link Email"; ?>" class="btn">
        <input type="submit" name="updateMobile" value="<?= ($userData['mobile'] != null) ? 'Update Mobile' : "Link Mobile"; ?>" class="btn">
        <input type="submit" name="updateName" value="<?= ($userData['name'] != null) ? 'Update Name' : "Add Name"; ?>" class="btn">
    </form>
    <a href="./signout.php" class="btn">Sign out</a>

    <h4>Current User Data:</h4>
    <pre><?= json_encode($userData, JSON_PRETTY_PRINT) ?></pre>


</body>

</html>