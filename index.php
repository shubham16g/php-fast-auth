<?php

include './class.FastAuth.php';
include './sample/autoload.php';

try {
    $auth = new FastAuth($db);
    $users = $auth->listUsers();
    print_r($users);
} catch (Exception $e) {
    die($e);
}