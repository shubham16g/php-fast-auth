<?php
require_once dirname(__FILE__, 2) . '/PHPFastAuth.php';
require_once dirname(__FILE__, 1) . '/config.php';
try {
    $auth = new PHPFastAuth($db);
    $auth->install();
    echo "PHP-Fast-Auth installed successfully";    
} catch (Exception $e) {
    echo $e->getMessage();
}
