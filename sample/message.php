<?php
$title = $_GET['title'];
$content = $_GET['content'];
$redirect = $_GET['redirect'];
$duration = 5000;
if (isset($_GET['duration'])) {
    $duration = $_GET['duration'];
}

?>


<!DOCTYPE html>

<head>
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Message</title>
    <link rel="stylesheet" href="./css/style.css">
</head>

<body>
    <center>
        <h3>
            <?= $title ?>
        </h3>
        <p><?= $content ?></p>
    </center>
    <script>
        window.onload = function() {
            // var newWindow = window.open("", "Title2", "toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes,resizable=yes,width=400,height=400,top=200,left=" + (screen.width - 840));
            // newWindow.document.write("' . $otp . '");
            setTimeout(() => {
                window.location.href = "<?= $redirect ?>";
            }, <?= $duration ?>);
        }
    </script>

</body>

</html>