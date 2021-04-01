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
    <style>
        .p-bar {
            position: absolute;
            top: 0;
            width: 100vw;
            background-color: #ff5555;
            left: 0;
            transform: translateX(-100vw);
            height: 5px;
            transition: all <?= $duration ?>ms linear;
        }
    </style>
</head>

<body>
    <div class="p-bar"></div>
    <center>
        <h3>
            <?= $title ?>
        </h3>
        <p><?= $content ?></p>
        <br>
        <br>
        <br>
        <h4 id="redirect">Redirect in 6 seconds!</h4>
    </center>
    <script>
        var duration = <?= $duration ?>;
        const red = document.getElementById('redirect');
        window.onload = function() {
            // var newWindow = window.open("", "Title2", "toolbar=no,location=no,directories=no,status=no,menubar=no,scrollbars=yes,resizable=yes,width=400,height=400,top=200,left=" + (screen.width - 840));
            // newWindow.document.write("' . $otp . '");
            setTimeout(() => {
                window.location.href = "<?= $redirect ?>";
            }, duration);



            printTimeout();

            document.querySelector('.p-bar').style.transform = 'translateX(0)';
        }


        function printTimeout() {
            var second = parseInt(duration / 1000);
            red.innerHTML = `Redirect in ${second} seconds!`;
            duration = duration - 1000;
            setTimeout(() => {
                if (duration > 0) {
                    printTimeout();
                }
            }, 1000);
        }
    </script>

</body>

</html>