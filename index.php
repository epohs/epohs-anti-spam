<?php include_once("inc/epohs-anti-spam.php"); ?>
<!doctype html>
<html lang="en">

<head>
<meta charset="utf-8" />
<meta http-equiv="x-ua-compatible" content="ie=edge" />
<meta name="viewport" content="width=device-width, initial-scale=1" />

<title>epohs anti-spam</title>
</head>

<body>


<form action="<?= $eas->self_url ?>" method="POST" />

  <?php $eas->init_form(); ?>

  <input type="text" name="name" placeholder="John Doe" /><br />
  <input type="text" name="email" placeholder="john_doe@example.com" /><br />

  <input type="submit" name="submit" value="Go" />

</form>


CHECK FORM: <?= $eas->check_form(); ?>



<script src="https://ajax.googleapis.com/ajax/libs/jquery/2.1.4/jquery.min.js"></script>
</body>

</html>