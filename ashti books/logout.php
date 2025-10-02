<?php
session_start();

// سڕینەوەی هەموو سیشنەکان
session_unset();
session_destroy();

// گەڕانەوە بۆ پەڕەی چوونەژوورەوە
header("Location: admin.php");
exit();
?>