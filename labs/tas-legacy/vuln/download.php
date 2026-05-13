<?php
session_start();

//file download 취약점 ./uploads/에 파일이 아니어도 다운 받을 수 있다.
$filename = $_GET['name'];

$path_file = "./uploads/$filename";

if (file_exists($path_file)) {
    header("content-type: application/octetstream");
    header("Content-disposition: attachment; filename=$filename");
    header("content-length".filesize($path_file));
    header('Content-Transfer-Encoding:binary');
    ob_clean();
    readfile($path_file);
    exit;
}
else{
    echo "<script>alert('오류'); history.back();</script>";
}
