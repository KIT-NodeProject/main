<?php
session_start();
ini_set('display_errors', 0);

//file download 취약점 ./uploads/에 파일이 아니어도 다운 받을 수 있다.
//보안 -> basename을 통해 file 경로를 마음대로 하지 못하게 막아준다.
$filename = basename($_GET['name']);

//보안 -> 만약 basename을 우회하기 위해 악성 파일이 업로드 될 경우를 고려
$check = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if($check !== 'jpg' && $check !== 'png'){
    echo "<script>alert('다운로드 불가!'); history.back();</script>";
    exit;
}

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
