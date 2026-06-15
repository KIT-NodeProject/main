<?php
session_start();
ini_set('display_errors', 0);

include 'database.php';

$id = $_GET['id'];
$sql = "SELECT * FROM list WHERE id = '$id'";
$result = $connect_db->query($sql);
$row = $result->fetch_assoc();
$filename = $row['filename'];
$upload_file = "./uploads/$filename";

if ($result) {
    if (file_exists($upload_file)) {
        unlink($upload_file);
    }

    $sql_delete = "DELETE FROM list WHERE id = $id";
    $sql_id = "ALTER TABLE list AUTO_INCREMENT = $id";
    if ($connect_db->query($sql_delete)) {
        $connect_db->query($sql_id);
        echo "<script>alert('삭제 성공!'); location.href='mypage.php';</script>";
        exit;
    } else {
        echo "삭제 실패";
    }
} else {
    echo "삭제 실패";
}

$result = $connect_db->close();
?>