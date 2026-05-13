<?php
include ("database.php");
session_start();

$id = $_POST['userid'];
$password = $_POST['password'];

//SQL Injection 취약점 id와 password에 sql 명령어가 들어가도 검열을 하지 않는다.    
$sql = "SELECT * FROM users WHERE user_id = '$id' AND user_password = '$password'";
$result = $connect_db->query($sql);
$user = $result->fetch_assoc();

if($user){
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['username'] = $user['username'];
    header("Location: index.php");
    exit;
}else{
    echo "<script>alert('아이디 또는 비밀번호가 틀렸습니다.'); history.back(); </script>";
}

$connect_db->close();
?>