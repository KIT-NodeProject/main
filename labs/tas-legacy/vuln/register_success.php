<?php
include ("database.php");

$nickname = $_POST['nickname'];
$userid = $_POST['userid'];
$password = $_POST['password'];
$password_again = $_POST['password_again'];

if ($nickname === '' || $userid === '' || $password === '' || $password_again === ''){
    echo "<script>alert('모든 항목을 1자 이상 입력해 주세요.'); history.back();</script>";
    exit;
}

if($password !== $password_again){
    echo "<script>alert('비밀번호가 일치하지 않습니다.'); history.back();</script>";
    exit;
}

$sql = "INSERT INTO users (username, user_id, user_password) VALUES ('$nickname', '$userid', '$password')";
$result = $connect_db->query($sql);

if($result){
    echo "<script>alert('회원가입 성공!'); location.href='login.php';</script>";
}else{
     echo "<script>alert('닉네임 중복 혹은 오류가 발생했습니다.'); history.back();</script>";
}

$connect_db->close();
?>
