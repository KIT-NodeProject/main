<?php
session_start();
ini_set('display_errors', 0);
include ("database.php");

$id = $_POST['userid'];
$password = $_POST['password'];

//SQL Injection 취약점 id와 password에 sql 명령어가 들어가도 검열을 하지 않는다.  
  
$sql = "SELECT * FROM users WHERE user_id = ? AND user_password = ?";

//보안 -> prepared statement을 이용해 sql 명령어가 들어와도 적용이 되지 않게 해준다.
$stmt = $connect_db->stmt_init();
$stmt->prepare($sql);
$stmt->bind_param("ss", $id, $password);
$stmt->execute();

$result = $stmt->get_result();
$user = $result->fetch_assoc();

if($user){
    $_SESSION['user_id'] = $user['user_id'];
    $_SESSION['username'] = $user['username'];
    header("Location: index.php");
    exit;
}else{
    echo "<script>alert('아이디 또는 비밀번호가 틀렸습니다.'); history.back(); </script>";
}

$stmt->close();
$connect_db->close();
?>