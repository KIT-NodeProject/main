<?php
session_start();
include 'database.php';

//XSS 취약점 content나 title을 post 받았을 때 <script> 등이 들어와도 검열을 하지 않는다.
$title = $_POST['title'];
$content = $_POST['content'];
$username = $_SESSION['username'];
$folder = "./uploads/";

if(!isset($_SESSION['username'])) {
    echo "<script>alert('로그인이 필요합니다.'); location.href='login.php';</script>";
    exit;
}

if($_SERVER['REQUEST_METHOD'] == 'POST'){
        
    //File Upload 취약점 파일로 악성 파일 확장자 등 확장자에 대한 검열을 하지 않는다.
    if(($_FILES['file']) != NULL){
        $tmp_name = $_FILES['file']['tmp_name'];
        $filename = $_FILES['file']['name'];
        move_uploaded_file($tmp_name, "$folder/$filename");
    }
    
    if (!is_dir($folder)) {
        mkdir($folder, 0777, true);
    }
    
    $sql = "INSERT INTO list (name, title, content, filename) VALUES ('$username', '$title', '$content', '$filename')";

    $result = $connect_db->query($sql);
    if($result){
        echo "<script>alert('글쓰기 성공!'); location.href='index.php';</script>";
    }else{
        echo "<script>alert('글쓰기 도중 오류가 발생했습니다. 다시 시도해주세요'); history.back();</script>";
    }
    $connect_db->close();   
}

?>