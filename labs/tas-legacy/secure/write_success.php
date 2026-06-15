<?php
session_start();
ini_set('display_errors', 0);
include 'database.php';

//XSS 취약점 content나 title을 post 받았을 때 <script> 등이 들어와도 검열을 하지 않는다.
$title = htmlspecialchars($_POST['title']);
$content = htmlspecialchars($_POST['content']);
$username = $_SESSION['username'];
$folder = "./uploads/";

if(!isset($_SESSION['username'])) {
    echo "<script>alert('로그인이 필요합니다.'); location.href='login.php';</script>";
    exit;
}

if($_SERVER['REQUEST_METHOD'] == 'POST'){
        
    $filename = "";
    //보안 -> XSS이 일어나지 않게 title, content를 <script> 등이 작동되지 않게 해준다.
    //File Upload 취약점 파일로 악성 파일 확장자 등 확장자에 대한 검열을 하지 않는다.
    //보안 -> 파일 확장자를 jpg, png만 올릴 수 있게 해준다.
    
    //파일이 없을 때도 check하는 경우가 일어나서 파일이 없을 때는 검사를 하지 않게 해준다.
    if((isset($_FILES['file']) && $_FILES['file']['error'] === UPLOAD_ERR_OK)){
        
        if (!is_dir($folder)) {
            mkdir($folder, 0777, true);
        }

        $tmp_name = $_FILES['file']['tmp_name'];
        $filename = $_FILES['file']['name'];
        $check = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

        if($check !== 'jpg' && $check !== 'png'){
            echo "<script>alert('jpg 또는 png 파일만 업로드할 수 있습니다.'); history.back();</script>";
            exit;
        }

        //mime 타입으로 검사를 해준다.
        if($_FILES['file']['type'] !== 'image/jpeg' && $_FILES['file']['type'] !== 'image/png' ){
            echo "<script>alert('허용된 파일이 아닙니다. 다시 작성해주세요'); history.back();</script>";
            exit;
        }

        //파일 이중 확장자 예방 
        $doublefile = strtolower($filename);
        $parts = explode('.', $doublefile);
        if(count($parts) >= 2){
            echo "<script>alert('이중 확장자 공격이 감지되었습니다!'); history.back();</script>";
            exit;
        }
        
        move_uploaded_file($tmp_name, "$folder/$filename");
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