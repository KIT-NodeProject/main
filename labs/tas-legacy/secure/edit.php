<?php
session_start();
ini_set('display_errors', 0);
include ("database.php");

if (!isset($_SESSION['username'])) {
    echo "<script>alert('로그인이 필요합니다.'); location.href='login.php';</script>";
    exit;
}

$id = $_GET['id'];
$sql = "SELECT * FROM list WHERE id = $id";
$result = $connect_db->query($sql);
$row = $result->fetch_assoc();

if(!$row){
    echo "존재하지 않는 게시글입니다";
    exit;
}

if($row['name'] !== $_SESSION['username']){
    echo "<script>alert('이 게시글을 수정할 수 없습니다.'); history.back();</script>";
    exit;
}
?>

<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>글 수정하기</title>
</head>
<body>
    <header>
        <h1 style="font-size:20px;"> 글 수정하기 </h1>
        <a href="mypage.php">돌아가기</a>
    </header>
    <hr>
    <form action="edit_success.php" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="id" value = "<?php echo $id; ?>">
        <div>
            <label for="title">제목</label><br>
            <input type="text" id="title" name="title" required style="width: 700px; padding: 10px; margin-top: 5px;" value = "<?php echo $row['title']; ?>">
        </div>
        <br>
        <div>
            <label for="content">내용</label><br>
            <textarea id="content" name="content" rows="10" required style="width: 700px; padding: 10px; margin-top: 5px; height: 500px; font-weight: bold;"><?php echo $row['content']; ?></textarea>
        </div>
        <br>
        <div>
            <label for="file">첨부파일</label><br>
            <input type="file" name="file" id="uploadfile" style="margin-top: 5px;">
            <?php
                if(!empty($row['filename'])){
                    echo "현재 첨부파일: " . $row['filename'];
                }
            ?>
        </div>
        <br>
        <div>
            <button type="submit">등록</button>
        </div>  
    </form>
</body>
</html>