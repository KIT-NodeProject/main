<?php
include ("database.php");

$id = $_GET['id'];
$sql = "SELECT * FROM list WHERE id = $id";
$result = $connect_db->query($sql);



$row = $result->fetch_assoc();
if(!$row){
    echo "<script>alert('게시글이 없습니다'); location.href='index.php';</script>";
}

?>

<!DOCTYPE html>
<html>
<head>
<meta charset = "UTF-8">
<title><?php echo $row['title']?> - 게시글</title>
</head>
<body>
    <h2><?php echo $row['title']?></h2>
    <h2><?php echo $row['name']?></h2>
    <h2><?php echo $row['content']?></h2>
    <p>첨부파일:</p>
    <a href = "download.php?name=<?php echo $row['filename']?>"><?php echo $row['filename']?></a>
    <hr>
    <div>
        <a href="index.php">목록으로 돌아가기</a>
    </div>
   
</body>
</html>
<?php $connect_db->close(); ?>