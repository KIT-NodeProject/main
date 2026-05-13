<?php
session_start();
include("database.php");

if (isset($_GET['searchword'])) {
    $searchword = $_GET['searchword'];
} else {
    $searchword = "";
}

//sql injeciton 취약점 searchword에 sql에서 사용하는 명령어가 들어와도 검열을 하지 않는다.
$sql = "SELECT id, title, name, post_date FROM list WHERE title LIKE '%$searchword%' ORDER BY post_date ASC";

$result = $connect_db->query($sql);
?>

<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>게시판</title>
</head>
<body>

<h1>게시판</h1>

<div>
<?php if (isset($_SESSION['user_id'])): ?>
    <a href="mypage.php">마이페이지</a>
    <strong><?= $_SESSION['username'] ?> 님</strong>
    <a href="logout.php" onclick="return confirm('로그아웃 하겠습니까?')">로그아웃</a>
<?php else: ?>
    <a href="login.php">로그인</a>
    <a href="register.php">회원가입</a>
<?php endif; ?>
</div>

<hr>

<form action="" method="get">
    <input type="text" name="searchword" placeholder="제목 검색" value="<?php echo $searchword; ?>">
    <button type="submit">검색</button>
</form>

<hr>

<table border = "1" width = "100%">
    <thead>
        <tr>
            <th>번호</th>
            <th>제목</th>
            <th>작성자</th>
            <th>작성일</th>
            <th>내용확인</th>
        </tr>
    </thead>
    <tbody>
    <?php 
    while ($row = $result->fetch_array()){
    ?>
        <tr>
            <td><?php echo $row['id'] ?></td>
            <td><?php echo $row['title'] ?></td>
            <td><?php echo $row['name'] ?></td>
            <td><?php echo $row['post_date'] ?></td>

            <td>
                <form action="view.php" method="GET">
                    <input type="hidden" name="id" value="<?php echo $row['id'] ?>">
                    <button type="submit">확인</button>
                </form>
            </td>
        </tr>
    <?php
    };
    ?>
    </tbody>
</table>

<hr>

<?php if (isset($_SESSION['user_id'])): ?>
    <a href="write.php">글 작성</a>
<?php else: ?>
    <p>로그인 후 글을 작성할 수 있습니다.</p>
<?php endif; ?>

</body>
</html>
