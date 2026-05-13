<?php
session_start();
include ("database.php");

if(!isset($_SESSION['username'])){
    echo "로그인 후 이용해 주세요";
    exit;
}

$username = $_SESSION['username'];
$sql = "SELECT id, title, post_date FROM list WHERE name = '$username' ORDER BY post_date ASC";
$result = $connect_db->query($sql);
?>

<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>마이페이지</title>
</head>
<body>
    <header>
        <h1>마이페이지</h1>
        <a href = "index.php">돌아가기</a>
    </header>
    <hr>
    <h2> 내가 쓴 글 목록 </h3>
    <table>
        <thead>
        <tr>
            <th>번호</th>
            <th>제목</th>
            <th>작성일</th>
            <th>삭제</th>
            <th>수정</th>
        </tr>
        </thead>
        <tbody>
        <?php if($result->num_rows > 0):?>
            <?php while ($row = $result->fetch_array()): ?>
                <tr>
                    <td><?php echo $row['id'];?></td>
                    <td><?php echo $row['title'];?></td>
                    <td><?php echo $row['post_date']; ?> </td>
                    <td>
                        <form action="delete.php" method="GET">
                            <input type="hidden" name="id" value="<?php echo $row['id'] ?>">
                            <button type="submit">삭제</button>
                        </form>
                    </td>

                    <td>
                        <form action="edit.php" method="GET">
                            <input type="hidden" name="id" value="<?php echo $row['id'] ?>">
                            <button type="submit">수정</button>
                        </form>
                    </td>
                </tr>
            <?php endwhile; ?>
        <?php else: ?>
            <tr>
                <td colspan="5"> 게시글이 없습니다. </td>
            </tr>
        <?php endif; ?>
        </tbody>
    </table>
</body>
</html>

<?php $connect_db->close(); ?>
