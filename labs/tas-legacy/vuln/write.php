<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>글 작성</title>
</head>
<body>
    <header>
        <h1 style="font-size:20px;"> 글 작성하기 </h1>
        <a href="index.php">돌아가기</a>
    </header>
    <hr>
    <form action="write_success.php" method="POST" enctype="multipart/form-data">
        <div>
            <label for="title">제목</label><br>
            <input type="text" id="title" name="title" required style="width: 700px; padding: 10px; margin-top: 5px;">
        </div>
        <br>
        <div>
            <label for="content">내용</label><br>
            <textarea id="content" name="content" rows="10" required style="width: 700px; padding: 10px; margin-top: 5px; height: 500px; font-weight: bold;"></textarea>
        </div>
        <br>
        <div>
            <label for="file">첨부파일</label><br>
            <input type="file" name="file" id="uploadfile" style="margin-top: 5px;">
        </div>
        <br>
        <div>
            <button type="submit">등록</button>
        </div>  
    </form>
</body>
</html>