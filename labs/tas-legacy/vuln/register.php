<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>Register</title>
</head>
<body>
    <form action="register_success.php" method="POST">
        <table>
            <tr>
                <td><h2>회원가입</h2></td>
            </tr>

            <tr>
                <td><h2>닉네임</h2></td>
            </tr>
            <tr>
                <td><input type="text" name="nickname" placeholder="별명"></td>
            </tr>

            <tr>
                <td><h2>아이디</h2></td>
            </tr>
            <tr>
                <td><input type="text" name="userid" placeholder="ID"></td>
            </tr>

            <tr>
                <td><h2>비밀번호</h2></td>
            </tr>
            <tr>
                <td><input type="password" name="password" placeholder="Password"></td>
            </tr>

            <tr>
                <td><h2>비밀번호 확인</h2></td>
            </tr>
            <tr>
                <td><input type="password" name="password_again" placeholder="Password"></td>
            </tr>

            <tr>
                <td><input type="submit" value="회원가입"></td>
            </tr>

            <tr>
                <td><a href="login.php">로그인하러 가기</a></td>
            </tr>
        </table>
    </form>
</body>
</html>