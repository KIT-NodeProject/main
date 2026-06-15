<!DOCTYPE html>
<html lang = "ko">
<head>
<meta charset="UTF-8">

<title>Login</title>
</head>
<body>
    <form action="login_success.php" method="POST">
        <table>
            <tr>
                <td><h2>로그인</h2></td>
            </tr>
            <tr>
                <td><input type="text" name="userid" placeholder="ID"></td>
            </tr>
            <tr>
                <td><input type="password" name="password" placeholder="Password"></td>
            </tr>
            <tr>
                <td><input type="submit" value="로그인" class="button"></td>
            </tr>
            <tr>
                <td><a href="index.php" class="button" >돌아가기</a></td>
            </tr>

            <tr>
                <td class="join"><a href="register.php">회원가입</a></td>
            </tr>
        </table>
    </form>
</body>
</html>