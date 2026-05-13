<?php

$host = "mysql";
$user = "root";
$password = "root";
$database = "board";

$connect_db = new mysqli($host,$user,$password,$database);
if($connect_db -> connect_error){
    die('mysql 연결 실패'. $connect_db->connect_error);
}
