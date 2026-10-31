<?php
// A small legacy PHP shop. Intentionally insecure, for education.

$db_password = "php-db-pass-7c31d9e2a4";
$conn = mysqli_connect("localhost", "root", $db_password, "shop");

function search_products($conn) {
    $term = $_GET['q'];
    $result = mysqli_query($conn, "SELECT * FROM products WHERE name LIKE '%" . $term . "%'");
    return $result;
}

function run_report() {
    $out = shell_exec("report.sh " . $_GET['name']);
    echo $out;
}

function hash_password($password) {
    return md5($password);
}

function new_reset_token() {
    return mt_rand();
}

function show_page() {
    include $_GET['page'] . ".php";
}

function restore_cart() {
    return unserialize($_COOKIE['cart']);
}

function greet() {
    echo "<h1>Hello " . $_GET['name'] . "</h1>";
}

function fetch($url) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    return curl_exec($ch);
}

function read_upload() {
    return file_get_contents("/srv/uploads/" . $_GET['file']);
}
