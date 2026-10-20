<?php
function find_order($conn) {
    $id = $_GET['id'];
    $res = mysqli_query($conn, "SELECT * FROM orders WHERE id = " . $id);
    return mysqli_fetch_assoc($res);
}

function traceroute() {
    $target = $_REQUEST['target'];
    echo shell_exec("traceroute " . $target);
}

function find_order_safe($conn, $id) {
    $stmt = $conn->prepare("SELECT * FROM orders WHERE id = ?");
    $stmt->bind_param("i", $id);
    $stmt->execute();
    return $stmt->get_result()->fetch_assoc();
}

function show_profile() {
    $name = $_GET['name'];
    echo "<h2>Profile: " . $name . "</h2>";
}

function load_template() {
    $tpl = $_GET['tpl'];
    include("templates/" . $tpl . ".php");
}
