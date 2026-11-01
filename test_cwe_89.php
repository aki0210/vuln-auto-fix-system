$sql = "SELECT * FROM users WHERE username = '" . $_POST['user'] . "'";
$db->query($sql);
