<?php

// 準備済み文（Prepared Statement）を使用してSQL構造とデータを分離する
$stmt = $db->prepare('SELECT * FROM users WHERE username = :username');

// パラメータをバインドして実行（自動的に安全な型処理が行われる）
$stmt->execute([
    ':username' => $_POST['user']
]);

// 実行結果の取得
$users = $stmt->fetchAll();

?>
