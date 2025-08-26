<?php

// SQLi vulnerable server

// Virtual endpoints
// GET /message.php?id=
// POST /login.php
//  - user
//  - password

define('SQLITE_DB_FILE', 'test.db');

# PHP config
#<
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
#>

# cli: --init
if ( isset($argc) && $argc == 2 && $argv[1] == "--init") {
#<
    // BD already initialized
    #<
    if (file_exists(SQLITE_DB_FILE)) {
        echo "[Error] DB already initialized!\n";
        exit;
    }
    #>

    $db = new SQLite3(SQLITE_DB_FILE);
    // Create user table
    #<
    $ddl = "CREATE TABLE IF NOT EXISTS user ("
        ." id INTEGER PRIMARY KEY AUTOINCREMENT,"
        ." name TEXT,"
        ." email TEXT,"
        ." password_hash TEXT"
    .")";
    $db->exec($ddl);
    #>

    // Create messages table
    #<
    $ddl = "CREATE TABLE IF NOT EXISTS message ("
        ." id INTEGER PRIMARY KEY AUTOINCREMENT,"
        ." body TEXT"
    .")";
    $db->exec($ddl);
    #>

    // Insert sample users
    #<
    $users = [
        (object) [
            "name"          => "h.simpson",
            "email"         => "h.simpson@gmail.com",
            "password_hash" => "e10adc3949ba59abbe56e057f20f883e"
        ],
        (object) [
            "name"          => "m.burns",
            "email"         => "m.burns@gmail.com",
            "password_hash" => "9726255eec083aa56dc0449a21b33190"
        ]
    ];
    foreach ($users as $u) {
        $sql = "INSERT INTO user(name, email, password_hash)"
            ." VALUES('$u->name', '$u->email', '$u->password_hash')";
        $db->exec($sql);
    }
    echo "Users created!\n";
    #>

    // Insert sample messages
    #<
    $messages = [
        (object) [
            "body" => "hola mundo"
        ],
        (object) [
            "body" => "Esto es un mensaje!"
        ],
        (object) [
            "body" => "Sección interesante con un texto largo"
        ]
    ];
    foreach ($messages as $m) {
        $sql = "INSERT INTO message(body) VALUES('$m->body')";
        $db->exec($sql);
    }
    echo "Messages created!\n";
    #>
    exit;
#>
}

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];

$db = new SQLite3(SQLITE_DB_FILE);

// POST methods
if ($method == "POST") {
    // login
    #<
    if ($uri == "/login.php") {
        $user = $_POST['user'] ?? null;
        $password = $_POST['password'] ?? null;

        // empty fields
        if (is_null($user) || is_null($password)) {
            http_response_code(400);
            exit;
        }

        // Try to login
        $password = md5($password);
        $sql = "SELECT COUNT(id) AS users"
            ." FROM user"
            ." WHERE name = '$user' AND password_hash = '$password'";
        // Debug query
        error_log($sql);
        $result = $db->query($sql);
        $is_login_ok = $result->fetchArray(SQLITE3_ASSOC)['users'] > 0;

        http_response_code($is_login_ok ? 204 : 403);
        exit;
    }
    #>
}
// GET METHODS
else if ($method == "GET") {
    // messages
    #<
    if (strpos($uri, "/message.php") !== false) {
        $id = $_GET['id'] ?? null;

        // Empty id
        if (is_null($id)) {
            http_response_code(404);
            exit;
        }

        // Search message at sqlite3
        $sql = "SELECT id, body"
            ." FROM message"
            ." WHERE id = $id";
        $message = $db->query($sql)->fetchArray(SQLITE3_ASSOC);
        if (!$message)
            http_response_code(404);
        else
            echo json_encode((object) $message);
    }
    #>
}

?>
