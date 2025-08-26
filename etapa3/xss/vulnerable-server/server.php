<?php

// XSS vulnerable server

// Virtual endpoints
// GET /get-message.php?id=

# PHP config
#<
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);
#>

$uri = $_SERVER['REQUEST_URI'];
$method = $_SERVER['REQUEST_METHOD'];


// GET METHODS
if ($method == "GET") {
    // messages
    #<
    if (strpos($uri, "/get-message.php") !== false) {
        // Get id from QS
        $id = $_GET['id'] ?? null;

        if ( !is_null($id) ) {

            // Define messages
            $messages = [
                (object)["id" => 10, "text" => "Hola mundo!"],
                (object)["id" => 23, "text" => "Este es un mensaje secreto!"],
            ];
    
            // Search messages
            $search_result = array_filter(
                $messages,
                function($m) use ($id) { return $m->id == $id; }
            );
    
            // Message found
            if ( count($search_result) == 1 ) {
                echo $search_result[0]->text;
                exit(0);
            }
    
            // Message not found
            else {
                echo "Message id: $id not found!";
            }
        }
    }
    #>
}

?>

<form action="http://localhost:4000/get-message.php" method="GET">
    <div>
        <label for="msg-id">Message Id:</label>
        <input id="msg-id" name="id" type="text">
    </div>
    <div>
        <button>Get Message</button>
    </div>
</form>
