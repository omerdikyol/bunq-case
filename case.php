<?php 

// Slim Network and SQLite
require 'vendor/autoload.php';

// Slim Network
use Slim\App;

// Set up app
$app = new App();

// Set up database
$db = new SQLite3('database.db');


// define routes for API

// Route for login
$app->post('/login', function ($request, $response, $args) use ($db) {
    $data = $request->getParsedBody();
    $username = $data['username'];
    $password = $data['password'];

    // fetch user from database
    $stmt = $db->prepare('SELECT * FROM users WHERE username = :username');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);

    // check if user exists
    if ($user) {
        // check if password is correct
        if (password_verify($password, $user['password'])) {
            // generate token
            $token = bin2hex(random_bytes(16));

            // insert token into database
            $stmt = $db->prepare('UPDATE users SET token = :token WHERE username = :username');
            $stmt->bindValue(':token', $token, SQLITE3_TEXT);
            $stmt->bindValue(':username', $username, SQLITE3_TEXT);
            $stmt->execute();

            // return token
            return $response->withJson(['token' => $token]);
        } else {
            // return error if password is incorrect
            return $response->withJson(['error' => 'Invalid password'], 401);
        }
    }
});


// Route for register
$app->post('/register', function ($request, $response, $args) use ($db) {
    // get username and password from request
    $data = $request->getParsedBody();
    $username = $data['username'];
    $password = $data['password'];

    // check if username is already taken
    $stmt = $db->prepare('SELECT * FROM users WHERE username = :username');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    // return error if username is already taken
    if ($user) {
        return $response->withJson(['error' => 'Username already taken'], 409);
    }

    // hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // insert user into database
    $stmt = $db->prepare('INSER INTO users (username, password) VALUES (:username, :password)');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $hashedPassword, SQLITE3_TEXT);
    $stmt->execute();

    // return success message
    return $response->withJson(['message' => 'User created with id ' . $db->lastInsertRowID()]); 
});


// Route for receiving messages
$app->get('/messages', function ($request, $response, $args) use ($db) {
    // get token from request
    $token = $request->getHeader('Authorization')[0];

    // check if token is valid
    $stmt = $db->prepare('SELECT * FROM users WHERE token = :token');
    $stmt->bindValue(':token', $token, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);

    // fetch messages from database
    $messages = [];
    while ($message = $result->fetchArray(SQLITE3_ASSOC)) {
        $messages[] = [
            'id' => $message['id'],
            'sender' => $message['sender'],
            'receiver' => $message['receiver'],
            'message' => $message['message'],
            'timestamp' => $message['timestamp']
        ];
    }

    // return messages
    return $response->withJson(['messages:' => $messages]);
});


// Route for sending messages
$app->post('/messages', function ($request, $response, $args) use ($db) {
    // get token from request
    $token = $request->getHeader('Authorization')[0];

    // check if token is valid
    $stmt = $db->prepare('SELECT * FROM users WHERE token = :token');
    $stmt->bindValue(':token', $token, SQLITE3_TEXT);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);

    // get message from request
    $data = $request->getParsedBody();
    $receiver = $data['receiver'];
    $message = $data['message'];
    $timestamp = $data['timestamp'];

    // insert message into database
    $stmt = $db->prepare('INSERT INTO messages (sender, receiver, message) VALUES (:sender, :receiver, :message)');
    $stmt->bindValue(':sender', $user['username'], SQLITE3_TEXT);
    $stmt->bindValue(':receiver', $receiver, SQLITE3_TEXT);
    $stmt->bindValue(':message', $message, SQLITE3_TEXT);
    $stmt->bindValue(':timestamp', $timestamp, SQLITE3_TEXT);
    $stmt->execute();

    // return success message
    return $response->withJson(['message' => 'Message sent with id ' . $db->lastInsertRowID()]);
});

// Run the Slim app
$app->run();