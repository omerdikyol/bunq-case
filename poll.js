// How to periodically refresh poll:
setInterval(function () {
    // get token from local storage
    var token = localStorage.getItem('token');

    // check if token is valid
    $.ajax({
        url: 'http://localhost:8080/messages',
        type: 'GET',
        headers: {
            'Authorization': token
        },
        success: function (data) {
            // display messages
            for (var i = 0; i < data.messages.length; i++) {
                var message = data.messages[i];
                $('#messages').append('<p>' + message.sender + ': ' + message.message + '</p>');
            }
        },
        error: function (data) {
            // redirect to login page if token is invalid
            window.location.href = 'login.html';
        }
    });

}, 10000);

// The setInterval() function will run continuously, sending a GET request to the /messages route every 10 seconds.
// If the token is valid, the messages will be displayed. If the token is invalid, the user will be redirected to the login page.
// This can result in a high number of requests being sent to the server, if there are many users logged in.