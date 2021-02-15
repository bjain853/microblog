let api = (function(){
    "use strict";
    
    function send(method, url, data, callback){
        let xhr = new XMLHttpRequest();
        xhr.onload = function() {
            if (xhr.status !== 200) callback("[" + xhr.status + "]" + xhr.responseText, null);
            else callback(null, JSON.parse(xhr.responseText));
        };
        xhr.open(method, url, true);
        if (!data) xhr.send();
        else{
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.send(JSON.stringify(data));
        }
    }
    
    let module = {};
    
    let errorListeners = [];
    
    function notifyErrorListeners(err){
        errorListeners.forEach(function(listener){
            listener(err);
        });
    }
    
    module.onError = function(listener){
        errorListeners.push(listener);
    };
    
    let userListeners = [];
    
    let getUsername = function(){
        return document.cookie.replace(/(?:(?:^|.*;\s*)username\s*\=\s*([^;]*).*$)|^.*$/, "$1");
    }
    
    function notifyUserListeners(username){
        userListeners.forEach(function(listener){
            listener(username);
        });
    };
    
    module.onUserUpdate = function(listener){
        userListeners.push(listener);
        listener(getUsername());
    }
    
    module.signin = function(username, password){
        send("POST", "/signin/", {username, password}, function(err, res){
             if (err) return notifyErrorListeners(err);
             notifyUserListeners(getUsername());
        });
    }
    
    module.signup = function(username, password){
        send("POST", "/signup/", {username, password}, function(err, res){
             if (err) return notifyErrorListeners(err);
             notifyUserListeners(getUsername());
        });
    }

    let getMessages = function(page, callback){
        send("GET", "/api/messages/?page=" + page, null, callback);
    }
    
    let messageListeners = [];
    
    function notifyMessageListeners(){
        getMessages(0, function(err, messages){
            if (err) return notifyErrorListeners(err);
            messageListeners.forEach(function(listener){
                listener(messages);
            });
        });
    }
    
    module.onMessageUpdate = function(listener){
        messageListeners.push(listener);
        getMessages(0, function(err, messages){
            if (err) return notifyErrorListeners(err);
            listener(messages);
        });
    }
    
    
    module.addMessage = function(content){
        send("POST", "/api/messages/", {content: content}, function(err, res){
             if (err) return notifyErrorListeners(err);
             notifyMessageListeners();
        });
    }
    
    module.deleteMessage = function(messageId){
        send("DELETE", "/api/messages/" + messageId + "/", null, function(err, res){
             if (err) return notifyErrorListeners(err);
             notifyMessageListeners();
        });
    }
    
    let voteListeners = [];
    
    function notifyVoteListeners(message){
        voteListeners.forEach(function(listener){
            listener(message);
        });
    }
    
    module.onVoteUpdate = function(listener){
        voteListeners.push(listener);
    }
    
    module.upvoteMessage = function(messageId){
        send("PATCH", "/api/messages/" + messageId + "/", {action: 'upvote'}, function(err, res){
             if (err) return notifyErrorListeners(err);
             notifyVoteListeners(res);
        });
    }
    
    module.downvoteMessage = function(messageId){
        send("PATCH", "/api/messages/" + messageId + "/", {action: 'downvote'}, function(err, res){
             if (err) return notifyErrorListeners(err);
             notifyVoteListeners(res);
        });
    }
    
    // (function refresh(){
    //     setTimeout(function(e){
    //         notifyMessageListeners();
    //         refresh();
    //     }, 2000);
    // }());
    
    return module;
})();