chrome.runtime.onInstalled.addListener(function () {
    chrome.declarativeContent.onPageChanged.removeRules(undefined, function () {
        chrome.declarativeContent.onPageChanged.addRules([{
            conditions: [new chrome.declarativeContent.PageStateMatcher({
                pageUrl: { schemes: ['https'] },
            })
            ],
            actions: [new chrome.declarativeContent.ShowPageAction()]
        }]);
    });
});



/* Keep track of the active tab in each window */
var activeTabs = {};

chrome.tabs.onActivated.addListener(function (details) {
    activeTabs[details.windowId] = details.tabId;
});

/* Clear the corresponding entry, whenever a window is closed */
chrome.windows.onRemoved.addListener(function (winId) {
    delete (activeTabs[winId]);
});

/* Listen for web-requests and filter them */
chrome.webRequest.onBeforeRequest.addListener(function (details) {
    if (details.tabId == -1) {
        //console.log("Skipping request from non-tabbed context...");
        return;
    }

    var notInteresting = Object.keys(activeTabs).every(function (key) {
        if (activeTabs[key] == details.tabId) {

            /* Environment : We need to store anything from oauth serveurs we can get : 
            - redirect uri from an auth request, mean where we will have auth_code or access_token or id_token
            - an access_token if used in URI (aka implicit flow)
            - same for id_token
            - authorization_code, a temporary session id used in authorization_code flow, then exchanged for an access_token with a POST request
            */
            var redirect_uri = null;
            redirect_uri = window.localStorage.getItem("redirect_uri");
            if (redirect_uri == "null") {
                redirect_uri = null;
            }

            var authorization_code = null;
            authorization_code = window.localStorage.getItem("authorization_code");
            if (authorization_code == "null") {
                authorization_code = null;
            }

            var id_token = null;
            id_token = window.localStorage.getItem("id_token");
            if (id_token == "null") {
                id_token = null;
            }

            var access_token = null;
            access_token = window.localStorage.getItem("access_token");
            if (access_token == "null") {
                access_token = null;
            }

            /*
            check for implicit flow use for access_token
            -- check in authentication URI, if an access_token is required and the redirect_uri where it will be provided
            */
            if (details.url.includes("response_type=id_token") || details.url.includes("response_type=access_token")) {
                var event = new Object();
                event.message = "Implicit flow is used for access_token";
                event.status = "danger"
                event.details = details;
                event.link = "implicit_flow";
                saveEvent(event);
                var url = new URL(details.url);
                if (url.search.includes("redirect_uri")) {
                    // retreive redirect uri
                    redirect_uri = url.searchParams.get("redirect_uri");
                    window.localStorage.setItem("redirect_uri", redirect_uri);
                    var event = new Object();
                    event.message = "We have redirect uri : " + redirect_uri;
                    event.status = "info"
                    event.details = details;
                    event.link = "redirect_uri";
                    saveEvent(event);
                }
            }

            /*
            check for implicit flow use for id_token
            -- check in authentication URI, if an id_token is required and the redirect_uri where it will be provided
            */
            if (details.url.includes("response_type=id_token") || details.url.includes("response_type=id_token")) {
                var event = new Object();
                event.message = "Implicit flow is used for id_token";
                event.status = "danger"
                event.details = details;
                event.link = "implicit_flow";
                saveEvent(event);
                var url = new URL(details.url);
                if (url.search.includes("redirect_uri")) {
                    // retreive redirect uri
                    redirect_uri = url.searchParams.get("redirect_uri");
                    window.localStorage.setItem("redirect_uri", redirect_uri);
                    var event = new Object();
                    event.message = "We have redirect uri : " + redirect_uri;
                    event.status = "info"
                    event.details = details;
                    event.link = "redirect_uri";                    
                    saveEvent(event);
                }
            }

            /*
            Check if an access_token is sent in URI, url encoded mean that it will be sent to an external server
            -- Use case : a webanalytics, get where the user comes from, so it can be a redirect_uri containing tokens
            */
            if (details.url.includes("access_token%3D")) {
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "access_token is exposed in an encoded url";
                    event.status = "danger"
                    event.details = details;
                    event.link = "access_token_exposed";
                    saveEvent(event);
                } else {
                    var event = new Object();
                    event.message = "access_token is exposed in an encoded url and sent to another server";
                    event.status = "dangerplus"
                    event.details = details;
                    event.link = "access_token_exposed";
                    saveEvent(event);
                }

            }

            /*
            Check if an id_token is sent in URI, url encoded mean that it will be sent to an external server
            -- Use case : a webanalytics, get where the user comes from, so it can be a redirect_uri containing tokens
            */
            if (details.url.includes("id_token%3D")) {
                // to another domain, danger, it is a leak
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "id_token is exposed in an encoded url. It means data leak";
                    event.status = "danger"
                    event.details = details;
                    event.link = "id_token_exposed";
                    saveEvent(event);
                } else {
                    var event = new Object();
                    event.message = "id_token is exposed in an encoded url, and sent to another server. It means data leak";
                    event.status = "dangerplus"
                    event.details = details;
                    event.link = "id_token_exposed";
                    saveEvent(event);
                }
            }

            /*
            Check if an access_token is sent in URI, not encoded with url_encode
            */
            if (details.url.includes("access_token=")) {
                // to another domain, danger, it is a leak
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "access_token is in URL as parameter.";
                    event.status = "danger"
                    event.details = details;
                    event.link = "access_token_in_uri";
                    saveEvent(event);
                } else {
                    var event = new Object();
                    event.message = "access_token is in URL as parameter, and sent to another server.";
                    event.status = "dangerplus"
                    event.details = details;
                    event.link = "access_token_exposed";
                    saveEvent(event);
                }
            }

            /*
            Check if an id_token is sent in URI, not encoded with url_encode
            */
            if (details.url.includes("id_token=")) {
                // to another domain, danger, it is a leak
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "id_token is in URL as parameter.";
                    event.status = "warning"
                    event.details = details;
                    event.link = "id_token_in_uri";
                    saveEvent(event);
                } else {
                    var event = new Object();
                    event.message = "id_token is in URL as parameter, and sent to another server.";
                    event.status = "dangerplus"
                    event.details = details;
                    event.link = "id_token_exposed";
                    saveEvent(event);
                }
            }

            /*
            Check if an refresh_token is sent in URI, not encoded with url_encode
            */
            if (details.url.includes("refresh_token=")) {
                // in the same domain, DANGER it is in a URI
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "refresh_token is in URL as parameter.";
                    event.status = "danger"
                    event.details = details;
                    event.link = "refresh_token_exposed";
                    saveEvent(event);

                } else {
                    var event = new Object();
                    event.message = "refresh_token is in URL as parameter, and sent to another server.";
                    event.status = "dangerplus"
                    event.details = details;
                    event.link = "refresh_token_exposed";
                    saveEvent(event);

                }
            }
            /*
            Check if a refresh_token is sent in URI, url encoded mean that it will be sent to an external server
            Use case : a webanalytics, get where the user comes from, so it can be a redirect_uri containing tokens
            */
            if (details.url.includes("refresh_token%3D")) {
                // to another domain, danger, it is a leak
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "refresh_token is exposed in an encoded url.";
                    event.status = "danger"
                    event.details = details;
                    event.link = "refresh_token_exposed";
                    saveEvent(event);
                } else {
                    var event = new Object();
                    event.message = "refresh_token is exposed in an encoded url, and sent to another server";
                    event.status = "dangerplus"
                    event.details = details;
                    event.link = "refresh_token_exposed";
                    saveEvent(event);
                }
            }

            /*
            AUTHORIZATION_CODE FLOW
        
            check for authorization_code flow use
            -- check in authentication URI, if a code is required and the redirect_uri where it will be provided
            */
            if (details.url.includes("response_type=code")) {
                var event = new Object();
                event.message = "authorization_code flow is initialized.";
                event.status = "info"
                event.details = details;
                event.link = "authorization_code_flow";
                saveEvent(event);
                var url = new URL(details.url);
                if (url.search.includes("redirect_uri")) {
                    // retreive redirect uri
                    redirect_uri = url.searchParams.get("redirect_uri");
                    window.localStorage.setItem("redirect_uri", redirect_uri);
                    var event = new Object();
                    event.message = "We have redirect uri : " + redirect_uri;
                    event.status = "info"
                    event.details = details;
                    event.link = "redirect_uri";
                    saveEvent(event);
                }
            }

            /*
            Get redirect URI, to retreive a response code, an id_token or an access_token
            */
            if (redirect_uri != null && details.url.startsWith(redirect_uri)) {
                window.localStorage.removeItem("redirect_uri");
                var event = new Object();
                event.message = "We are from redirect uri : " + redirect_uri;
                event.status = "info"
                event.details = details;
                event.link = "redirect_uri";
                saveEvent(event);
                // get the code from URI
                var url = new URL(details.url);

                authorization_code = url.searchParams.get("code");
                if (authorization_code == null) {
                    authorization_code = new URLSearchParams(url.hash).get("code");
                    if (authorization_code != null) {
                        var event = new Object();
                        event.message = "Got authorization_code " + authorization_code + " in fragment in uri :  " + redirect_uri;
                        event.status = "info"
                        event.details = details;
                        event.link = "redirect_uri";
                        saveEvent(event);
                    }
                } else {
                    var event = new Object();
                    event.message = "Got authorization_code " + authorization_code + " in uri :  " + redirect_uri + " Use it in fragment is better.";
                    event.status = "secondary"
                    event.details = details;
                    event.link = "redirect_uri";
                    saveEvent(event);
                }
                access_token = url.searchParams.get("access_token");
                if (access_token == null) {
                    access_token = new URLSearchParams(url.hash).get("access_token");
                    if (access_token != null) {
                        var event = new Object();
                        event.message = "Got access_token " + access_token + " in fragment in uri :  " + redirect_uri + "Use authorization_code instead.";
                        event.status = "danger"
                        event.details = details;
                        event.link = "implicit_flow";
                        saveEvent(event);
                    }
                } else {
                    var event = new Object();
                    event.message = "Got access_token " + access_token + " in uri :  " + redirect_uri + "Use authorization_code instead.";
                    event.status = "danger"
                    event.details = details;
                    event.link = "implicit_flow";
                    saveEvent(event);
                }
                id_token = url.searchParams.get("id_token");
                if (id_token == null) {
                    id_token = new URLSearchParams(url.hash).get("id_token");
                    if (id_token != null) {
                        var event = new Object();
                        event.message = "Got id_token " + id_token + " in fragment in uri :  " + redirect_uri + "Use authorization_code instead.";
                        event.status = "danger"
                        event.details = details;
                        event.link = "implicit_flow";
                        saveEvent(event);
                    }
                } else {
                    var event = new Object();
                    event.message = "Got id_token " + id_token + " in uri :  " + redirect_uri + "Use authorization_code instead.";
                    event.status = "danger"
                    event.details = details;
                    event.link = "implicit_flow";
                    saveEvent(event);
                }

                window.localStorage.setItem("authorization_code", authorization_code);
                window.localStorage.setItem("access_token", access_token);
                window.localStorage.setItem("id_token", id_token);
            }

            /*
            With authorization_code flow, an authorization_code is exchanged for a token with a POST to "/token" on auth server.
            An access_token/refresh_token is returned as response.
            This is the critical part of authorization_code flow. An authorization_code can be used only once, to retreive a session.
            It mean that the authorization_code has to be protected between redirect_uri and this call
            */
            if (authorization_code != null && details.method == "POST" && details.url.includes("/token")) {
                var event = new Object();
                event.message = "authorization_code " + authorization_code + " is exchanged for a token. " +
                    window.localStorage.getItem("callsBeforeToken") + "calls BEFORE this operation. Check external calls and referer header.";
                event.status = "info"
                event.details = details;
                event.link = "authorization_code_exchanged";
                saveEvent(event);
                window.localStorage.removeItem("authorization_code");
                window.localStorage.removeItem(callsBeforeToken);
            }

            /*
            Check number an kind of calls between redirect_uri and /token POST request to retreive an access_token. Each call is potentially 
            a security issue if the authorization_code is used by another app.
            */
            var callsBeforeToken = 0;
            callsBeforeToken = parseInt(window.localStorage.getItem("callsBeforeToken"));
            if (isNaN(callsBeforeToken)) {
                callsBeforeToken = 0;
            }
            if (authorization_code != null && details.method == "GET" && !details.url.includes(redirect_uri)) {
                callsBeforeToken++;
                window.localStorage.setItem("callsBeforeToken", callsBeforeToken);
                if (checkSameOrigin(details)) {
                    var event = new Object();
                    event.message = "GET request before getting an access_token, with a valid authorization_code.";
                    event.status = "secondary"
                    event.details = details;
                    event.link = "get_before_authorization_code_exchanged";
                    saveEvent(event);
                } else {
                    var event = new Object();
                    event.message = "GET request before getting an access_token, from another server with a valid authorization_code. Check referer header to avoid any leak.";
                    event.status = "secondary"
                    event.details = details;
                    event.link = "get_before_authorization_code_exchanged";
                    saveEvent(event);
                }
                if (details.url.includes(authorization_code)) {
                    /*
                    Worst case, a call is made with the authorization_code directly in URL
                    */
                    if (checkSameOrigin(details)) {
                        var event = new Object();
                        event.message = "GET request before getting an access_token, with a valid authorization_code " + authorization_code + " sent in URI.";
                        event.status = "danger"
                        event.details = details;
                        event.link = "authorization_code_exposed";
                        saveEvent(event);
                    } else {
                        var event = new Object();
                        event.message = "GET request before getting an access_token, with a valid authorization_code " + authorization_code + " sent in URI to an external server.";
                        event.status = "dangerplus"
                        event.details = details;
                        event.link = "authorization_code_exposed";
                        saveEvent(event);
                    }
                }
            }

            return false;
        } else {
            return true;
        }
    });
    
}, { urls: ["<all_urls>"] });

/* Get the active tabs in all currently open windows */
chrome.tabs.query({ active: true }, function (tabs) {
    tabs.forEach(function (tab) {
        activeTabs[tab.windowId] = tab.id;
    });
    console.log("activeTabs = ", activeTabs);
});

function saveEvent(event) {
    var entryId = Math.floor(Math.random() * 10000000)

    var details = " <p> \
                        <a data-toggle=\"collapse\" href=\"#entry" + entryId + "\" role=\"button\" aria-expanded=\"false\" \
                            aria-controls=\"entry" + entryId + "\">Details</a> | <a target=\"_blank\" href=\"https://github.com/please-openit/token-leak-extension/wiki/"+event.link+"\">More ...</a>\
                    </p> \
                    <div class=\"row\">\
                        <div class=\"col\">\
                            <div class=\"collapse multi-collapse\" id=\"entry" + entryId + "\">\
                                <div class=\"card card-body\">\
                                    <table class=\"table\">\
                                        <tr>\
                                            <td>initiator</td>\
                                            <td>" + event.details.initiator + "</td>\
                                        </tr>\
                                        <tr>\
                                            <td>Method</td>\
                                            <td>" + event.details.method + "</td>\
                                        </tr>\
                                        <tr>\
                                            <td>URL</td>\
                                            <td>" + event.details.url + "</td>\
                                        </tr>\
                                    </table>\
                                </div>\
                            </div>\
                        </div>\
                    </div>";

    var htmlOutput = window.localStorage.getItem("htmlOutput");
    if (htmlOutput == null) {
        htmlOutput = "";
    }

    htmlOutput += "<div class='alert alert-" + event.status + "'>" + event.message + details + "</div>";
    window.localStorage.setItem("htmlOutput", htmlOutput);
    chrome.storage.local.set({ html: htmlOutput }, function () {
        console.log('html is saved');
    });
}

function checkSameOrigin(details) {
    var from = new URL(details.initiator);
    var fromServer = from.origin.replace("https://", "");
    fromServer = fromServer.replace("www.", "");

    var to = new URL(details.url);
    var toServer = to.origin.replace("https://", "");
    toServer = toServer.replace("www.", "");

    return toServer.includes(fromServer);
}

chrome.runtime.onMessage.addListener(
    function (request, sender, sendResponse) {
        if (request.cleanup == "all")
            window.localStorage.removeItem("htmlOutput");
        sendResponse({ farewell: "ok" });
    });

