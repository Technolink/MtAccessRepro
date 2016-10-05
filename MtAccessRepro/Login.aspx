<%@ Page Language="C#"
    AutoEventWireup="true"
    CodeBehind="Login.aspx.cs"
    Async="true"
    AsyncTimeOut="10000"
    Inherits="MtAccessRepro.Login" %>

<!DOCTYPE html>

<html xmlns="http://www.w3.org/1999/xhtml">
<head runat="server">
    <title>Azure Logon Test</title>
    <script src="https://code.jquery.com/jquery-3.1.0.min.js" integrity="sha256-cCueBR6CsyA4/9szpPfrX3s49M9vUU5BgtiJj06wt/s=" crossorigin="anonymous"></script>
    <script type="text/javascript">
        function getUrlVar(key) {
            var result = new RegExp(key + "=([^&]*)", "i").exec(window.location.search);
            return result && unescape(result[1]) || "";
        }

        function login() {
            var API = "https://login.microsoftonline.com/common/OAuth2/Authorize";
            var queryParams = {
                'client_id': document.getElementById("ClientIdLabel").innerText,
                'response_mode': 'query',
                'response_type': 'code',
                'redirect_uri': window.location.href,
                'prompt': 'consent'
            };
            var encodedParams = $.param(queryParams);
            window.location.href = API + "?" + encodedParams;
        }

        function displayElements(loggedIn) {
            document.getElementById("login").hidden = loggedIn;
            document.getElementById("logout").hidden = !loggedIn;
            document.getElementById("authenticatedDiv").hidden = !loggedIn;
        }

        var authCodeSessionStorageKey = 'AzureADAuthCode';

        function loadElements() {
            var code = getUrlVar('code');
            if (code) {
                window.sessionStorage.setItem(authCodeSessionStorageKey, code);
                //document.location = document.location.toString().split('?')[0];
            } else {
                code = window.sessionStorage.getItem(authCodeSessionStorageKey);
            }

            if (code) {
                document.getElementById("Code").value = code;
                displayElements(true);
            } else {
                displayElements(false);
            }
        }

        function logout() {
            window.sessionStorage.removeItem(authCodeSessionStorageKey);
            displayElements(false);
        }
    </script>
</head>
<body onload="loadElements()">
    ClientId:
    <label id="ClientIdLabel" runat="server"></label>
    <br/>
    <input id="login" type="button" onclick="login()" value="Login"/>
    <input id="logout" type="button" onclick="logout()" value="Logout"/>
    <br/>
    <div id="authenticatedDiv">
        Code:
        <input id="Code" type="text" readonly style="width: 100%;" runat="server"/>
        <form id="subscriptionForm" runat="server">
            Subscriptions:
            <select id="SubscriptionsElement" runat="server">
                <option>Select a subscription to link</option>
            </select>
            <br/>
            <input id="LinkButton" type="button" value="Link a subscription" OnServerClick="LinkButton_OnServerClick" runat="server"/>
            <br/>
            New role definition ID:
            <label id="DefinitionId" runat="server"></label>
            <br/>
            Subscription Name (fetched by app token):
            <label id="SubscriptionName" runat="server"></label>
        </form>
    </div>
</body>
</html>
