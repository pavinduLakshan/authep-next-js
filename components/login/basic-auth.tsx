const isBackChannelBasicAuth = false;

const samlssoURL = "../samlsso";
const commonauthURL = "https://localhost:9443/commonauth";

export const BasicAuth = () => {

    const params = new URLSearchParams(global?.window && window.location.search);

    const getLoginFormActionUrl = () => {
        const queryString = global?.window && window.location.search;
        const urlParams = new URLSearchParams(queryString);

        let loginFormActionURL = "";
    
        if (isBackChannelBasicAuth) {
            loginFormActionURL = "authenticate.do";
            
            const queryString = global?.window && window.location.search;

            if (queryString != "" || queryString) {
                loginFormActionURL = loginFormActionURL + "?" + queryString?.substring(1);
            }
        } else {
            const type: string | null = urlParams.get("type");
            if (type === "samlsso") {
                loginFormActionURL = samlssoURL;
            } else {
                loginFormActionURL = commonauthURL;
            }
        }

        return loginFormActionURL;
    }

    return (
        <form action={getLoginFormActionUrl()} method="post" id="loginForm">
            <label>Username</label>
            <input type="text" name="username" placeholder="Username" />
            <label>Password</label>
            <input type="password" name="password" placeholder="Password" />
            <input type="text" name="sessionDataKey" value={params.get("sessionDataKey") || undefined} hidden />
            <input type="submit" />
            <input id="tocommonauth" name="tocommonauth" type="hidden" value="true" />
        </form>
    )
}
