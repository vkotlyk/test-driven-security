document.querySelector(".js-form").addEventListener("submit", function register(e) {
    e.preventDefault();
    fetch("/register", {
        method: "POST",
        headers: {
            "Accept": "application/json",
            "Content-Type": "application/json"
        },
        body: JSON.stringify({
            username: document.querySelector(".username").value,
            password: document.querySelector(".password").value
        })
    }).then(res => res.json()).then(json => document.querySelector(".registration-status").innerHTML = typeof json === "string" ? json : json.error);
});