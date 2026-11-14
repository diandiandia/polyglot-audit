// DOM Rendering view (Vulnerable XSS sink)

function renderUserProfile(container, userComment) {
    // Untrusted comment passed directly to innerHTML
    container.innerHTML = userComment;
}
