// Safe DOM text assignment alternative

export function renderSafeProfile(container: HTMLElement, userComment: string): void {
    // Safe text assignment avoiding DOM XSS
    container.textContent = userComment;
}
