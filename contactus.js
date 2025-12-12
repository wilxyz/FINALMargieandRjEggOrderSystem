const navToggle = document.getElementById('nav-toggle');
const navMenu = document.getElementById('nav-menu');

navToggle.addEventListener('click', () => {
    navMenu.classList.toggle('active');
});

document.addEventListener('click', (e) => {
    if (!navMenu.contains(e.target) && !navToggle.contains(e.target)) {
        navMenu.classList.remove('active');
    }
});

window.addEventListener('DOMContentLoaded', () => {
    const urlParams = new URLSearchParams(window.location.search);
    const message = urlParams.get('msg');

    if (message) {
        const modal = document.getElementById('modal');
        const modalMessage = document.getElementById('modal-message');
        const modalClose = document.getElementById('modal-close');

        if (!modal) return; // In case some pages don't have modal

        modalMessage.textContent = message;
        modal.style.display = 'block';

        modalClose.addEventListener('click', () => {
            modal.style.display = 'none';
            window.history.replaceState({}, document.title, window.location.pathname);
        });
    }
});