// Toggle password visibility safely
const showHiddenPass = (password, eye) => {
    const input = document.getElementById(password);
    const iconEye = document.getElementById(eye);

    if (!input || !iconEye) return; // Prevent errors

    iconEye.addEventListener('click', () => {
        input.type = input.type === 'password' ? 'text' : 'password';
        iconEye.classList.toggle('ri-eye-off-line');
        iconEye.classList.toggle('ri-eye-line');
    });
};

// Call safely for any page
showHiddenPass('loginPass', 'loginEye');
showHiddenPass('signupPass', 'signupEye');
showHiddenPass('confirmPass', 'confirmEye');
showHiddenPass('newPass', 'newPassEye');

// GLOBAL MODAL HANDLING (works on ALL pages)
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