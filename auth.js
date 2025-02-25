// auth.js
function isAuthenticated() {
  const token = localStorage.getItem('token');
  if (!token) {
    alert('Você precisa estar logado para acessar esta página.');
    window.location.href = 'login.html';
    return false;
  }
  return true;
}

function logout() {
  localStorage.removeItem('token');
  window.location.href = 'login.html';
}