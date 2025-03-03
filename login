<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
</head>
<body>
  <h1>Login</h1>
  <form id="loginForm">
    <label for="email">E-mail:</label>
    <input type="email" id="email" name="email" required><br>
    <label for="password">Senha:</label>
    <input type="password" id="password" name="password" required><br>
    <button type="submit">Entrar</button>
  </form>

  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const email = document.getElementById('email').value;
      const password = document.getElementById('password').value;

      const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      const data = await response.json();
      if (data.success) {
        if (data.role === 'admin') window.location.href = '/admin-dashboard.html';
        else if (data.role === 'consultant') window.location.href = '/consultas.html?role=consultant';
        else window.location.href = '/consultas.html?role=user';
      } else {
        alert(data.message);
      }
    });
  </script>
</body>
</html>