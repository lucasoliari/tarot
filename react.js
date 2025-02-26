import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [token, setToken] = useState(null);
  const [permissao, setPermissao] = useState(null);

  const handleLogin = async () => {
    try {
      const response = await axios.post('http://localhost:10000/login', { email, password });
      const { token, permissao } = response.data;
      setToken(token);
      setPermissao(permissao);

      if (permissao === 'master') {
        window.location.href = '/admin';
      } else {
        window.location.href = '/consultas';
      }
    } catch (error) {
      alert('Credenciais inválidas');
    }
  };

  return (
    <div>
      <h1>Login</h1>
      <input type="email" placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="password" placeholder="Senha" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button onClick={handleLogin}>Entrar</button>
    </div>
  );
}

export default App;