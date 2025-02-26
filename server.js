const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg'); // PostgreSQL
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || 'sua_chave_secreta_aqui';

// Configuração do CORS
app.use(cors({ origin: '*' }));
app.use(bodyParser.json());

// Configuração do PostgreSQL
const pool = new Pool({
  user: 'login_p7n8_user',
  host: 'dpg-cutqkfd2ng1s73dd5ui0-a',
  database: 'login_p7n8',
  password: 'uhF5GKbxzXYyS0jtx9PDj4lIcRpnKk00',
  port: 5432,
  ssl: {
    rejectUnauthorized: false, // Necessário para conexões SSL no Render
  },
});

// Middleware para verificar se o usuário é admin
function isAdmin(req, res, next) {
  const token = req.headers.authorization;
  if (!token) return res.status(401).json({ error: 'Token não fornecido.' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Acesso negado.' });
    }
    req.user = decoded; // Armazena os dados do usuário no objeto `req`
    next();
  });
}

// Rota para criar um novo administrador
app.post('/api/admin/create', isAdmin, async (req, res) => {
  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Todos os campos são obrigatórios.' });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)',
      [username, email, hashedPassword, 'admin']
    );
    res.json({ message: 'Administrador criado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao criar administrador.' });
  }
});

// Rota para promover um usuário a administrador
app.post('/api/admin/promote', isAdmin, async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ error: 'O campo "email" é obrigatório.' });
  }

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    await pool.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', email]);
    res.json({ message: `Usuário ${email} foi promovido a administrador.` });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao promover usuário.' });
  }
});

// Rota de Cadastro
app.post('/api/signup', async (req, res) => {
  const { username, email, password, role = 'user' } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)',
      [username, email, hashedPassword, role]
    );
    res.json({ message: 'Usuário cadastrado com sucesso!' });
  } catch (err) {
    console.error(err);
    res.status(400).json({ error: 'Erro ao cadastrar usuário.' });
  }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Email ou senha inválidos.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Email ou senha inválidos.' });
    }

    // Atualiza o status para 'online'
    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['online', user.id]);

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login bem-sucedido!', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// Rota para listar administradores online
app.get('/api/admins-online', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email FROM users WHERE role = $1 AND status = $2',
      ['admin', 'online']
    );

    const adminsOnline = result.rows;
    res.json(adminsOnline); // Retorna a lista de administradores online
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro ao buscar administradores online.' });
  }
});

// Função para criar um administrador inicial
async function createInitialAdmin() {
  try {
    const result = await pool.query('SELECT * FROM users WHERE role = $1', ['admin']);
    if (result.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.query(
        'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)',
        ['AdminInicial', 'admin@example.com', hashedPassword, 'admin']
      );
      console.log('Administrador inicial criado com sucesso!');
    } else {
      console.log('Administrador já existe no banco de dados.');
    }
  } catch (err) {
    console.error('Erro ao criar administrador inicial:', err);
  }
}

// Chamar a função ao iniciar o servidor
createInitialAdmin();

// Garantir que a tabela "users" exista ao iniciar o servidor
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user',
    status VARCHAR(50) DEFAULT 'offline'
  )
`, (err, res) => {
  if (err) {
    console.error('Erro ao criar tabela:', err);
  } else {
    console.log('Tabela "users" criada com sucesso!');
  }
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});