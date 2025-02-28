const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt'); // Para criptografia de senhas
const { Client } = require('pg'); // Driver do PostgreSQL

// Configuração do servidor
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware para processar JSON
app.use(express.json());

// Configuração do banco de dados (PostgreSQL)
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'tarot_online',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'senha_do_banco',
};

const client = new Client(dbConfig);

// Conectar ao banco de dados
client.connect()
  .then(async () => {
    console.log('Conectado ao banco de dados');

    // Criar tabelas se não existirem
    await createTables();
    console.log('Tabelas verificadas/criadas com sucesso');
  })
  .catch(err => console.error('Erro ao conectar ao banco de dados:', err));

// Função para criar tabelas
async function createTables() {
  try {
    // Tabela de Usuários
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        nickname VARCHAR(255) NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'user'
      )
    `);

    // Tabela de Consultores
    await client.query(`
      CREATE TABLE IF NOT EXISTS consultants (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        status VARCHAR(50) DEFAULT 'offline',
        total_time_logged INTEGER DEFAULT 0,
        total_clients_served INTEGER DEFAULT 0
      )
    `);

    // Tabela de Sessões de Chat
    await client.query(`
      CREATE TABLE IF NOT EXISTS chat_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        consultant_id INTEGER REFERENCES consultants(id),
        duration INTEGER NOT NULL,
        start_time TIMESTAMP,
        end_time TIMESTAMP
      )
    `);

    // Tabela de Mensagens de Chat
    await client.query(`
      CREATE TABLE IF NOT EXISTS chat_messages (
        id SERIAL PRIMARY KEY,
        session_id INTEGER REFERENCES chat_sessions(id),
        sender_id INTEGER REFERENCES users(id),
        message TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  } catch (error) {
    console.error('Erro ao criar tabelas:', error);
  }
}

// Rota de Cadastro
app.post('/api/register', async (req, res) => {
  const { nickname, email, password } = req.body;

  try {
    // Verificar se o e-mail já está cadastrado
    const checkEmailQuery = 'SELECT * FROM users WHERE email = $1';
    const existingUser = await client.query(checkEmailQuery, [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'E-mail já cadastrado' });
    }

    // Criptografar a senha
    const hashedPassword = await bcrypt.hash(password, 10);

    // Inserir novo usuário no banco de dados
    const insertUserQuery = `
      INSERT INTO users (nickname, email, password, role)
      VALUES ($1, $2, $3, $4)
    `;
    await client.query(insertUserQuery, [nickname, email, hashedPassword, 'user']);

    res.json({ success: true, message: 'Usuário registrado com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao registrar usuário' });
  }
});

// Rota de Login
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    // Encontrar o usuário pelo e-mail
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await client.query(query, [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
    }

    // Verificar a senha
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Credenciais inválidas' });
    }

    res.json({ success: true, role: user.role });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao fazer login' });
  }
});

// Rota para listar todos os usuários (somente admin)
app.get('/api/users', async (req, res) => {
  try {
    const query = 'SELECT id, nickname, email, role FROM users';
    const result = await client.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao listar usuários' });
  }
});

// Socket.IO para chat em tempo real
io.on('connection', (socket) => {
  console.log('Novo cliente conectado:', socket.id);

  // Evento para notificar consultor
  socket.on('request_chat', (data) => {
    io.emit('notify_consultant', data);
  });

  // Evento para enviar mensagens
  socket.on('send_message', (data) => {
    io.emit('receive_message', data);
  });

  socket.on('disconnect', () => {
    console.log('Cliente desconectado:', socket.id);
  });
});

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});