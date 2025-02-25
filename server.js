const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const app = express();
const PORT = process.env.PORT || 3000; // Usa a porta fornecida pelo Render ou 3000 localmente
const SECRET_KEY = process.env.SECRET_KEY || 'sua_chave_secreta_aqui';
const http = require('http');
const { Server } = require('socket.io');


const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: 'https://tarot-zsst.onrender.com', // Substitua pela URL do frontend
    methods: ['GET', 'POST'],
  },
});

const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'sua_chave_secreta_aqui';

// Middleware para verificar o token JWT
function authenticateToken(socket, next) {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token não fornecido'));

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return next(new Error('Token inválido'));
    socket.user = user; // Armazena o usuário no objeto socket
    next();
  });
}

// Gerenciar administradores e filas
const admins = {}; // { adminId: { queue: [], currentClient: null, timer: null } }
const clients = {}; // { clientId: adminId }

// Configurar Socket.IO
io.use(authenticateToken);

io.on('connection', (socket) => {
  console.log(`Usuário conectado: ${socket.user.id}`);

  // Verificar se é um administrador
  if (socket.user.role === 'admin') {
    admins[socket.user.id] = { queue: [], currentClient: null, timer: null };
    console.log(`Administrador conectado: ${socket.user.id}`);
  }

  // Cliente entra na fila
  socket.on('joinQueue', (adminId) => {
    if (!admins[adminId]) {
      return socket.emit('error', 'Administrador não encontrado');
    }

    // Adicionar cliente à fila do administrador
    admins[adminId].queue.push(socket.user.id);
    clients[socket.user.id] = adminId;
    console.log(`Cliente ${socket.user.id} entrou na fila do admin ${adminId}`);

    // Notificar administrador sobre a fila
    io.to(adminId).emit('updateQueue', admins[adminId].queue);

    // Se não houver cliente ativo, iniciar o chat imediatamente
    if (!admins[adminId].currentClient) {
      startChat(adminId, socket.user.id);
    }
  });

  // Enviar mensagem
  socket.on('sendMessage', ({ to, message }) => {
    io.to(to).emit('receiveMessage', { from: socket.user.id, message });
  });

  // Desconectar
  socket.on('disconnect', () => {
    console.log(`Usuário desconectado: ${socket.user.id}`);

    // Remover cliente da fila ou encerrar sessão
    if (socket.user.role !== 'admin') {
      const adminId = clients[socket.user.id];
      if (adminId) {
        const admin = admins[adminId];
        if (admin.currentClient === socket.user.id) {
          endChat(adminId);
        } else {
          admin.queue = admin.queue.filter((clientId) => clientId !== socket.user.id);
          io.to(adminId).emit('updateQueue', admin.queue);
        }
        delete clients[socket.user.id];
      }
    } else {
      endChat(socket.user.id);
    }
  });
});

// Função para iniciar o chat
function startChat(adminId, clientId) {
  const admin = admins[adminId];
  admin.currentClient = clientId;
  admin.timer = 30 * 60; // 30 minutos em segundos

  // Notificar cliente e administrador
  io.to(clientId).emit('startChat', { adminId, timer: admin.timer });
  io.to(adminId).emit('startChat', { clientId, timer: admin.timer });

  // Iniciar contador
  const interval = setInterval(() => {
    admin.timer--;
    io.to(adminId).emit('updateTimer', admin.timer);
    io.to(clientId).emit('updateTimer', admin.timer);

    if (admin.timer <= 0) {
      clearInterval(interval);
      endChat(adminId);
    }
  }, 1000);
}

// Função para encerrar o chat
function endChat(adminId) {
  const admin = admins[adminId];
  if (admin.currentClient) {
    io.to(admin.currentClient).emit('endChat');
    io.to(adminId).emit('endChat');
    admin.currentClient = null;

    // Iniciar próximo cliente na fila
    if (admin.queue.length > 0) {
      const nextClient = admin.queue.shift();
      startChat(adminId, nextClient);
      io.to(adminId).emit('updateQueue', admin.queue);
    }
  }
}

// Iniciar servidor
server.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});
// Configuração do CORS
app.use(cors({
  origin: process.env.FRONTEND_URL || '*', // Substitua pelo domínio do frontend
}));

// Middleware
app.use(bodyParser.json());

// Configuração do PostgreSQL
const { Pool } = require('pg');

const pool = new Pool({
  user: 'login_p7n8_user', // Usuário do banco de dados
  host: 'dpg-cutqkfd2ng1s73dd5ui0-a', // Host fornecido pelo Render
  database: 'login_p7n8', // Nome do banco de dados
  password: 'uhF5GKbxzXYyS0jtx9PDj4lIcRpnKk00', // Senha do banco de dados
  port: 5432, // Porta (como número, não string)
  ssl: {
    rejectUnauthorized: false, // Necessário para conexões SSL no Render
  },
});

// Garantir que a tabela "users" exista ao iniciar o servidor
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) DEFAULT 'user'
  )
`, (err, res) => {
  if (err) {
    console.error('Erro ao criar tabela:', err);
  } else {
    console.log('Tabela "users" criada com sucesso!');
  }
});

// Rota de Cadastro
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    await pool.query(
      'INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
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

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ message: 'Login bem-sucedido!', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// Rota Protegida (Admin)
app.get('/api/admin', (req, res) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Token não fornecido.' });

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Acesso negado.' });
    }
    res.json({ message: 'Bem-vindo ao painel de administração!' });
  });
});

// Inicia o servidor
app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});