const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg'); // PostgreSQL
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*', // Substitua pela URL do frontend
    methods: ['GET', 'POST'],
  },
});

const PORT = process.env.PORT || 3000;
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
      console.error('Erro ao verificar token:', err || 'Usuário não é admin');
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
    console.error('Erro ao criar administrador:', err);
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
      console.error('Usuário não encontrado para promoção:', email);
      return res.status(404).json({ error: 'Usuário não encontrado.' });
    }

    await pool.query('UPDATE users SET role = $1 WHERE email = $2', ['admin', email]);
    res.json({ message: `Usuário ${email} foi promovido a administrador.` });
  } catch (err) {
    console.error('Erro ao promover usuário:', err);
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
    console.error('Erro ao cadastrar usuário:', err);
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
      console.error('Email ou senha inválidos:', email);
      return res.status(400).json({ error: 'Email ou senha inválidos.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.error('Senha incorreta para o email:', email);
      return res.status(400).json({ error: 'Email ou senha inválidos.' });
    }

    // Atualiza o status para 'online'
    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['online', socket.user.id]);

    
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      SECRET_KEY,
      { expiresIn: '1h' }
    );

    res.json({ message: 'Login bem-sucedido!', token });
  } catch (err) {
    console.error('Erro ao realizar login:', err);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
x
});

socket.on('disconnect'), async () => {
  if (socket.user.role === 'admin') {
    await pool.query('UPDATE users SET status = $1 WHERE id = $2', ['offline', socket.user.id]);
  }}

// Rota para listar administradores online
app.get('/api/admins-online', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT id, username, email FROM users WHERE role = $1 AND status = $2',
      ['admin', 'online']
    );

    const adminsOnline = result.rows;
    console.log('Administradores online encontrados:', adminsOnline); // Log dos administradores online
    res.json(adminsOnline); // Retorna a lista de administradores online
  } catch (err) {
    console.error('Erro ao buscar administradores online:', err);
    res.status(500).json({ error: 'Erro ao buscar administradores online.' });
  }
});

// Rota para listar a fila de espera do admin
app.get('/api/admin/queue', isAdmin, async (req, res) => {
  const adminId = req.user.id; // ID do admin extraído do token
  const admin = admins[adminId];

  if (!admin) {
    console.error('Administrador não encontrado na fila:', adminId);
    return res.status(404).json({ error: 'Administrador não encontrado.' });
  }

  try {
    const queue = await Promise.all(admin.queue.map(async (clientId) => {
      const result = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [clientId]);
      return result.rows[0];
    }));

    console.log('Fila de espera do admin:', queue); // Log da fila de espera
    res.json(queue);
  } catch (err) {
    console.error('Erro ao carregar fila de espera:', err);
    res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// Notificar administrador sobre a fila
io.to(adminId).emit('updateQueue', admins[adminId].queue);

// Notificar cliente sobre o início do chat
io.to(clientId).emit('startChat', { adminId, timer: admin.timer });

// Middleware para verificar o token JWT no Socket.IO
function authenticateToken(socket, next) {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error('Token não fornecido'));

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) {
      console.error('Token inválido:', err);
      return next(new Error('Token inválido'));
    }
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

  io.on('connection', (socket) => {
    console.log(`Usuário conectado: ${socket.user.id}`);
  
    // Verificar se é um administrador
    if (socket.user.role === 'admin') {
      admins[socket.user.id] = { queue: [], currentClient: null, timer: null };
      console.log(`Administrador conectado: ${socket.user.id}`);
    }
  
    // Quando um administrador se desconecta
    socket.on('disconnect', () => {
      if (socket.user.role === 'admin') {
        delete admins[socket.user.id];
        console.log(`Administrador desconectado: ${socket.user.id}`);
      }
    });
  });

  // Cliente entra na fila
  socket.on('joinQueue', (adminId) => {
    if (!admins[adminId]) {
      console.error('Administrador não encontrado na fila:', adminId);
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
  if (!admin) return;

  const clientId = admin.currentClient;
  if (clientId) {
    io.to(clientId).emit('endChat');
    io.to(adminId).emit('endChat');
  }

  admin.currentClient = null;
  admin.timer = null;

  // Iniciar chat com o próximo cliente na fila
  const nextClient = admin.queue.shift();
  if (nextClient) {
    startChat(adminId, nextClient);
    io.to(adminId).emit('updateQueue', admin.queue);
  }
}

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
`, async (err, res) => {
  if (err) {
    console.error('Erro ao criar tabela:', err);
  } else {
    console.log('Tabela "users" criada com sucesso!');

    // Verificar se a coluna "status" existe e, se não, adicioná-la
    try {
      const columnExistsResult = await pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'users' AND column_name = 'status'
      `);

      if (columnExistsResult.rows.length === 0) {
        await pool.query(`
          ALTER TABLE users ADD COLUMN status VARCHAR(50) DEFAULT 'offline';
        `);
        console.log('Coluna "status" adicionada à tabela "users".');
      } else {
        console.log('Coluna "status" já existe na tabela "users".');
      }
    } catch (err) {
      console.error('Erro ao verificar ou adicionar a coluna "status":', err);
    }
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

// Inicia o servidor
server.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
});