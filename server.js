const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const bcrypt = require('bcrypt');
const { Client } = require('pg');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const { body, validationResult } = require('express-validator');
const cors = require('cors');

// Carregar variáveis de ambiente
dotenv.config();

// Configuração do servidor
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(express.json());
app.use(cors());

// Configuração do PostgreSQL
const pool = new Pool({
  user: 'login_p7n8_user',
  host: 'dpg-cutqkfd2ng1s73dd5ui0-a',
  database:'login_p7n8',
  password:'uhF5GKbxzXYyS0jtx9PDj4lIcRpnKk00',
  port: 5432,
  ssl: {
    rejectUnauthorized: false, // Necessário para conexões SSL no Render
  },
});

const client = new Client(dbConfig);

// Secret para JWT
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

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
        role VARCHAR(50) DEFAULT 'user',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de Consultores
    await client.query(`
      CREATE TABLE IF NOT EXISTS consultants (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        bio TEXT,
        specialties TEXT[],
        hourly_rate DECIMAL(10,2),
        status VARCHAR(50) DEFAULT 'offline',
        rating DECIMAL(3,2) DEFAULT 0,
        total_time_logged INTEGER DEFAULT 0,
        total_clients_served INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Tabela de Sessões de Chat
    await client.query(`
      CREATE TABLE IF NOT EXISTS chat_sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        consultant_id INTEGER REFERENCES consultants(id),
        status VARCHAR(50) DEFAULT 'waiting',
        duration INTEGER DEFAULT 0,
        start_time TIMESTAMP,
        end_time TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    // Tabela de Avaliações
    await client.query(`
      CREATE TABLE IF NOT EXISTS ratings (
        id SERIAL PRIMARY KEY,
        session_id INTEGER REFERENCES chat_sessions(id),
        user_id INTEGER REFERENCES users(id),
        consultant_id INTEGER REFERENCES consultants(id),
        rating INTEGER NOT NULL CHECK (rating BETWEEN 1 AND 5),
        comment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);
  } catch (error) {
    console.error('Erro ao criar tabelas:', error);
  }
}

// Middleware para verificar autenticação
const authenticateJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(' ')[1];

    jwt.verify(token, JWT_SECRET, (err, user) => {
      if (err) {
        return res.status(403).json({ success: false, message: 'Token inválido ou expirado' });
      }

      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ success: false, message: 'Token de autenticação não fornecido' });
  }
};

// Middleware para verificar se é admin
const isAdmin = (req, res, next) => {
  if (req.user && req.user.role === 'admin') {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Acesso negado: permissões de administrador necessárias' });
  }
};

// Middleware para verificar se é consultor
const isConsultant = (req, res, next) => {
  if (req.user && (req.user.role === 'consultant' || req.user.role === 'admin')) {
    next();
  } else {
    res.status(403).json({ success: false, message: 'Acesso negado: permissões de consultor necessárias' });
  }
};

// Validações para registro
const registerValidation = [
  body('nickname').notEmpty().withMessage('O apelido é obrigatório'),
  body('email').isEmail().withMessage('E-mail inválido'),
  body('password').isLength({ min: 6 }).withMessage('A senha deve ter pelo menos 6 caracteres')
];

// Rota de Cadastro
app.post('/api/register', registerValidation, async (req, res) => {
  // Verificar erros de validação
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }

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
      RETURNING id, nickname, email, role
    `;
    const newUser = await client.query(insertUserQuery, [nickname, email, hashedPassword, 'user']);
    
    // Gerar token JWT
    const token = jwt.sign(
      { id: newUser.rows[0].id, email: newUser.rows[0].email, role: newUser.rows[0].role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      message: 'Usuário registrado com sucesso!',
      user: {
        id: newUser.rows[0].id,
        nickname: newUser.rows[0].nickname,
        email: newUser.rows[0].email,
        role: newUser.rows[0].role
      },
      token
    });
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

    // Verificar se é consultor
    let consultantInfo = null;
    if (user.role === 'consultant') {
      const consultantQuery = 'SELECT * FROM consultants WHERE user_id = $1';
      const consultantResult = await client.query(consultantQuery, [user.id]);
      consultantInfo = consultantResult.rows[0];
    }

    // Gerar token JWT
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.json({ 
      success: true, 
      user: {
        id: user.id,
        nickname: user.nickname,
        email: user.email,
        role: user.role
      },
      consultant: consultantInfo,
      token
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao fazer login' });
  }
});

// Verificar token (para cliente verificar se o token ainda é válido)
app.get('/api/verify-token', authenticateJWT, (req, res) => {
  res.json({ success: true, user: req.user });
});

// Rota para listar todos os usuários (somente admin)
app.get('/api/users', authenticateJWT, isAdmin, async (req, res) => {
  try {
    const query = 'SELECT id, nickname, email, role, created_at FROM users ORDER BY created_at DESC';
    const result = await client.query(query);
    res.json({ success: true, users: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao listar usuários' });
  }
});

// Rota para atualizar perfil do usuário
app.put('/api/users/profile', authenticateJWT, async (req, res) => {
  const { nickname, email } = req.body;
  const userId = req.user.id;

  try {
    // Verificar se o e-mail já está em uso por outro usuário
    if (email) {
      const checkEmailQuery = 'SELECT * FROM users WHERE email = $1 AND id != $2';
      const existingUser = await client.query(checkEmailQuery, [email, userId]);
      if (existingUser.rows.length > 0) {
        return res.status(400).json({ success: false, message: 'E-mail já está em uso' });
      }
    }

    // Construir a consulta dinamicamente baseada nos campos fornecidos
    let updateQuery = 'UPDATE users SET ';
    const updateValues = [];
    const updateFields = [];
    
    if (nickname) {
      updateFields.push(`nickname = $${updateValues.length + 1}`);
      updateValues.push(nickname);
    }
    
    if (email) {
      updateFields.push(`email = $${updateValues.length + 1}`);
      updateValues.push(email);
    }
    
    // Se nenhum campo foi fornecido
    if (updateFields.length === 0) {
      return res.status(400).json({ success: false, message: 'Nenhum campo para atualizar fornecido' });
    }
    
    updateQuery += updateFields.join(', ');
    updateQuery += ` WHERE id = $${updateValues.length + 1} RETURNING id, nickname, email, role`;
    updateValues.push(userId);
    
    const result = await client.query(updateQuery, updateValues);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }
    
    res.json({ success: true, user: result.rows[0], message: 'Perfil atualizado com sucesso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao atualizar perfil' });
  }
});

// Rota para alterar senha
app.put('/api/users/password', authenticateJWT, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const userId = req.user.id;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ success: false, message: 'Senha atual e nova senha são obrigatórias' });
  }

  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, message: 'A nova senha deve ter pelo menos 6 caracteres' });
  }

  try {
    // Obter a senha atual do usuário
    const userQuery = 'SELECT password FROM users WHERE id = $1';
    const userResult = await client.query(userQuery, [userId]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }
    
    // Verificar se a senha atual está correta
    const isPasswordValid = await bcrypt.compare(currentPassword, userResult.rows[0].password);
    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Senha atual incorreta' });
    }
    
    // Criptografar a nova senha
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    
    // Atualizar a senha
    await client.query('UPDATE users SET password = $1 WHERE id = $2', [hashedPassword, userId]);
    
    res.json({ success: true, message: 'Senha alterada com sucesso' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao alterar senha' });
  }
});

// Rota para tornar um usuário consultor
app.post('/api/consultants', authenticateJWT, isAdmin, async (req, res) => {
  const { userId, specialties, hourlyRate, bio } = req.body;

  try {
    // Verificar se o usuário existe
    const userQuery = 'SELECT * FROM users WHERE id = $1';
    const userResult = await client.query(userQuery, [userId]);
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }
    
    // Verificar se o usuário já é um consultor
    const consultantCheckQuery = 'SELECT * FROM consultants WHERE user_id = $1';
    const consultantCheck = await client.query(consultantCheckQuery, [userId]);
    
    if (consultantCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'Usuário já é um consultor' });
    }
    
    // Atualizar o papel do usuário
    await client.query('UPDATE users SET role = $1 WHERE id = $2', ['consultant', userId]);
    
    // Criar o perfil de consultor
    const insertConsultantQuery = `
      INSERT INTO consultants (user_id, specialties, hourly_rate, bio)
      VALUES ($1, $2, $3, $4)
      RETURNING *
    `;
    const consultantResult = await client.query(
      insertConsultantQuery, 
      [userId, specialties, hourlyRate, bio]
    );
    
    res.json({ 
      success: true, 
      message: 'Consultor criado com sucesso',
      consultant: consultantResult.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao criar consultor' });
  }
});

// Rota para listar consultores disponíveis
app.get('/api/consultants', async (req, res) => {
  try {
    const query = `
      SELECT 
        c.id, c.specialties, c.hourly_rate, c.status, c.rating, c.bio,
        u.id as user_id, u.nickname
      FROM consultants c
      JOIN users u ON c.user_id = u.id
      WHERE c.status = 'online'
      ORDER BY c.rating DESC
    `;
    const result = await client.query(query);
    res.json({ success: true, consultants: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao listar consultores' });
  }
});

// Rota para atualizar status do consultor
app.put('/api/consultants/status', authenticateJWT, isConsultant, async (req, res) => {
  const { status } = req.body;
  const userId = req.user.id;

  if (!status || !['online', 'offline', 'busy'].includes(status)) {
    return res.status(400).json({ success: false, message: 'Status inválido. Use: online, offline ou busy' });
  }

  try {
    // Verificar se o usuário é um consultor
    const consultantQuery = 'SELECT * FROM consultants WHERE user_id = $1';
    const consultantResult = await client.query(consultantQuery, [userId]);
    
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Perfil de consultor não encontrado' });
    }
    
    // Atualizar o status
    await client.query('UPDATE consultants SET status = $1 WHERE user_id = $2', [status, userId]);
    
    // Notificar os clientes via Socket.IO
    io.emit('consultant_status_changed', {
      consultantId: consultantResult.rows[0].id,
      status
    });
    
    res.json({ success: true, message: `Status atualizado para ${status}` });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao atualizar status' });
  }
});

// Rota para solicitar uma sessão de chat
app.post('/api/chat-sessions', authenticateJWT, async (req, res) => {
  const { consultantId } = req.body;
  const userId = req.user.id;

  try {
    // Verificar se o consultor existe e está online
    const consultantQuery = 'SELECT * FROM consultants WHERE id = $1 AND status = \'online\'';
    const consultantResult = await client.query(consultantQuery, [consultantId]);
    
    if (consultantResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Consultor não encontrado ou não está disponível' });
    }
    
    // Criar nova sessão de chat
    const createSessionQuery = `
      INSERT INTO chat_sessions (user_id, consultant_id, status)
      VALUES ($1, $2, 'waiting')
      RETURNING *
    `;
    const sessionResult = await client.query(createSessionQuery, [userId, consultantId]);
    const session = sessionResult.rows[0];
    
    // Obter informações do usuário
    const userQuery = 'SELECT nickname FROM users WHERE id = $1';
    const userResult = await client.query(userQuery, [userId]);
    
    // Notificar o consultor via Socket.IO
    io.emit('chat_request', {
      sessionId: session.id,
      userId,
      userNickname: userResult.rows[0].nickname,
      consultantId,
      timestamp: new Date()
    });
    
    res.json({ 
      success: true, 
      message: 'Solicitação de chat enviada com sucesso',
      session
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao solicitar chat' });
  }
});

// Rota para aceitar uma sessão de chat
app.put('/api/chat-sessions/:sessionId/accept', authenticateJWT, isConsultant, async (req, res) => {
  const { sessionId } = req.params;
  const consultantUserId = req.user.id;

  try {
    // Verificar se a sessão existe
    const sessionQuery = `
      SELECT s.*, c.user_id as consultant_user_id
      FROM chat_sessions s
      JOIN consultants c ON s.consultant_id = c.id
      WHERE s.id = $1 AND s.status = 'waiting'
    `;
    const sessionResult = await client.query(sessionQuery, [sessionId]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Sessão não encontrada ou não está aguardando' });
    }
    
    const session = sessionResult.rows[0];
    
    // Verificar se o consultor é o correto
    if (session.consultant_user_id !== consultantUserId) {
      return res.status(403).json({ success: false, message: 'Você não é o consultor desta sessão' });
    }
    
    // Atualizar o status da sessão e definir o horário de início
    const updateSessionQuery = `
      UPDATE chat_sessions
      SET status = 'active', start_time = CURRENT_TIMESTAMP
      WHERE id = $1
      RETURNING *
    `;
    const updatedSession = await client.query(updateSessionQuery, [sessionId]);
    
    // Atualizar o status do consultor para ocupado
    await client.query('UPDATE consultants SET status = $1 WHERE user_id = $2', ['busy', consultantUserId]);
    
    // Notificar via Socket.IO
    io.emit('chat_accepted', {
      sessionId,
      userId: session.user_id,
      consultantId: session.consultant_id,
      startTime: updatedSession.rows[0].start_time
    });
    
    res.json({ 
      success: true, 
      message: 'Sessão de chat aceita com sucesso',
      session: updatedSession.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao aceitar sessão de chat' });
  }
});

// Rota para finalizar uma sessão de chat
app.put('/api/chat-sessions/:sessionId/end', authenticateJWT, async (req, res) => {
  const { sessionId } = req.params;
  const userId = req.user.id;

  try {
    // Verificar se a sessão existe e está ativa
    const sessionQuery = `
      SELECT s.*, c.user_id as consultant_user_id
      FROM chat_sessions s
      JOIN consultants c ON s.consultant_id = c.id
      WHERE s.id = $1 AND s.status = 'active'
    `;
    const sessionResult = await client.query(sessionQuery, [sessionId]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Sessão não encontrada ou não está ativa' });
    }
    
    const session = sessionResult.rows[0];
    
    // Verificar se o usuário é participante da sessão
    if (session.user_id !== userId && session.consultant_user_id !== userId) {
      return res.status(403).json({ success: false, message: 'Você não é participante desta sessão' });
    }
    
    // Atualizar a sessão
    const endTime = new Date();
    const startTime = new Date(session.start_time);
    const durationInSeconds = Math.floor((endTime - startTime) / 1000);
    
    const updateSessionQuery = `
      UPDATE chat_sessions
      SET status = 'completed', end_time = CURRENT_TIMESTAMP, duration = $1
      WHERE id = $2
      RETURNING *
    `;
    const updatedSession = await client.query(updateSessionQuery, [durationInSeconds, sessionId]);
    
    // Atualizar as estatísticas do consultor
    const updateConsultantQuery = `
      UPDATE consultants
      SET 
        status = 'online',
        total_time_logged = total_time_logged + $1,
        total_clients_served = total_clients_served + 1
      WHERE id = $2
    `;
    await client.query(updateConsultantQuery, [durationInSeconds, session.consultant_id]);
    
    // Notificar via Socket.IO
    io.emit('chat_ended', {
      sessionId,
      userId: session.user_id,
      consultantId: session.consultant_id,
      duration: durationInSeconds
    });
    
    res.json({ 
      success: true, 
      message: 'Sessão de chat finalizada com sucesso',
      session: updatedSession.rows[0]
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao finalizar sessão de chat' });
  }
});

// Rota para enviar mensagem em um chat
app.post('/api/chat-sessions/:sessionId/messages', authenticateJWT, async (req, res) => {
  const { sessionId } = req.params;
  const { message } = req.body;
  const senderId = req.user.id;

  if (!message) {
    return res.status(400).json({ success: false, message: 'Mensagem não pode estar vazia' });
  }

  try {
    // Verificar se a sessão existe e está ativa
    const sessionQuery = `
      SELECT s.*, c.user_id as consultant_user_id
      FROM chat_sessions s
      JOIN consultants c ON s.consultant_id = c.id
      WHERE s.id = $1 AND s.status = 'active'
    `;
    const sessionResult = await client.query(sessionQuery, [sessionId]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Sessão não encontrada ou não está ativa' });
    }
    
    const session = sessionResult.rows[0];
    
    // Verificar se o usuário é participante da sessão
    if (session.user_id !== senderId && session.consultant_user_id !== senderId) {
      return res.status(403).json({ success: false, message: 'Você não é participante desta sessão' });
    }
    
    // Salvar a mensagem
    const insertMessageQuery = `
      INSERT INTO chat_messages (session_id, sender_id, message)
      VALUES ($1, $2, $3)
      RETURNING id, message, timestamp
    `;
    const messageResult = await client.query(insertMessageQuery, [sessionId, senderId, message]);
    const newMessage = messageResult.rows[0];
    
    // Buscar informações do remetente para enviar junto com a mensagem
    const senderQuery = 'SELECT nickname, role FROM users WHERE id = $1';
    const senderResult = await client.query(senderQuery, [senderId]);
    
    // Criar objeto de mensagem
    const messageObject = {
      id: newMessage.id,
      sessionId: parseInt(sessionId),
      senderId,
      senderNickname: senderResult.rows[0].nickname,
      senderRole: senderResult.rows[0].role,
      message: newMessage.message,
      timestamp: newMessage.timestamp
    };
    
    // Enviar via Socket.IO
    io.emit(`chat_message_${sessionId}`, messageObject);
    
    res.json({ 
      success: true, 
      message: 'Mensagem enviada com sucesso',
      chatMessage: messageObject
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao enviar mensagem' });
  }
});

// Rota para buscar histórico de mensagens
app.get('/api/chat-sessions/:sessionId/messages', authenticateJWT, async (req, res) => {
  const { sessionId } = req.params;
  const userId = req.user.id;

  try {
    // Verificar se a sessão existe
    const sessionQuery = `
      SELECT s.*, c.user_id as consultant_user_id
      FROM chat_sessions s
      JOIN consultants c ON s.consultant_id = c.id
      WHERE s.id = $1
    `;
    const sessionResult = await client.query(sessionQuery, [sessionId]);
    
    if (sessionResult.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Sessão não encontrada' });
    }
    
    const session = sessionResult.rows[0];
    
    // Verificar se o usuário é participante da sessão
    if (session.user_id !== userId && session.consultant_user_id !== userId && req.user.role !== 'admin') {
      return res.status(403).json({ success: false, message: 'Você não tem permissão para ver estas mensagens' });
    }
    
    // Buscar as mensagens
    const messagesQuery = `
      SELECT 
        m.id, m.message, m.timestamp, m.sender_id,
        u.nickname as sender_nickname, u.role as sender_role
      FROM chat_messages m
      JOIN users u ON m.sender_id = u.id
      WHERE m.session_id = $1
      ORDER BY m.timestamp ASC
    `;
    const messagesResult = await client.query(messagesQuery, [sessionId]);
    
    res.json({ 
      success: true, 
      messages: messagesResult.rows
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Erro ao buscar mensagens' });
  }
});


// Rota para avaliar um consultor após uma sessão
  try {
    app.post('/api/ratings', authenticateJWT, async (req, res) => {
      const { sessionId, rating, comment } = req.body;
      const userId = req.user.id;
    
      if (!sessionId || !rating || rating < 1 || rating > 5) {
        return res.status(400).json({ success: false, message: 'ID de sessão e avaliação (1-5) são obrigatórios' });
      }
    
      try {
        // Verificar se a sessão existe e está completa
        const sessionQuery = `
          SELECT * FROM chat_sessions 
          WHERE id = $1 AND status = 'completed' AND user_id = $2
        `;
        const sessionResult = await client.query(sessionQuery, [sessionId, userId]);
        
        if (sessionResult.rows.length === 0) {
          return res.status(404).json({ 
            success: false, 
            message: 'Sessão não encontrada, não está completa ou você não é o cliente desta sessão' 
          });
        }
        
        const session = sessionResult.rows[0];
        
        // Verificar se já existe uma avaliação para esta sessão
        const checkRatingQuery = 'SELECT * FROM ratings WHERE session_id = $1';
        const existingRating = await client.query(checkRatingQuery, [sessionId]);
        
        if (existingRating.rows.length > 0) {
          return res.status(400).json({ success: false, message: 'Esta sessão já foi avaliada' });
        }
        
        // Inserir a avaliação
        const insertRatingQuery = `
          INSERT INTO ratings (session_id, user_id, consultant_id, rating, comment)
          VALUES ($1, $2, $3, $4, $5)
          RETURNING *
        `;
        const ratingResult = await client.query(
          insertRatingQuery, 
          [sessionId, userId, session.consultant_id, rating, comment || null]
        );
        
        // Atualizar a média de avaliação do consultor
        const updateConsultantRatingQuery = `
          UPDATE consultants
          SET rating = (
            SELECT AVG(rating) FROM ratings
            WHERE consultant_id = $1
          )
          WHERE id = $1
          RETURNING rating
        `;
        const updatedConsultant = await client.query(updateConsultantRatingQuery, [session.consultant_id]);
        
        res.json({ 
          success: true, 
          message: 'Avaliação enviada com sucesso',
          rating: ratingResult.rows[0],
          newConsultantRating: updatedConsultant.rows[0].rating
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Erro ao enviar avaliação' });
      }
    });
  } catch (error) {
    console.error('Erro global no servidor:', error);
}
    // Rota para obter estatísticas gerais (apenas admin)
    app.get('/api/stats', authenticateJWT, isAdmin, async (req, res) => {
      try {
        // Total de usuários
        const totalUsersQuery = 'SELECT COUNT(*) as total FROM users WHERE role = \'user\'';
        const totalUsers = await client.query(totalUsersQuery);
        
        // Total de consultores
        const totalConsultantsQuery = 'SELECT COUNT(*) as total FROM consultants';
        const totalConsultants = await client.query(totalConsultantsQuery);
        
        // Total de sessões
        const totalSessionsQuery = 'SELECT COUNT(*) as total FROM chat_sessions';
        const totalSessions = await client.query(totalSessionsQuery);
        
        // Sessões nos últimos 30 dias
        const recentSessionsQuery = `
          SELECT COUNT(*) as total FROM chat_sessions 
          WHERE created_at > CURRENT_DATE - INTERVAL '30 days'
        `;
        const recentSessions = await client.query(recentSessionsQuery);
        
        // Média de duração das sessões (em segundos)
        const avgDurationQuery = 'SELECT AVG(duration) as average FROM chat_sessions WHERE status = \'completed\'';
        const avgDuration = await client.query(avgDurationQuery);
        
        // Média de avaliações
        const avgRatingQuery = 'SELECT AVG(rating) as average FROM ratings';
        const avgRating = await client.query(avgRatingQuery);
        
        // Consultores mais ativos
        const topConsultantsQuery = `
          SELECT 
            c.id, c.total_clients_served, c.total_time_logged, c.rating,
            u.nickname
          FROM consultants c
          JOIN users u ON c.user_id = u.id
          ORDER BY c.total_clients_served DESC
          LIMIT 5
        `;
        const topConsultants = await client.query(topConsultantsQuery);
        
        res.json({ 
          success: true, 
          stats: {
            totalUsers: parseInt(totalUsers.rows[0].total),
            totalConsultants: parseInt(totalConsultants.rows[0].total),
            totalSessions: parseInt(totalSessions.rows[0].total),
            recentSessions: parseInt(recentSessions.rows[0].total),
            avgSessionDuration: avgDuration.rows[0].average ? parseFloat(avgDuration.rows[0].average) : 0,
            avgRating: avgRating.rows[0].average ? parseFloat(avgRating.rows[0].average) : 0,
            topConsultants: topConsultants.rows
          }
        });
      } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Erro ao obter estatísticas' });
      }
    });
    
    // Lidar com conexões Socket.IO
    io.on('connection', (socket) => {
      console.log('Novo cliente conectado:', socket.id);
      
      // Associar usuário ao socket (se autenticado)
      socket.on('authenticate', (token) => {
        try {
          const user = jwt.verify(token, JWT_SECRET);
          socket.userId = user.id;
          socket.userRole = user.role;
          socket.join(`user_${user.id}`);
          console.log(`Usuário ${user.id} autenticado no socket: ${socket.id}`);
          
          // Se for consultor, verificar e atualizar status
          if (user.role === 'consultant') {
            client.query('SELECT id FROM consultants WHERE user_id = $1', [user.id])
              .then(result => {
                if (result.rows.length > 0) {
                  const consultantId = result.rows[0].id;
                  socket.consultantId = consultantId;
                  socket.join(`consultant_${consultantId}`);
                  
                  // Atualizar status para online
                  client.query('UPDATE consultants SET status = $1 WHERE id = $2', ['online', consultantId])
                    .then(() => {
                      io.emit('consultant_status_changed', {
                        consultantId,
                        status: 'online'
                      });
                    })
                    .catch(err => console.error('Erro ao atualizar status do consultor:', err));
                }
              })
              .catch(err => console.error('Erro ao verificar consultor:', err));
          }
        } catch (error) {
          console.error('Erro ao autenticar socket:', error);
        }
      });
      
      // Entrar em uma sala de chat específica
      socket.on('join_chat', (sessionId) => {
        socket.join(`chat_${sessionId}`);
        console.log(`Socket ${socket.id} entrou na sala chat_${sessionId}`);
      });
      
      // Sair de uma sala de chat específica
      socket.on('leave_chat', (sessionId) => {
        socket.leave(`chat_${sessionId}`);
        console.log(`Socket ${socket.id} saiu da sala chat_${sessionId}`);
      });
      
      // Enviar mensagem para uma sala de chat específica
      socket.on('send_message', async (data) => {
        const { sessionId, message } = data;
        
        // Verificar se o usuário está autenticado no socket
        if (!socket.userId) {
          socket.emit('error', { message: 'Você precisa estar autenticado para enviar mensagens' });
          return;
        }
        
        try {
          // Verificar se a sessão existe e está ativa
          const sessionQuery = `
            SELECT s.*, c.user_id as consultant_user_id
            FROM chat_sessions s
            JOIN consultants c ON s.consultant_id = c.id
            WHERE s.id = $1 AND s.status = 'active'
          `;
          const sessionResult = await client.query(sessionQuery, [sessionId]);
          
          if (sessionResult.rows.length === 0) {
            socket.emit('error', { message: 'Sessão não encontrada ou não está ativa' });
            return;
          }
          
          const session = sessionResult.rows[0];
          
          // Verificar se o usuário é participante da sessão
          if (session.user_id !== socket.userId && session.consultant_user_id !== socket.userId) {
            socket.emit('error', { message: 'Você não é participante desta sessão' });
            return;
          }
          
          // Salvar a mensagem
          const insertMessageQuery = `
            INSERT INTO chat_messages (session_id, sender_id, message)
            VALUES ($1, $2, $3)
            RETURNING id, message, timestamp
          `;
          const messageResult = await client.query(insertMessageQuery, [sessionId, socket.userId, message]);
          const newMessage = messageResult.rows[0];
          
          // Buscar informações do remetente
          const senderQuery = 'SELECT nickname, role FROM users WHERE id = $1';
          const senderResult = await client.query(senderQuery, [socket.userId]);
          
          // Criar objeto de mensagem
          const messageObject = {
            id: newMessage.id,
            sessionId: parseInt(sessionId),
            senderId: socket.userId,
            senderNickname: senderResult.rows[0].nickname,
            senderRole: senderResult.rows[0].role,
            message: newMessage.message,
            timestamp: newMessage.timestamp
          };
          
          // Enviar para todos na sala de chat
          io.to(`chat_${sessionId}`).emit('new_message', messageObject);
        } catch (error) {
          console.error('Erro ao enviar mensagem:', error);
          socket.emit('error', { message: 'Erro ao enviar mensagem' });
        }
      });
      
      // Gerenciar desconexões
      socket.on('disconnect', async () => {
        console.log('Cliente desconectado:', socket.id);
        
        // Se for um consultor, atualizar status para offline
        if (socket.userRole === 'consultant' && socket.consultantId) {
          try {
            await client.query('UPDATE consultants SET status = $1 WHERE id = $2', ['offline', socket.consultantId]);
            
            io.emit('consultant_status_changed', {
              consultantId: socket.consultantId,
              status: 'offline'
            });
          } catch (error) {
            console.error('Erro ao atualizar status do consultor desconectado:', error);
          }
        }
      });
    });
    
    // Tratamento de erros para rotas não encontradas
    app.use((req, res) => {
      res.status(404).json({ success: false, message: 'Rota não encontrada' });
    });
    
    // Iniciar o servidor
    const PORT = process.env.PORT || 10000;
    server.listen(PORT, () => {
      console.log(`Servidor rodando na porta ${PORT}`);
    });
    
    // Tratamento para encerramento gracioso do servidor
    process.on('SIGINT', async () => {
      console.log('Encerrando servidor...');
      try {
        await client.end();
        console.log('Conexão com banco de dados encerrada');
        server.close(() => {
          console.log('Servidor HTTP encerrado');
          process.exit(0);
        });
      } catch (error) {
        console.error('Erro ao encerrar conexões:', error);
        process.exit(1);
      }
    });
