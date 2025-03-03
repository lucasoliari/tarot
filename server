const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const { Sequelize, DataTypes } = require('sequelize');

// Configuração do servidor
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Configuração do banco de dados (PostgreSQL)
const sequelize = new Sequelize('login_p7n8', 'login_p7n8_user', 'uhF5GKbxzXYyS0jtx9PDj4lIcRpnKk00', {
  host: 'dpg-cutqkfd2ng1s73dd5ui0-a',
  dialect: 'postgres',
});

// Modelos do banco de dados
const User = sequelize.define('User', {
  nickname: { type: DataTypes.STRING, allowNull: false },
  email: { type: DataTypes.STRING, allowNull: false, unique: true },
  password: { type: DataTypes.STRING, allowNull: false },
  role: { type: DataTypes.ENUM('user', 'consultant', 'admin'), defaultValue: 'user' },
});

const Consultant = sequelize.define('Consultant', {
  status: { type: DataTypes.ENUM('online', 'in_session', 'offline'), defaultValue: 'offline' },
  total_time_logged: { type: DataTypes.INTEGER, defaultValue: 0 },
  total_clients_served: { type: DataTypes.INTEGER, defaultValue: 0 },
});

const ChatSession = sequelize.define('ChatSession', {
  duration: { type: DataTypes.INTEGER, allowNull: false },
  start_time: { type: DataTypes.DATE },
  end_time: { type: DataTypes.DATE },
});

const ChatMessage = sequelize.define('ChatMessage', {
  message: { type: DataTypes.TEXT, allowNull: false },
  timestamp: { type: DataTypes.DATE, defaultValue: Sequelize.NOW },
});

// Relacionamentos
User.hasOne(Consultant);
Consultant.belongsTo(User);

ChatSession.belongsTo(User, { as: 'user' });
ChatSession.belongsTo(Consultant, { as: 'consultant' });

ChatMessage.belongsTo(ChatSession);

// Rotas
app.use(express.json());

// Rota de login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ where: { email, password } });
  if (user) {
    res.json({ success: true, role: user.role });
  } else {
    res.status(401).json({ success: false, message: 'Credenciais inválidas' });
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

// Sincronizar o banco de dados e iniciar o servidor
sequelize.sync().then(() => {
  server.listen(3000, () => {
    console.log('Servidor rodando na porta 3000');
  });
});