const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');

// Configurações do Servidor
const app = express();
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: "*", // Permitir conexões de qualquer origem
        methods: ["GET", "POST"]
    }
});

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 10000;

// Gerenciar sessões e temporizadores
const sessions = {};

// Conexão WebSocket
io.on('connection', (socket) => {
    console.log('Novo cliente conectado:', socket.id);

    // Evento para iniciar uma sessão de chat
    socket.on('startSession', ({ username, duration }) => {
        const endTime = Date.now() + duration * 60000; // Duração em milissegundos
        sessions[socket.id] = { username, endTime };

        socket.emit('sessionStarted', { endTime });

        // Enviar atualizações do temporizador a cada segundo
        const interval = setInterval(() => {
            const timeLeft = Math.max(0, sessions[socket.id].endTime - Date.now());
            if (timeLeft === 0) {
                clearInterval(interval);
                socket.emit('sessionEnded', 'O tempo da sua sessão acabou.');
                socket.disconnect();
                delete sessions[socket.id];
            } else {
                socket.emit('timeUpdate', timeLeft);
            }
        }, 1000);
    });

    // Evento para mensagens do chat
    socket.on('sendMessage', (message) => {
        const session = sessions[socket.id];
        if (session) {
            // Emitir mensagem para todos os clientes conectados
            io.emit('newMessage', { username: session.username, message });
        }
    });

    // Evento de desconexão
    socket.on('disconnect', () => {
        console.log('Cliente desconectado:', socket.id);
        delete sessions[socket.id];
    });
});

// Rota padrão
app.get('/', (req, res) => {
    res.send('Servidor de Chat de Tarot está ativo!');
});

// Iniciar servidor
server.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
