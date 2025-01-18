const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');

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

// Configuração do pool de conexão com o PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL, // Substitua pelo valor da URL do banco fornecida pelo Render
    ssl: {
        rejectUnauthorized: false,
    },
});

// Gerenciar sessões e temporizadores
const sessions = {};

// Criar a tabela de usuários caso não exista
async function createUserTable() {
    const createTableQuery = `
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email VARCHAR(100) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `;
    try {
        await pool.query(createTableQuery);
        console.log('Tabela "users" criada ou já existe.');
    } catch (error) {
        console.error('Erro ao criar a tabela "users":', error);
    }
}

// Chamar a função de criação de tabela ao iniciar o servidor
createUserTable();

// Rota de registro de usuários
app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, hashedPassword]);
        res.status(201).send('Usuário registrado com sucesso!');
    } catch (error) {
        console.error('Erro ao registrar usuário:', error);
        res.status(500).send('Erro ao registrar o usuário.');
    }
});

// Rota de login de usuários
app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            const match = await bcrypt.compare(password, user.password_hash);
            if (match) {
                res.status(200).send('Login bem-sucedido!');
            } else {
                res.status(401).send('Senha incorreta.');
            }
        } else {
            res.status(404).send('Usuário não encontrado.');
        }
    } catch (error) {
        console.error('Erro ao fazer login:', error);
        res.status(500).send('Erro ao fazer login.');
    }
});

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
