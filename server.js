const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.get('/', (req, res) => {
    res.send('Servidor de chat está ativo.');
});

// Lida com conexões de WebSocket
io.on('connection', (socket) => {
    console.log('Novo usuário conectado.');

    socket.on('message', (msg) => {
        console.log('Mensagem recebida:', msg);
        socket.broadcast.emit('message', msg); // Envia a mensagem para outros usuários
    });

    socket.on('disconnect', () => {
        console.log('Usuário desconectado.');
    });
});

server.listen(8080, () => {
    console.log('Servidor rodando na porta 8080.');
});
