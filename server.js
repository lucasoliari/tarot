const express = require('express');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const PORT = process.env.PORT || 3000;

io.on('connection', (socket) => {
    console.log('Usuário conectado:', socket.id);

    socket.on('sendMessage', (data) => {
        console.log('Mensagem recebida:', data.message);
        io.emit('receiveMessage', { message: data.message });
    });

    socket.on('disconnect', () => {
        console.log('Usuário desconectado:', socket.id);
    });
});

server.listen(PORT, () => {
    console.log(`Servidor rodando na porta ${PORT}`);
});
