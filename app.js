import React, { useEffect, useState } from 'react';
import io from 'socket.io-client';

const socket = io('http://localhost:3000'); // Conectar ao backend

function App() {
    const [role, setRole] = useState('user'); // 'user' ou 'consultant'
    const [userId, setUserId] = useState('user123'); // ID do usuário
    const [consultantId, setConsultantId] = useState('consultant456'); // ID do consultor
    const [status, setStatus] = useState('idle'); // Estado da consulta
    const [messages, setMessages] = useState([]);
    const [room, setRoom] = useState(null);

    useEffect(() => {
        // Registrar usuário ou consultor
        if (role === 'user') {
            socket.emit('registerUser', userId);
        } else {
            socket.emit('registerConsultant', consultantId);
        }

        // Receber solicitações de consulta
        socket.on('consultationRequest', ({ userId }) => {
            alert(`Nova solicitação de consulta do usuário ${userId}`);
        });

        // Aguardando confirmação
        socket.on('waitingConfirmation', () => {
            setStatus('waiting');
        });

        // Consulta aceita
        socket.on('consultationAccepted', ({ room }) => {
            setRoom(room);
            setStatus('accepted');
        });

        // Receber mensagens
        socket.on('receiveMessage', (message) => {
            setMessages((prev) => [...prev, message]);
        });

        return () => {
            socket.disconnect();
        };
    }, [role]);

    const requestConsultation = () => {
        socket.emit('requestConsultation', { userId, consultantId });
    };

    const sendMessage = (message) => {
        if (room) {
            socket.emit('sendMessage', { room, message });
        }
    };

    return (
        <div>
            <h1>Bem-vindo ao Site de Tarot</h1>
            <button onClick={() => setRole('user')}>Sou Usuário</button>
            <button onClick={() => setRole('consultant')}>Sou Consultor</button>

            {role === 'user' && (
                <div>
                    <button onClick={requestConsultation} disabled={status !== 'idle'}>
                        Solicitar Consulta
                    </button>
                    {status === 'waiting' && <p>Aguardando confirmação...</p>}
                    {status === 'accepted' && (
                        <div>
                            <h2>Chat</h2>
                            <ul>
                                {messages.map((msg, index) => (
                                    <li key={index}>{msg}</li>
                                ))}
                            </ul>
                            <input
                                type="text"
                                onKeyDown={(e) => {
                                    if (e.key === 'Enter') {
                                        sendMessage(e.target.value);
                                        e.target.value = '';
                                    }
                                }}
                            />
                        </div>
                    )}
                </div>
            )}

            {role === 'consultant' && (
                <div>
                    <h2>Painel do Consultor</h2>
                    {/* Implementar lista de solicitações */}
                </div>
            )}
        </div>
    );
}

export default App;