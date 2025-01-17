// Navegar para o chat
function startChat() {
    const duration = document.getElementById('duration').value;
    const username = document.getElementById('username').value.trim();

    if (!username) {
        alert('Por favor, insira seu nome.');
        return;
    }

    alert(`Iniciando chat para ${username} por ${duration} minutos.`);
    // Lógica para redirecionar ou iniciar o chat será adicionada
}

// Obter horóscopo (placeholder)
function getHoroscope() {
    const zodiac = document.getElementById('zodiac').value;
    document.getElementById('horoscope-result').textContent = `O horóscopo para ${zodiac} será adicionado futuramente.`;
}
