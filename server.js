const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// Configuração do banco de dados
const pool = new Pool({
  user: 'login_p7n8_user',
  host: 'dpg-cutqkfd2ng1s73dd5ui0-a',
  database: 'login_p7n8',
  password: 'uhF5GKbxzXYyS0jtx9PDj4lIcRpnKk00',
  port: 5432,
});

const cors = require('cors');

// Habilitar CORS
app.use(cors({
  origin: '*', // Permite todas as origens (ajuste conforme necessário)
}));

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Acesso negado' });

  jwt.verify(token, 'sua_chave_secreta', (err, user) => {
    if (err) return res.status(403).json({ error: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Verificar se a tabela existe e criar/atualizar se necessário
async function verifyDatabase() {
  try {
    // Verificar se a tabela `usuarios` existe
    const tableExists = await pool.query(`
      SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'usuarios'
      );
    `);

    if (!tableExists.rows[0].exists) {
      // Criar a tabela se não existir
      await pool.query(`
        CREATE TABLE usuarios (
          id SERIAL PRIMARY KEY,
          nome VARCHAR(100),
          email VARCHAR(100) UNIQUE NOT NULL,
          senha VARCHAR(255) NOT NULL,
          tipo_usuario VARCHAR(10) NOT NULL CHECK (tipo_usuario IN ('usuario', 'admin', 'master')),
          privilegio VARCHAR(10) NOT NULL CHECK (privilegio IN ('usuario', 'admin', 'master')),
          ultimo_login TIMESTAMP,
          tempo_online INTERVAL DEFAULT '00:00:00'
        );
      `);
      console.log('Tabela "usuarios" criada com sucesso.');
    } else {
      // Verificar se os campos `tipo_usuario` e `privilegio` existem
      const columnsExist = await pool.query(`
        SELECT column_name
        FROM information_schema.columns
        WHERE table_name = 'usuarios' AND column_name IN ('tipo_usuario', 'privilegio');
      `);

      const existingColumns = columnsExist.rows.map(row => row.column_name);
      if (!existingColumns.includes('tipo_usuario')) {
        await pool.query(`ALTER TABLE usuarios ADD COLUMN tipo_usuario VARCHAR(10) NOT NULL DEFAULT 'usuario';`);
        console.log('Coluna "tipo_usuario" adicionada à tabela "usuarios".');
      }
      if (!existingColumns.includes('privilegio')) {
        await pool.query(`ALTER TABLE usuarios ADD COLUMN privilegio VARCHAR(10) NOT NULL DEFAULT 'usuario';`);
        console.log('Coluna "privilegio" adicionada à tabela "usuarios".');
      }

      // Garantir que os valores de `tipo_usuario` e `privilegio` estejam corretos
      await pool.query(`
        ALTER TABLE usuarios
        ADD CONSTRAINT chk_tipo_usuario CHECK (tipo_usuario IN ('usuario', 'admin', 'master')),
        ADD CONSTRAINT chk_privilegio CHECK (privilegio IN ('usuario', 'admin', 'master'));
      `);
      console.log('Restrições de tipo e privilégio aplicadas.');
    }
  } catch (error) {
    console.error('Erro ao verificar/criar tabela:', error);
  }
}

// Executar a verificação do banco de dados ao iniciar o servidor
verifyDatabase();

// Rota de Login
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const result = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.status(401).json({ error: 'Usuário não encontrado' });

    const user = result.rows[0];
    const isPasswordValid = await bcryptjs.compare(password, user.senha);
    if (!isPasswordValid) return res.status(401).json({ error: 'Senha incorreta' });

    // Atualizar último login
    await pool.query('UPDATE usuarios SET ultimo_login = NOW() WHERE id = $1', [user.id]);

    // Gerar token JWT
    const token = jwt.sign(
      { userId: user.id, privilegio: user.privilegio },
      'sua_chave_secreta',
      { expiresIn: '1h' }
    );

    res.json({ token, privilegio: user.privilegio });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Dashboard (Ponto de Encontro)
app.get('/dashboard', authenticateToken, async (req, res) => {
  const { privilegio } = req.user;

  try {
    // Dados comuns para todos os usuários
    const userData = {
      privilegio,
      mensagem: 'Bem-vindo ao Dashboard!',
    };

    // Dados específicos para consultores (admin ou master)
    if (privilegio === 'admin' || privilegio === 'master') {
      const consultas = await pool.query('SELECT * FROM consultas');
      userData.consultas = consultas.rows;
    }

    // Dados específicos para usuários comuns
    if (privilegio === 'usuario') {
      const consultasUsuario = await pool.query('SELECT * FROM consultas WHERE usuario_id = $1', [req.user.userId]);
      userData.consultas = consultasUsuario.rows;
    }

    res.json(userData);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Erro interno do servidor' });
  }
});

// Iniciar o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});