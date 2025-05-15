const express = require('express');
const jwt = require('jsonwebtoken');
const path = require('path');
const WebSocket = require('ws');
const router = require('./routes');

const app = express();
const port = 3000;

// Middleware para verificar autenticação (aplicado antes de express.static)
app.use((req, res, next) => {
  const publicRoutes = ['/login', '/register', '/api/login', '/api/register', '/about'];
  if (req.method === 'GET' && !publicRoutes.includes(req.path)) {
    const token = req.headers['authorization']?.split(' ')[1] || req.cookies['token'];
    if (!token) {
      return res.redirect('/login');
    }
    jwt.verify(token, 'secret_key', (err, user) => {
      if (err) {
        return res.redirect('/login');
      }
      req.user = user;
      next();
    });
  } else if (req.path.startsWith('/api/') && req.method !== 'GET') {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ message: 'Token não fornecido' });
    }
    jwt.verify(token, 'secret_key', (err, user) => {
      if (err) {
        return res.status(403).json({ message: 'Token inválido' });
      }
      req.user = user;
      next();
    });
  } else {
    next();
  }
});

// Middleware para parsing de JSON e formulários
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Servir arquivos estáticos após o middleware de autenticação
app.use(express.static(path.join(__dirname, '../public')));

// Rotas da API
app.use('/api', router);

// Rotas para páginas (como fallback)
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, '../public/login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, '../public/register.html')));
app.get('/index', (req, res) => res.sendFile(path.join(__dirname, '../public/index.html')));
app.get('/chat', (req, res) => res.sendFile(path.join(__dirname, '../public/chat.html')));
app.get('/about', (req, res) => res.sendFile(path.join(__dirname, '../public/about.html')));
app.get('/summary', (req, res) => res.sendFile(path.join(__dirname, '../public/summary.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, '../public/admin.html')));
app.get('/logout', (req, res) => {
  res.clearCookie('token');
  localStorage.removeItem('token'); // Simulação de remoção do localStorage
  res.redirect('/login');
});
app.get('/', (req, res) => res.redirect('/login'));

// Iniciar servidor HTTP
const server = app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});

// Configurar WebSocket
const wss = new WebSocket.Server({ server });
const clients = new Map();

app.locals.broadcastItems = () => {
  const items = router.items;
  wss.clients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify({ type: 'items', data: items }));
    }
  });
};

wss.on('connection', ws => {
  let username = null;

  ws.on('message', message => {
    try {
      const msg = JSON.parse(message);
      if (msg.type === 'chat') {
        let response = '';
        if (msg.data.action) {
          const items = router.items;
          if (msg.data.action === 'calculate_total') {
            const total = items.reduce((sum, item) => sum + (item.price * item.quantity), 0);
            response = `O total da sua lista é ${total.toFixed(2)} MZN.`;
          } else if (msg.data.action === 'organize_by_place') {
            const byPlace = items.reduce((acc, item) => {
              acc[item.place] = acc[item.place] || [];
              acc[item.place].push(item);
              return acc;
            }, {});
            response = 'Itens organizados por lugar:\n' + Object.entries(byPlace)
              .map(([place, items]) => `${place}: ${items.map(item => item.name).join(', ')}`)
              .join('\n');
          } else if (msg.data.action === 'suggestions') {
            response = 'Sugestões: Verifique se todos os itens estão disponíveis no estoque. Considere comprar em locais próximos para economizar tempo.';
          } else if (msg.data.action === 'contact_admin') {
            response = 'Você está agora em contato com o administrador. Por favor, envie sua dúvida.';
          }
        } else if (msg.data.text) {
          if (msg.data.isAdminChat && msg.data.user) {
            const targetClient = Array.from(clients.entries()).find(([u, c]) => u === msg.data.user && c.readyState === WebSocket.OPEN);
            if (targetClient) {
              targetClient[1].send(JSON.stringify({ type: 'chat', data: `Admin: ${msg.data.text}` }));
              response = `Mensagem enviada para ${msg.data.user}: ${msg.data.text}`;
            } else {
              response = `Usuário ${msg.data.user} não está online.`;
            }
          } else {
            response = `Você disse: "${msg.data.text}". Como posso ajudar? Deseja falar com o administrador?`;
          }
        }
        if (username && clients.has(username)) {
          clients.get(username).send(JSON.stringify({ type: 'chat', data: response }));
        }
      } else if (msg.type === 'auth') {
        username = msg.data.username;
        clients.set(username, ws);
        ws.send(JSON.stringify({ type: 'items', data: router.items }));
      }
    } catch (error) {
      console.error('Erro ao processar mensagem WebSocket:', error.message);
    }
  });

  ws.on('close', () => {
    if (username && clients.has(username)) {
      clients.delete(username);
    }
  });

  ws.on('error', (error) => {
    console.error('Erro no WebSocket:', error.message);
  });
});

module.exports = app;