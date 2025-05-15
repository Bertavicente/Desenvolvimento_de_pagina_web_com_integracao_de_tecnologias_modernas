const express = require('express');
const router = express.Router();
const fs = require('fs');
const jwt = require('jsonwebtoken');

// Arquivos de dados
const itemsFile = './items.json';
const historyFile = './history.json';
const usersFile = './users.json';

// Funções para carregar dados
function loadItems() {
  try {
    if (!fs.existsSync(itemsFile)) {
      fs.writeFileSync(itemsFile, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(itemsFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Erro ao carregar items.json:', error.message);
    fs.writeFileSync(itemsFile, JSON.stringify([], null, 2));
    return [];
  }
}

function loadHistory() {
  try {
    if (!fs.existsSync(historyFile)) {
      fs.writeFileSync(historyFile, JSON.stringify([], null, 2));
      return [];
    }
    const data = fs.readFileSync(historyFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Erro ao carregar history.json:', error.message);
    fs.writeFileSync(historyFile, JSON.stringify([], null, 2));
    return [];
  }
}

function loadUsers() {
  try {
    if (!fs.existsSync(usersFile)) {
      fs.writeFileSync(usersFile, JSON.stringify([
        { username: 'Berta', password: '1234', role: 'user' },
        { username: 'admin', password: 'admin', role: 'admin' }
      ], null, 2));
      return [
        { username: 'Berta', password: '1234', role: 'user' },
        { username: 'admin', password: 'admin', role: 'admin' }
      ];
    }
    const data = fs.readFileSync(usersFile, 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Erro ao carregar users.json:', error.message);
    fs.writeFileSync(usersFile, JSON.stringify([], null, 2));
    return [];
  }
}

// Dados em memória
let items = loadItems();
let history = loadHistory();
let users = loadUsers();

// Middleware para autenticação
function authenticateToken(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token não fornecido' });
  jwt.verify(token, 'secret_key', (err, user) => {
    if (err) return res.status(403).json({ message: 'Token inválido' });
    req.user = user;
    next();
  });
}

// Endpoint para login
router.post('/login', (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: 'Usuário e senha são obrigatórios' });
    }
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) {
      return res.status(401).json({ message: 'Credenciais inválidas' });
    }
    const token = jwt.sign({ username: user.username, role: user.role }, 'secret_key', { expiresIn: '1h' });
    res.json({ token });
  } catch (error) {
    console.error('Erro ao fazer login:', error.message);
    res.status(500).json({ message: 'Erro interno ao fazer login' });
  }
});

// Endpoint para registro
router.post('/register', (req, res) => {
  try {
    const { username, password, perfil } = req.body;
    if (!username || !password || !perfil) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
    }
    if (username.length < 3 || password.length < 3) {
      return res.status(400).json({ message: 'Usuário e senha devem ter pelo menos 3 caracteres' });
    }
    if (users.find(u => u.username === username)) {
      return res.status(400).json({ message: 'Usuário já existe' });
    }
    const validRoles = ['user', 'admin'];
    const role = validRoles.includes(perfil) ? perfil : 'user';
    const newUser = { username, password, role };
    users.push(newUser);
    fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
    users = loadUsers(); // Recarrega para sincronizar
    res.json({ message: 'Registro realizado com sucesso' });
  } catch (error) {
    console.error('Erro ao registrar:', error.message);
    res.status(500).json({ message: 'Erro interno ao registrar' });
  }
});

// Endpoint para listar itens
router.get('/items', authenticateToken, (req, res) => {
  try {
    const category = req.query.category;
    let filteredItems = req.user.role === 'admin' ? items : items.filter(item => item.user === req.user.username);
    if (category) filteredItems = filteredItems.filter(item => item.category === category);
    res.json(filteredItems);
  } catch (error) {
    console.error('Erro ao listar itens:', error.message);
    res.status(500).json({ message: 'Erro interno ao listar itens' });
  }
});

// Endpoint para adicionar item
router.post('/items', authenticateToken, (req, res) => {
  try {
    const { name, quantity, price, time, place, category } = req.body;
    if (!name || !quantity || !price || !time || !place || !category) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
    }
    if (isNaN(quantity) || quantity < 1) {
      return res.status(400).json({ message: 'Quantidade deve ser um número positivo' });
    }
    if (isNaN(price) || price < 0) {
      return res.status(400).json({ message: 'Preço deve ser um número não negativo' });
    }
    const item = {
      id: items.length + 1,
      user: req.user.username,
      name,
      quantity: parseInt(quantity),
      price: parseFloat(price),
      time,
      place,
      category,
      stock: 10 // Estoque inicial
    };
    items.push(item);
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    req.app.locals.broadcastItems();
    res.json({ message: 'Item adicionado com sucesso' });
  } catch (error) {
    console.error('Erro ao adicionar item:', error.message);
    res.status(500).json({ message: 'Erro interno ao adicionar item' });
  }
});

// Endpoint para editar item
router.put('/items/:id', authenticateToken, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const itemIndex = items.findIndex(item => item.id === id);
    if (itemIndex === -1) return res.status(404).json({ message: 'Item não encontrado' });
    const item = items[itemIndex];
    if (item.user !== req.user.username && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    const { name, quantity, price, time, place, category } = req.body;
    if (!name || !quantity || !price || !time || !place || !category) {
      return res.status(400).json({ message: 'Todos os campos são obrigatórios' });
    }
    if (isNaN(quantity) || quantity < 1) {
      return res.status(400).json({ message: 'Quantidade deve ser um número positivo' });
    }
    if (isNaN(price) || price < 0) {
      return res.status(400).json({ message: 'Preço deve ser um número não negativo' });
    }
    items[itemIndex] = {
      ...item,
      name,
      quantity: parseInt(quantity),
      price: parseFloat(price),
      time,
      place,
      category,
      stock: item.stock - (parseInt(quantity) - item.quantity) // Atualiza estoque
    };
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    req.app.locals.broadcastItems();
    res.json({ message: 'Item atualizado com sucesso' });
  } catch (error) {
    console.error('Erro ao editar item:', error.message);
    res.status(500).json({ message: 'Erro interno ao editar item' });
  }
});

// Endpoint para remover item
router.delete('/items/:id', authenticateToken, (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const item = items.find(item => item.id === id);
    if (!item) return res.status(404).json({ message: 'Item não encontrado' });
    if (item.user !== req.user.username && req.user.role !== 'admin') {
      return res.status(403).json({ message: 'Acesso negado' });
    }
    items = items.filter(item => item.id !== id);
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    req.app.locals.broadcastItems();
    res.json({ message: 'Item removido com sucesso' });
  } catch (error) {
    console.error('Erro ao remover item:', error.message);
    res.status(500).json({ message: 'Erro interno ao remover item' });
  }
});

// Endpoint para histórico
router.get('/history', authenticateToken, (req, res) => {
  try {
    const userHistory = history.filter(h => h.user === req.user.username);
    res.json(userHistory);
  } catch (error) {
    console.error('Erro ao listar histórico:', error.message);
    res.status(500).json({ message: 'Erro interno ao listar histórico' });
  }
});

// Endpoint para reutilizar histórico
router.post('/history/reuse/:id', authenticateToken, (req, res) => {
  try {
    const list = history.find(h => h.id === parseInt(req.params.id) && h.user === req.user.username);
    if (!list) return res.status(404).json({ message: 'Lista não encontrada' });
    list.items.forEach(item => {
      items.push({
        ...item,
        id: items.length + 1,
        user: req.user.username,
        time: new Date().toISOString()
      });
    });
    fs.writeFileSync(itemsFile, JSON.stringify(items, null, 2));
    req.app.locals.broadcastItems();
    res.json({ message: 'Lista reutilizada com sucesso' });
  } catch (error) {
    console.error('Erro ao reutilizar histórico:', error.message);
    res.status(500).json({ message: 'Erro interno ao reutilizar histórico' });
  }
});

// Endpoint para admin ver todos os itens
router.get('/admin/items', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acesso restrito' });
  try {
    res.json(items);
  } catch (error) {
    console.error('Erro ao listar itens (admin):', error.message);
    res.status(500).json({ message: 'Erro interno ao listar itens (admin)' });
  }
});

// Endpoint para admin ver todos os usuários
router.get('/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acesso restrito' });
  try {
    res.json(users);
  } catch (error) {
    console.error('Erro ao listar usuários (admin):', error.message);
    res.status(500).json({ message: 'Erro interno ao listar usuários (admin)' });
  }
});

// Endpoint para relatórios de admin
router.get('/admin/report/:type', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Acesso restrito' });
  try {
    const type = req.params.type;
    let report = {};
    if (type === 'monthly') {
      report = items.reduce((acc, item) => {
        const month = new Date(item.time).toLocaleString('pt-BR', { month: 'long', year: 'numeric' });
        acc[month] = (acc[month] || 0) + (item.price * item.quantity);
        return acc;
      }, {});
    } else if (type === 'price_variation') {
      report = items.reduce((acc, item) => {
        acc[item.name] = acc[item.name] || [];
        acc[item.name].push({ price: item.price, date: item.time });
        return acc;
      }, {});
    } else if (type === 'by_place') {
      report = items.reduce((acc, item) => {
        acc[item.place] = (acc[item.place] || 0) + (item.price * item.quantity);
        return acc;
      }, {});
    } else if (type === 'current_summary') {
      report = {
        total: items.reduce((sum, item) => sum + (item.price * item.quantity), 0),
        by_category: items.reduce((acc, item) => {
          acc[item.category] = (acc[item.category] || 0) + (item.price * item.quantity);
          return acc;
        }, {}),
        by_place: items.reduce((acc, item) => {
          acc[item.place] = (acc[item.place] || 0) + (item.price * item.quantity);
          return acc;
        }, {})
      };
    }
    res.json(report);
  } catch (error) {
    console.error('Erro ao gerar relatório:', error.message);
    res.status(500).json({ message: 'Erro interno ao gerar relatório' });
  }
});

module.exports = router;
module.exports.items = items;