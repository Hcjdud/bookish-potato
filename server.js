const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Создаем папки для загрузок
const fs = require('fs');
if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');
if (!fs.existsSync('uploads/cases')) fs.mkdirSync('uploads/cases');
if (!fs.existsSync('uploads/items')) fs.mkdirSync('uploads/items');

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const type = req.params.type || 'cases';
    cb(null, `uploads/${type}`);
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage: storage });

// ===== БАЗА ДАННЫХ =====
let db;

async function initDB() {
  db = await open({
    filename: './gifts.db',
    driver: sqlite3.Database
  });

  // Создаем таблицы
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      balance REAL DEFAULT 0,
      total_games INTEGER DEFAULT 0,
      total_wins INTEGER DEFAULT 0,
      is_premium BOOLEAN DEFAULT 0,
      is_admin BOOLEAN DEFAULT 0,
      is_banned BOOLEAN DEFAULT 0,
      ip_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE,
      description TEXT,
      price REAL,
      image_url TEXT,
      is_active BOOLEAN DEFAULT 1,
      sort_order INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS case_items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER,
      name TEXT,
      image_url TEXT,
      value REAL,
      probability REAL,
      FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS case_openings (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      case_id INTEGER,
      item_id INTEGER,
      win_amount REAL,
      is_test BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id),
      FOREIGN KEY (case_id) REFERENCES cases (id),
      FOREIGN KEY (item_id) REFERENCES case_items (id)
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      amount REAL,
      type TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id)
    );
  `);

  // Создаем админов если их нет
  const admin1 = await db.get('SELECT * FROM users WHERE username = ?', ['Aries']);
  if (!admin1) {
    const hash = await bcrypt.hash('cheesecakes', 10);
    await db.run(
      'INSERT INTO users (username, password, balance, is_admin) VALUES (?, ?, ?, ?)',
      ['Aries', hash, 10000, 1]
    );
    console.log('✅ Админ Aries создан');
  }

  const admin2 = await db.get('SELECT * FROM users WHERE username = ?', ['Aneba']);
  if (!admin2) {
    const hash = await bcrypt.hash('admin', 10);
    await db.run(
      'INSERT INTO users (username, password, balance, is_admin) VALUES (?, ?, ?, ?)',
      ['Aneba', hash, 10000, 1]
    );
    console.log('✅ Админ Aneba создан');
  }

  console.log('✅ База данных подключена');
}

// ===== СТРАНИЦЫ =====

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Страница логина
app.get('/login', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>Вход в админку</title>
        <style>
            body {
                background: #0f0f0f;
                color: #fff;
                font-family: Arial;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
                margin: 0;
            }
            .login-form {
                background: #1a1a1a;
                padding: 40px;
                border-radius: 16px;
                border: 1px solid #333;
                width: 300px;
            }
            h1 {
                color: gold;
                text-align: center;
                margin-bottom: 30px;
            }
            input {
                width: 100%;
                padding: 12px;
                margin: 10px 0;
                background: #252525;
                border: 1px solid #333;
                border-radius: 6px;
                color: #fff;
            }
            button {
                width: 100%;
                padding: 12px;
                background: gold;
                border: none;
                border-radius: 6px;
                font-weight: bold;
                cursor: pointer;
                margin-top: 20px;
            }
            .error {
                color: #f44336;
                text-align: center;
                margin-top: 10px;
            }
        </style>
    </head>
    <body>
        <div class="login-form">
            <h1>👑 Вход в админку</h1>
            <form onsubmit="login(event)">
                <input type="text" id="username" placeholder="Логин" required>
                <input type="password" id="password" placeholder="Пароль" required>
                <button type="submit">Войти</button>
                <div id="error" class="error"></div>
            </form>
        </div>
        
        <script>
            async function login(event) {
                event.preventDefault();
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                const res = await fetch('/api/admin/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({username, password})
                });
                
                if (res.ok) {
                    window.location.href = '/admin';
                } else {
                    document.getElementById('error').textContent = 'Неверный логин или пароль';
                }
            }
        </script>
    </body>
    </html>
  `);
});

// Админка (защищенная)
app.get('/admin', async (req, res) => {
  const token = req.cookies.admin_token;
  
  if (!token) {
    return res.redirect('/login');
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const user = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!user || !user.is_admin) {
      return res.redirect('/login');
    }
    
    res.sendFile(path.join(__dirname, 'admin', 'index.html'));
  } catch {
    res.redirect('/login');
  }
});

// ===== API АВТОРИЗАЦИЯ =====

// Логин
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  
  if (!user) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  
  const valid = await bcrypt.compare(password, user.password);
  
  if (!valid) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  
  if (!user.is_admin) {
    return res.status(403).json({ error: 'Недостаточно прав' });
  }
  
  const token = jwt.sign(
    { id: user.id, username: user.username },
    process.env.JWT_SECRET || 'secret-key',
    { expiresIn: '7d' }
  );
  
  res.cookie('admin_token', token, {
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
  
  res.json({ success: true });
});

// Выход
app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_token');
  res.json({ success: true });
});

// Проверка админа
app.get('/api/admin/check', async (req, res) => {
  const token = req.cookies.admin_token;
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const user = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!user || !user.is_admin) {
      return res.status(403).json({ error: 'Not admin' });
    }
    
    res.json({ 
      success: true, 
      user: {
        id: user.id,
        username: user.username
      }
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== API ПОЛЬЗОВАТЕЛИ =====

// Получить или создать пользователя
app.post('/api/user', async (req, res) => {
  const { username } = req.body;
  const ip = req.ip;

  let user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
  
  if (!user) {
    const result = await db.run(
      'INSERT INTO users (username, ip_address) VALUES (?, ?)',
      [username, ip]
    );
    user = await db.get('SELECT * FROM users WHERE id = ?', [result.lastID]);
  }

  await db.run('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

  res.json({
    id: user.id,
    username: user.username,
    balance: user.balance,
    is_premium: Boolean(user.is_premium),
    is_admin: Boolean(user.is_admin)
  });
});

// Получить всех пользователей (для админки)
app.get('/api/users', async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const users = await db.all('SELECT id, username, balance, total_games, total_wins, is_premium, is_admin FROM users ORDER BY balance DESC');
    res.json(users);
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Выдать баланс (админка)
app.post('/api/users/:id/balance', async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const { id } = req.params;
    const { amount } = req.body;

    await db.run('UPDATE users SET balance = balance + ? WHERE id = ?', [amount, id]);
    await db.run(
      'INSERT INTO transactions (user_id, amount, type) VALUES (?, ?, ?)',
      [id, amount, 'admin']
    );

    const user = await db.get('SELECT * FROM users WHERE id = ?', [id]);
    res.json({ success: true, new_balance: user.balance });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== API КЕЙСЫ =====

// Получить все кейсы (публичное)
app.get('/api/cases', async (req, res) => {
  const cases = await db.all('SELECT * FROM cases WHERE is_active = 1 ORDER BY sort_order');
  
  for (let c of cases) {
    const items = await db.all('SELECT * FROM case_items WHERE case_id = ?', [c.id]);
    c.items_count = items.length;
  }
  
  res.json({ cases });
});

// Создать кейс (админка)
app.post('/api/cases', upload.single('image'), async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const { name, description, price } = req.body;
    const image_url = req.file ? `/uploads/cases/${req.file.filename}` : null;

    const result = await db.run(
      'INSERT INTO cases (name, description, price, image_url) VALUES (?, ?, ?, ?)',
      [name, description, price, image_url]
    );

    res.json({ success: true, case_id: result.lastID });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Удалить кейс (админка)
app.delete('/api/cases/:id', async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await db.run('DELETE FROM cases WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Получить предметы кейса (админка)
app.get('/api/cases/:id/items', async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const items = await db.all('SELECT * FROM case_items WHERE case_id = ?', [req.params.id]);
    res.json({ items });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Добавить предмет в кейс (админка)
app.post('/api/cases/:id/items', upload.single('image'), async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    const case_id = req.params.id;
    const { name, value, probability } = req.body;
    const image_url = req.file ? `/uploads/items/${req.file.filename}` : null;

    // Проверяем сумму вероятностей
    const items = await db.all('SELECT * FROM case_items WHERE case_id = ?', [case_id]);
    const totalProb = items.reduce((sum, item) => sum + item.probability, 0);
    
    if (totalProb + parseFloat(probability) > 100) {
      return res.status(400).json({ error: 'Сумма вероятностей не может превышать 100%' });
    }

    const result = await db.run(
      'INSERT INTO case_items (case_id, name, image_url, value, probability) VALUES (?, ?, ?, ?, ?)',
      [case_id, name, image_url, value, probability]
    );

    res.json({ success: true, item_id: result.lastID });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// Удалить предмет (админка)
app.delete('/api/items/:id', async (req, res) => {
  // Проверяем авторизацию
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret-key');
    const admin = await db.get('SELECT * FROM users WHERE id = ?', [decoded.id]);
    
    if (!admin || !admin.is_admin) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    
    await db.run('DELETE FROM case_items WHERE id = ?', [req.params.id]);
    res.json({ success: true });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== ОТКРЫТИЕ КЕЙСОВ =====

// Открыть кейс
app.post('/api/cases/:id/open', async (req, res) => {
  const case_id = req.params.id;
  const { user_id } = req.body;

  // Получаем пользователя
  const user = await db.get('SELECT * FROM users WHERE id = ?', [user_id]);
  if (!user) return res.status(404).json({ error: 'User not found' });

  // Получаем кейс
  const caseData = await db.get('SELECT * FROM cases WHERE id = ? AND is_active = 1', [case_id]);
  if (!caseData) return res.status(404).json({ error: 'Case not found' });

  // Получаем предметы
  const items = await db.all('SELECT * FROM case_items WHERE case_id = ?', [case_id]);
  if (!items.length) return res.status(400).json({ error: 'Case is empty' });

  // Проверяем баланс
  if (user.balance < caseData.price) {
    return res.status(400).json({ error: 'Insufficient balance' });
  }

  // Выбираем предмет по вероятности
  const totalProb = items.reduce((sum, item) => sum + item.probability, 0);
  let rand = Math.random() * totalProb;
  let selectedItem = items[0];
  let cumulative = 0;

  for (const item of items) {
    cumulative += item.probability;
    if (rand <= cumulative) {
      selectedItem = item;
      break;
    }
  }

  // Обновляем баланс
  await db.run('UPDATE users SET balance = balance - ? WHERE id = ?', [caseData.price, user_id]);
  await db.run('UPDATE users SET balance = balance + ?, total_games = total_games + 1, total_wins = total_wins + 1 WHERE id = ?', 
    [selectedItem.value, user_id]);

  // Записываем открытие
  await db.run(
    'INSERT INTO case_openings (user_id, case_id, item_id, win_amount) VALUES (?, ?, ?, ?)',
    [user_id, case_id, selectedItem.id, selectedItem.value]
  );

  // Получаем новый баланс
  const updatedUser = await db.get('SELECT * FROM users WHERE id = ?', [user_id]);

  res.json({
    success: true,
    item: {
      id: selectedItem.id,
      name: selectedItem.name,
      image_url: selectedItem.image_url,
      value: selectedItem.value
    },
    win_amount: selectedItem.value,
    new_balance: updatedUser.balance
  });
});

// Последние открытия
app.get('/api/recent-openings', async (req, res) => {
  const openings = await db.all(`
    SELECT 
      u.username, 
      c.name as case_name, 
      ci.name as item_name, 
      co.win_amount 
    FROM case_openings co
    JOIN users u ON u.id = co.user_id
    JOIN cases c ON c.id = co.case_id
    JOIN case_items ci ON ci.id = co.item_id
    WHERE co.is_test = 0
    ORDER BY co.created_at DESC
    LIMIT 10
  `);

  res.json({ openings });
});

// ===== ЗАПУСК =====

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Сервер запущен на порту ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`👑 Админка: http://localhost:${PORT}/login`);
    console.log(`   Логин: Aries / cheesecakes`);
    console.log(`   Логин: Aneba / admin`);
  });
});
