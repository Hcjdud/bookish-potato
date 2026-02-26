const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const cors = require('cors');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'gifts-battle-secret-key-2024';

// ===== ПОДКЛЮЧЕНИЕ К POSTGRESQL =====
const pool = new Pool({
  connectionString: 'postgresql://gifts_db_i4ig_user:pDtsgu5KrXJnReT2zW2zFxzAWd0XF57L@dpg-d6fvlha4d50c73dfc1n0-a/gifts_db_i4ig',
  ssl: {
    rejectUnauthorized: false
  }
});

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Слишком много запросов, попробуйте позже'
});

// Middleware
app.use(limiter);
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Статические файлы
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// Создаем папки для загрузок
const fs = require('fs');
const dirs = ['uploads', 'uploads/cases', 'uploads/items', 'uploads/avatars'];
dirs.forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

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
const upload = multer({ 
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) {
      return cb(null, true);
    }
    cb(new Error('Только изображения разрешены'));
  }
});

// ===== ИНИЦИАЛИЗАЦИЯ БАЗЫ ДАННЫХ =====
async function initDB() {
  try {
    // Проверяем подключение
    await pool.query('SELECT NOW()');
    console.log('✅ PostgreSQL подключен');

    // Создаем таблицы
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255),
        email VARCHAR(255) UNIQUE,
        avatar TEXT,
        balance DECIMAL DEFAULT 0,
        total_deposited DECIMAL DEFAULT 0,
        total_withdrawn DECIMAL DEFAULT 0,
        total_games INTEGER DEFAULT 0,
        total_wins INTEGER DEFAULT 0,
        win_rate DECIMAL DEFAULT 0,
        is_premium BOOLEAN DEFAULT FALSE,
        premium_until TIMESTAMP,
        is_admin BOOLEAN DEFAULT FALSE,
        is_banned BOOLEAN DEFAULT FALSE,
        ban_reason TEXT,
        ip_address TEXT,
        fingerprint TEXT,
        device_info TEXT,
        referrer_id INTEGER REFERENCES users(id),
        referrer_code TEXT UNIQUE,
        referral_count INTEGER DEFAULT 0,
        referral_earnings DECIMAL DEFAULT 0,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        settings JSONB DEFAULT '{"theme":"dark","notifications":true}'
      );

      CREATE TABLE IF NOT EXISTS sessions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token TEXT UNIQUE,
        ip_address TEXT,
        user_agent TEXT,
        expires_at TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS cases (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        price DECIMAL NOT NULL,
        image_url TEXT,
        background_color VARCHAR(50) DEFAULT '#1a1a1a',
        is_active BOOLEAN DEFAULT TRUE,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS case_items (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        image_url TEXT,
        value DECIMAL NOT NULL,
        probability DECIMAL NOT NULL,
        rarity VARCHAR(50) DEFAULT 'common',
        color VARCHAR(50) DEFAULT '#ffffff',
        min_win DECIMAL,
        max_win DECIMAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS case_openings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        item_id INTEGER REFERENCES case_items(id) ON DELETE CASCADE,
        win_amount DECIMAL NOT NULL,
        is_test BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS games (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        image_url TEXT,
        min_bet DECIMAL DEFAULT 1,
        max_bet DECIMAL DEFAULT 1000,
        is_active BOOLEAN DEFAULT TRUE,
        sort_order INTEGER DEFAULT 0
      );

      CREATE TABLE IF NOT EXISTS game_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        game_type VARCHAR(50) NOT NULL,
        bet_amount DECIMAL NOT NULL,
        win_amount DECIMAL NOT NULL,
        multiplier DECIMAL,
        result JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL NOT NULL,
        type VARCHAR(50) NOT NULL,
        method VARCHAR(50),
        status VARCHAR(50) DEFAULT 'completed',
        tx_hash TEXT UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS deposits (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL NOT NULL,
        method VARCHAR(50) NOT NULL,
        stars_amount INTEGER,
        gift_type VARCHAR(50),
        status VARCHAR(50) DEFAULT 'pending',
        tx_hash TEXT UNIQUE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        referrer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        referred_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        ip_address TEXT,
        fingerprint TEXT,
        reward_amount DECIMAL DEFAULT 0,
        claimed BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS admin_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        action VARCHAR(255) NOT NULL,
        target_type VARCHAR(50),
        target_id INTEGER,
        details JSONB,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS banned_ips (
        id SERIAL PRIMARY KEY,
        ip_address VARCHAR(255) UNIQUE NOT NULL,
        reason TEXT,
        banned_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Таблицы созданы');

    // Создаем тестовые игры если их нет
    const gamesResult = await pool.query('SELECT COUNT(*) FROM games');
    if (parseInt(gamesResult.rows[0].count) === 0) {
      await pool.query(
        `INSERT INTO games (name, description, image_url, min_bet, max_bet, sort_order) VALUES 
         ($1, $2, $3, $4, $5, $6),
         ($7, $8, $9, $10, $11, $12),
         ($13, $14, $15, $16, $17, $18)`,
        [
          'Кейсы', 'Открывай кейсы и выигрывай', '/games/cases.png', 1, 10000, 1,
          'Ракетка', 'Лови момент и забирай', '/games/rocket.png', 1, 1000, 2,
          'Rolls', 'Угадай цвет и умножай', '/games/rolls.png', 1, 500, 3
        ]
      );
    }

    // Создаем тестовые кейсы если их нет
    const casesResult = await pool.query('SELECT COUNT(*) FROM cases');
    if (parseInt(casesResult.rows[0].count) === 0) {
      await pool.query(
        `INSERT INTO cases (name, description, price, image_url, sort_order) VALUES 
         ($1, $2, $3, $4, $5),
         ($6, $7, $8, $9, $10),
         ($11, $12, $13, $14, $15),
         ($16, $17, $18, $19, $20)`,
        [
          'Обычный кейс', 'Шанс на выигрыш до 100 ⭐', 10, '/cases/common.png', 1,
          'Редкий кейс', 'Шанс на выигрыш до 500 ⭐', 50, '/cases/rare.png', 2,
          'Эпический кейс', 'Шанс на выигрыш до 2000 ⭐', 200, '/cases/epic.png', 3,
          'Легендарный кейс', 'Шанс на выигрыш до 10000 ⭐', 1000, '/cases/legendary.png', 4
        ]
      );

      // Добавляем предметы для кейсов
      const cases = await pool.query('SELECT id FROM cases ORDER BY id');
      
      // Для обычного кейса
      await pool.query(
        `INSERT INTO case_items (case_id, name, value, probability, rarity) VALUES 
         ($1, $2, $3, $4, $5),
         ($1, $6, $7, $8, $9),
         ($1, $10, $11, $12, $13)`,
        [cases.rows[0].id, 'Обычный предмет', 5, 50, 'common', 'Редкий предмет', 20, 30, 'rare', 'Эпический предмет', 50, 20, 'epic']
      );

      // Для редкого кейса
      await pool.query(
        `INSERT INTO case_items (case_id, name, value, probability, rarity) VALUES 
         ($1, $2, $3, $4, $5),
         ($1, $6, $7, $8, $9),
         ($1, $10, $11, $12, $13)`,
        [cases.rows[1].id, 'Редкий предмет', 30, 50, 'rare', 'Эпический предмет', 100, 30, 'epic', 'Легендарный предмет', 300, 20, 'legendary']
      );

      // Для эпического кейса
      await pool.query(
        `INSERT INTO case_items (case_id, name, value, probability, rarity) VALUES 
         ($1, $2, $3, $4, $5),
         ($1, $6, $7, $8, $9),
         ($1, $10, $11, $12, $13)`,
        [cases.rows[2].id, 'Эпический предмет', 150, 50, 'epic', 'Легендарный предмет', 500, 30, 'legendary', 'Мифический предмет', 1500, 20, 'mythic']
      );

      // Для легендарного кейса
      await pool.query(
        `INSERT INTO case_items (case_id, name, value, probability, rarity) VALUES 
         ($1, $2, $3, $4, $5),
         ($1, $6, $7, $8, $9),
         ($1, $10, $11, $12, $13)`,
        [cases.rows[3].id, 'Легендарный предмет', 800, 50, 'legendary', 'Мифический предмет', 2500, 30, 'mythic', 'Божественный предмет', 8000, 20, 'divine']
      );
    }

    // Создаем админов (с балансом 1,000,000)
    const admins = [
      { username: 'Aries', password: 'cheesecakes' },
      { username: 'Aneba', password: 'admin' }
    ];

    for (const admin of admins) {
      const existing = await pool.query('SELECT * FROM users WHERE username = $1', [admin.username]);
      
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(admin.password, 10);
        const referrerCode = 'ADMIN' + Math.random().toString(36).substring(2, 10).toUpperCase();
        
        await pool.query(
          `INSERT INTO users (username, password, balance, is_admin, is_premium, referrer_code, settings) 
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [admin.username, hash, 1000000, true, true, referrerCode, JSON.stringify({theme: 'dark', notifications: true})]
        );
        console.log(`✅ Админ ${admin.username} создан (баланс: 1,000,000 ⭐)`);
      } else {
        // Обновляем баланс админа если нужно
        await pool.query(
          'UPDATE users SET balance = 1000000 WHERE username = $1',
          [admin.username]
        );
      }
    }

  } catch (error) {
    console.error('❌ Ошибка инициализации БД:', error);
  }
}

// ===== МИДЛВАРЫ =====

// Получение или создание пользователя по fingerprint
async function getOrCreateUser(req, res, next) {
  const fingerprint = req.headers['x-fingerprint'] || req.query.fingerprint || req.body.fingerprint || 'unknown';
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  
  try {
    // Ищем пользователя по fingerprint
    let userResult = await pool.query(
      'SELECT * FROM users WHERE fingerprint = $1',
      [fingerprint]
    );
    
    let user = userResult.rows[0];
    
    // Если не нашли, создаем нового
    if (!user) {
      const username = 'user_' + Math.random().toString(36).substring(2, 10);
      const referrerCode = 'GB' + Math.random().toString(36).substring(2, 10).toUpperCase();
      
      const newUserResult = await pool.query(
        `INSERT INTO users (username, fingerprint, ip_address, device_info, referrer_code, settings, balance) 
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
        [username, fingerprint, ip, userAgent, referrerCode, JSON.stringify({theme: 'dark', notifications: true}), 0]
      );
      
      user = newUserResult.rows[0];
      console.log(`✅ Новый пользователь создан: ${username} (баланс: 0 ⭐)`);
    } else {
      // Обновляем last_seen
      await pool.query(
        'UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = $1',
        [user.id]
      );
    }
    
    req.user = user;
    next();
  } catch (error) {
    console.error('Ошибка в getOrCreateUser:', error);
    next();
  }
}

// ===== СТРАНИЦЫ =====

// Главная страница
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Админка
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// ===== API =====

// Получение текущего пользователя (авторегистрация)
app.get('/api/user', getOrCreateUser, async (req, res) => {
  try {
    res.json({
      id: req.user.id,
      username: req.user.username,
      balance: parseFloat(req.user.balance),
      is_premium: req.user.is_premium,
      is_admin: req.user.is_admin,
      settings: req.user.settings,
      fingerprint: req.user.fingerprint
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение всех кейсов
app.get('/api/cases', async (req, res) => {
  try {
    const casesResult = await pool.query(
      'SELECT * FROM cases WHERE is_active = true ORDER BY sort_order'
    );
    
    const cases = [];
    for (const c of casesResult.rows) {
      const itemsResult = await pool.query(
        'SELECT COUNT(*) as count FROM case_items WHERE case_id = $1',
        [c.id]
      );
      
      cases.push({
        id: c.id,
        name: c.name,
        description: c.description,
        price: parseFloat(c.price),
        image_url: c.image_url,
        background_color: c.background_color,
        items_count: parseInt(itemsResult.rows[0].count)
      });
    }
    
    res.json({ cases });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Открытие кейса
app.post('/api/cases/:id/open', getOrCreateUser, async (req, res) => {
  const case_id = req.params.id;
  const user_id = req.user.id;
  
  try {
    // Получаем пользователя
    const userResult = await pool.query('SELECT * FROM users WHERE id = $1', [user_id]);
    const user = userResult.rows[0];
    
    // Получаем кейс
    const caseResult = await pool.query(
      'SELECT * FROM cases WHERE id = $1 AND is_active = true',
      [case_id]
    );
    const caseData = caseResult.rows[0];
    
    if (!caseData) {
      return res.status(404).json({ error: 'Кейс не найден' });
    }
    
    // Получаем предметы
    const itemsResult = await pool.query(
      'SELECT * FROM case_items WHERE case_id = $1',
      [case_id]
    );
    const items = itemsResult.rows;
    
    if (items.length === 0) {
      return res.status(400).json({ error: 'Кейс пуст' });
    }
    
    // Проверяем баланс
    if (parseFloat(user.balance) < parseFloat(caseData.price)) {
      return res.status(400).json({ error: 'Недостаточно средств' });
    }
    
    // Выбираем предмет по вероятности
    const totalProb = items.reduce((sum, item) => sum + parseFloat(item.probability), 0);
    let rand = Math.random() * totalProb;
    let selectedItem = items[0];
    let cumulative = 0;
    
    for (const item of items) {
      cumulative += parseFloat(item.probability);
      if (rand <= cumulative) {
        selectedItem = item;
        break;
      }
    }
    
    // Определяем выигрыш
    let winAmount = parseFloat(selectedItem.value);
    
    // Обновляем баланс
    await pool.query(
      'UPDATE users SET balance = balance - $1, total_games = total_games + 1 WHERE id = $2',
      [caseData.price, user_id]
    );
    
    await pool.query(
      'UPDATE users SET balance = balance + $1 WHERE id = $2',
      [winAmount, user_id]
    );
    
    if (winAmount > caseData.price) {
      await pool.query(
        'UPDATE users SET total_wins = total_wins + 1 WHERE id = $1',
        [user_id]
      );
    }
    
    // Обновляем win_rate
    await pool.query(`
      UPDATE users 
      SET win_rate = (total_wins::float / NULLIF(total_games, 0)) * 100 
      WHERE id = $1
    `, [user_id]);
    
    // Записываем открытие
    await pool.query(
      `INSERT INTO case_openings (user_id, case_id, item_id, win_amount) 
       VALUES ($1, $2, $3, $4)`,
      [user_id, case_id, selectedItem.id, winAmount]
    );
    
    // Получаем обновленного пользователя
    const updatedUserResult = await pool.query('SELECT * FROM users WHERE id = $1', [user_id]);
    const updatedUser = updatedUserResult.rows[0];
    
    res.json({
      success: true,
      item: {
        id: selectedItem.id,
        name: selectedItem.name,
        description: selectedItem.description,
        image_url: selectedItem.image_url,
        value: winAmount,
        rarity: selectedItem.rarity,
        color: selectedItem.color
      },
      win_amount: winAmount,
      new_balance: parseFloat(updatedUser.balance)
    });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Последние открытия
app.get('/api/recent-openings', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        u.username,
        c.name as case_name,
        ci.name as item_name,
        ci.rarity,
        ci.color,
        co.win_amount,
        co.created_at
      FROM case_openings co
      JOIN users u ON u.id = co.user_id
      JOIN cases c ON c.id = co.case_id
      JOIN case_items ci ON ci.id = co.item_id
      WHERE co.is_test = false
      ORDER BY co.created_at DESC
      LIMIT 20
    `);
    
    res.json({ openings: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Логин админа
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1 AND is_admin = true', [username]);
    const admin = result.rows[0];
    
    if (!admin) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    
    const valid = await bcrypt.compare(password, admin.password);
    
    if (!valid) {
      return res.status(401).json({ error: 'Неверный логин или пароль' });
    }
    
    const token = jwt.sign(
      { id: admin.id, username: admin.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    
    res.cookie('admin_token', token, {
      httpOnly: true,
      maxAge: 7 * 24 * 60 * 60 * 1000,
      sameSite: 'strict'
    });
    
    res.json({ success: true });
    
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Проверка админа
app.get('/api/admin/check', async (req, res) => {
  const token = req.cookies.admin_token;
  
  if (!token) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const result = await pool.query('SELECT * FROM users WHERE id = $1 AND is_admin = true', [decoded.id]);
    const admin = result.rows[0];
    
    if (!admin) {
      return res.status(403).json({ error: 'Not admin' });
    }
    
    res.json({ 
      success: true, 
      admin: {
        id: admin.id,
        username: admin.username
      }
    });
  } catch {
    res.status(401).json({ error: 'Invalid token' });
  }
});

// ===== АДМИНКА API =====

// Получение статистики
app.get('/api/admin/stats', async (req, res) => {
  try {
    const usersCount = await pool.query('SELECT COUNT(*) FROM users');
    const activeToday = await pool.query(`
      SELECT COUNT(*) FROM users 
      WHERE last_seen > NOW() - INTERVAL '1 day'
    `);
    const totalBalance = await pool.query('SELECT COALESCE(SUM(balance), 0) FROM users');
    const openingsToday = await pool.query(`
      SELECT COUNT(*) FROM case_openings 
      WHERE created_at > NOW() - INTERVAL '1 day'
    `);
    
    res.json({
      total_users: parseInt(usersCount.rows[0].count),
      active_today: parseInt(activeToday.rows[0].count),
      total_balance: parseFloat(totalBalance.rows[0].sum),
      openings_today: parseInt(openingsToday.rows[0].count)
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение всех пользователей
app.get('/api/admin/users', async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT id, username, balance, total_games, total_wins, 
             is_premium, is_admin, is_banned, created_at, last_seen
      FROM users ORDER BY id DESC
    `);
    res.json({ users: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение всех кейсов (для админки)
app.get('/api/admin/cases', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM cases ORDER BY id');
    res.json({ cases: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Создание кейса
app.post('/api/admin/cases', upload.single('image'), async (req, res) => {
  const { name, description, price, background_color, sort_order } = req.body;
  const image_url = req.file ? `/uploads/cases/${req.file.filename}` : null;
  
  try {
    const result = await pool.query(
      `INSERT INTO cases (name, description, price, image_url, background_color, sort_order) 
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [name, description, price, image_url, background_color || '#1a1a1a', sort_order || 0]
    );
    
    res.json({ success: true, case_id: result.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка создания кейса' });
  }
});

// Получение предметов кейса
app.get('/api/admin/cases/:id/items', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM case_items WHERE case_id = $1 ORDER BY probability DESC',
      [req.params.id]
    );
    res.json({ items: result.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Добавление предмета
app.post('/api/admin/cases/:id/items', upload.single('image'), async (req, res) => {
  const case_id = req.params.id;
  const { name, description, value, probability, rarity, color, min_win, max_win } = req.body;
  const image_url = req.file ? `/uploads/items/${req.file.filename}` : null;
  
  try {
    // Проверка суммы вероятностей
    const itemsResult = await pool.query(
      'SELECT COALESCE(SUM(probability), 0) as total FROM case_items WHERE case_id = $1',
      [case_id]
    );
    const totalProb = parseFloat(itemsResult.rows[0].total);
    
    if (totalProb + parseFloat(probability) > 100) {
      return res.status(400).json({ error: 'Сумма вероятностей не может превышать 100%' });
    }
    
    const result = await pool.query(
      `INSERT INTO case_items (case_id, name, description, image_url, value, probability, rarity, color, min_win, max_win) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id`,
      [case_id, name, description, image_url, value, probability, rarity, color, min_win, max_win]
    );
    
    res.json({ success: true, item_id: result.rows[0].id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка добавления предмета' });
  }
});

// Удаление предмета
app.delete('/api/admin/items/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM case_items WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка удаления' });
  }
});

// Удаление кейса
app.delete('/api/admin/cases/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM cases WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка удаления' });
  }
});

// Выдача баланса пользователю
app.post('/api/admin/users/:id/balance', async (req, res) => {
  const { id } = req.params;
  const { amount } = req.body;
  
  try {
    await pool.query(
      'UPDATE users SET balance = balance + $1 WHERE id = $2',
      [amount, id]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка' });
  }
});

// ===== ЗАПУСК =====

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Сервер запущен на порту ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`👑 Админка: http://localhost:${PORT}/admin`);
    console.log(`   Логин: Aries / cheesecakes`);
    console.log(`   Логин: Aneba / admin`);
    console.log(`💰 Баланс новых пользователей: 0 ⭐`);
    console.log(`💰 Баланс админов: 1,000,000 ⭐`);
  });
});
