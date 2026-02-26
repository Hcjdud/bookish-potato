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
        telegram_id BIGINT UNIQUE,
        username VARCHAR(255) UNIQUE,
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        photo_url TEXT,
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
        fingerprint TEXT UNIQUE,
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

      CREATE TABLE IF NOT EXISTS game_sessions (
        id SERIAL PRIMARY KEY,
        game_type VARCHAR(50) NOT NULL,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        session_id VARCHAR(255) UNIQUE,
        bet_amount DECIMAL,
        status VARCHAR(50) DEFAULT 'active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    // Создаем админов
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
        console.log(`✅ Админ ${admin.username} создан`);
      }
    }

  } catch (error) {
    console.error('❌ Ошибка инициализации БД:', error);
  }
}

// ===== МИДЛВАРЫ =====

// Получение или создание пользователя
async function getOrCreateUser(req, res, next) {
  const { telegram_id, username, first_name, last_name, photo_url } = req.body;
  const fingerprint = req.headers['x-fingerprint'] || req.query.fingerprint || 'unknown';
  const ip = req.ip || req.connection.remoteAddress;
  const userAgent = req.headers['user-agent'];
  
  try {
    let user;
    
    // Ищем по telegram_id если есть
    if (telegram_id) {
      const result = await pool.query('SELECT * FROM users WHERE telegram_id = $1', [telegram_id]);
      user = result.rows[0];
    }
    
    // Ищем по fingerprint если нет telegram_id
    if (!user) {
      const result = await pool.query('SELECT * FROM users WHERE fingerprint = $1', [fingerprint]);
      user = result.rows[0];
    }
    
    // Если не нашли, создаем нового
    if (!user) {
      const newUsername = username || 'user_' + Math.random().toString(36).substring(2, 10);
      const referrerCode = 'GB' + Math.random().toString(36).substring(2, 10).toUpperCase();
      
      const newUserResult = await pool.query(
        `INSERT INTO users (telegram_id, username, first_name, last_name, photo_url, fingerprint, ip_address, device_info, referrer_code, settings, balance) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
        [telegram_id, newUsername, first_name, last_name, photo_url, fingerprint, ip, userAgent, referrerCode, JSON.stringify({theme: 'dark', notifications: true}), 0]
      );
      
      user = newUserResult.rows[0];
      console.log(`✅ Новый пользователь создан: ${newUsername}`);
    } else {
      // Обновляем данные Telegram если изменились
      if (telegram_id && (!user.telegram_id || user.telegram_id !== telegram_id)) {
        await pool.query(
          'UPDATE users SET telegram_id = $1, first_name = $2, last_name = $3, photo_url = $4 WHERE id = $5',
          [telegram_id, first_name, last_name, photo_url, user.id]
        );
      }
      
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

// ===== API =====

// Получение текущего пользователя
app.post('/api/user', getOrCreateUser, async (req, res) => {
  try {
    res.json({
      id: req.user.id,
      telegram_id: req.user.telegram_id,
      username: req.user.username,
      first_name: req.user.first_name,
      last_name: req.user.last_name,
      photo_url: req.user.photo_url,
      balance: parseFloat(req.user.balance),
      is_premium: req.user.is_premium,
      is_admin: req.user.is_admin,
      settings: req.user.settings
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение статистики пользователя
app.get('/api/user/stats', async (req, res) => {
  const { user_id } = req.query;
  
  try {
    const stats = await pool.query(`
      SELECT 
        total_games,
        total_wins,
        win_rate,
        referral_count,
        created_at
      FROM users WHERE id = $1
    `, [user_id]);
    
    res.json(stats.rows[0] || { total_games: 0, total_wins: 0, win_rate: 0 });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== REAL-TIME СТАТИСТИКА =====

// Получение количества игроков в играх
app.get('/api/games/players', async (req, res) => {
  try {
    // Подсчитываем активные сессии за последние 5 минут
    const fiveMinAgo = new Date(Date.now() - 5 * 60 * 1000).toISOString();
    
    const casesPlayers = await pool.query(`
      SELECT COUNT(DISTINCT user_id) as count 
      FROM game_sessions 
      WHERE game_type = 'cases' AND updated_at > $1
    `, [fiveMinAgo]);
    
    const rocketPlayers = await pool.query(`
      SELECT COUNT(DISTINCT user_id) as count 
      FROM game_sessions 
      WHERE game_type = 'rocket' AND updated_at > $1
    `, [fiveMinAgo]);
    
    const rollsPlayers = await pool.query(`
      SELECT COUNT(DISTINCT user_id) as count 
      FROM game_sessions 
      WHERE game_type = 'rolls' AND updated_at > $1
    `, [fiveMinAgo]);
    
    res.json({
      cases: parseInt(casesPlayers.rows[0].count) || 127,
      rocket: parseInt(rocketPlayers.rows[0].count) || 234,
      rolls: parseInt(rollsPlayers.rows[0].count) || 89
    });
  } catch (error) {
    console.error(error);
    // Возвращаем тестовые данные при ошибке
    res.json({
      cases: 127,
      rocket: 234,
      rolls: 89
    });
  }
});

// Обновление игровой сессии
app.post('/api/games/session', async (req, res) => {
  const { user_id, game_type, session_id } = req.body;
  
  try {
    // Проверяем существующую сессию
    const existing = await pool.query(
      'SELECT * FROM game_sessions WHERE user_id = $1 AND game_type = $2',
      [user_id, game_type]
    );
    
    if (existing.rows.length > 0) {
      // Обновляем существующую
      await pool.query(
        'UPDATE game_sessions SET updated_at = CURRENT_TIMESTAMP WHERE id = $1',
        [existing.rows[0].id]
      );
    } else {
      // Создаем новую
      await pool.query(
        'INSERT INTO game_sessions (user_id, game_type, session_id) VALUES ($1, $2, $3)',
        [user_id, game_type, session_id || uuidv4()]
      );
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error(error);
    res.json({ success: true }); // Не блокируем игру при ошибке
  }
});

// ===== ТОП ИГРОКОВ =====
app.get('/api/leaderboard', async (req, res) => {
  try {
    // Топ по балансу - исключаем админов
    const byBalance = await pool.query(`
      SELECT username, balance, total_games, total_wins 
      FROM users 
      WHERE is_admin = false AND is_banned = false
      ORDER BY balance DESC 
      LIMIT 10
    `);
    
    res.json({ by_balance: byBalance.rows });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== КЕЙСЫ =====
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
app.post('/api/cases/:id/open', async (req, res) => {
  const case_id = req.params.id;
  const { user_id } = req.body;
  
  if (!user_id) {
    return res.status(400).json({ error: 'User ID required' });
  }
  
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
    
    // Обновляем игровую сессию
    await pool.query(
      `INSERT INTO game_sessions (user_id, game_type, session_id, updated_at) 
       VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
       ON CONFLICT (user_id, game_type) DO UPDATE SET updated_at = CURRENT_TIMESTAMP`,
      [user_id, 'cases', uuidv4()]
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

// ===== АДМИНКА API =====

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

// Получение статистики
app.get('/api/admin/stats', async (req, res) => {
  try {
    const usersCount = await pool.query('SELECT COUNT(*) FROM users WHERE is_admin = false');
    const activeToday = await pool.query(`
      SELECT COUNT(*) FROM users 
      WHERE last_seen > NOW() - INTERVAL '1 day' AND is_admin = false
    `);
    const totalBalance = await pool.query('SELECT COALESCE(SUM(balance), 0) FROM users WHERE is_admin = false');
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

// ===== ЗАПУСК =====

initDB().then(() => {
  app.listen(PORT, () => {
    console.log(`✅ Сервер запущен на порту ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`👑 Админка: http://localhost:${PORT}/admin`);
    console.log(`   Логин: Aries / cheesecakes`);
    console.log(`   Логин: Aneba / admin`);
  });
});
