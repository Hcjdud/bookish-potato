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
const compression = require('compression');
const helmet = require('helmet');
const http = require('http');
const { Server } = require('socket.io');
const axios = require('axios');
const { Telegraf } = require('telegraf');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'gifts-battle-secret-key-2024';
const BOT_TOKEN = process.env.BOT_TOKEN;
const TON_WALLET = process.env.TON_WALLET_ADDRESS;

// ===== ПОДКЛЮЧЕНИЕ К POSTGRESQL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// ===== МИДЛВАРЫ =====
app.use(compression());
app.use(helmet({
  contentSecurityPolicy: false,
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: 'Слишком много запросов, попробуйте позже'
});

app.use(limiter);
app.use(cors({
  origin: '*',
  credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Статические файлы
app.use(express.static('public', { maxAge: '1d' }));
app.use('/uploads', express.static('uploads', { maxAge: '7d' }));
app.use('/admin', express.static('admin'));

// Создаем папки
const fs = require('fs');
const dirs = ['uploads', 'uploads/cases', 'uploads/items', 'uploads/avatars', 'uploads/nft', 'uploads/screenshots'];
dirs.forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const type = req.params.type || 'cases';
    cb(null, `uploads/${type}`);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${uuidv4()}${ext}`);
  }
});

const upload = multer({ 
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif|webp/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Только изображения разрешены'));
  }
});

// ===== ИНИЦИАЛИЗАЦИЯ БД =====
async function initDB() {
  try {
    await pool.query('SELECT NOW()');
    console.log('✅ PostgreSQL подключен');

    // Создаем все таблицы
    await pool.query(`
      -- Пользователи
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        telegram_id BIGINT UNIQUE,
        username VARCHAR(255),
        first_name VARCHAR(255),
        last_name VARCHAR(255),
        photo_url TEXT,
        balance DECIMAL DEFAULT 0,
        gift_balance DECIMAL DEFAULT 0,
        total_games INTEGER DEFAULT 0,
        total_wins INTEGER DEFAULT 0,
        win_rate DECIMAL DEFAULT 0,
        is_premium BOOLEAN DEFAULT FALSE,
        premium_until TIMESTAMP,
        is_admin BOOLEAN DEFAULT FALSE,
        is_banned BOOLEAN DEFAULT FALSE,
        ip_address TEXT,
        fingerprint TEXT UNIQUE,
        referrer_id INTEGER REFERENCES users(id),
        referral_code TEXT UNIQUE,
        referral_count INTEGER DEFAULT 0,
        referral_earnings DECIMAL DEFAULT 0,
        notifications_enabled BOOLEAN DEFAULT TRUE,
        last_login TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        settings JSONB DEFAULT '{"theme":"dark","language":"ru"}'
      );

      -- Индексы
      CREATE INDEX IF NOT EXISTS idx_users_telegram ON users(telegram_id);
      CREATE INDEX IF NOT EXISTS idx_users_balance ON users(balance DESC);

      -- Активные игроки (РЕАЛЬНЫЕ)
      CREATE TABLE IF NOT EXISTS active_players (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        bet_amount DECIMAL,
        current_multiplier DECIMAL DEFAULT 1.0,
        status VARCHAR(50) DEFAULT 'waiting',
        socket_id VARCHAR(255),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- История игр (РЕАЛЬНАЯ)
      CREATE TABLE IF NOT EXISTS game_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        game_type VARCHAR(50),
        bet_amount DECIMAL,
        win_amount DECIMAL,
        multiplier DECIMAL,
        crashed_at DECIMAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Раунды краш-игры
      CREATE TABLE IF NOT EXISTS crash_rounds (
        id SERIAL PRIMARY KEY,
        round_id VARCHAR(50) UNIQUE,
        seed VARCHAR(255),
        hash VARCHAR(255),
        crash_point DECIMAL NOT NULL,
        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        end_time TIMESTAMP,
        status VARCHAR(50) DEFAULT 'waiting'
      );

      -- Ставки в раундах
      CREATE TABLE IF NOT EXISTS round_bets (
        id SERIAL PRIMARY KEY,
        round_id INTEGER REFERENCES crash_rounds(id) ON DELETE CASCADE,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        bet_amount DECIMAL NOT NULL,
        cashout_multiplier DECIMAL,
        win_amount DECIMAL,
        status VARCHAR(50) DEFAULT 'active'
      );

      -- Кейсы
      CREATE TABLE IF NOT EXISTS cases (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) UNIQUE NOT NULL,
        description TEXT,
        price DECIMAL NOT NULL,
        gift_price DECIMAL,
        image_url TEXT,
        background_color VARCHAR(50) DEFAULT '#1a1a1a',
        is_active BOOLEAN DEFAULT TRUE,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER REFERENCES users(id)
      );

      -- Предметы кейсов
      CREATE TABLE IF NOT EXISTS case_items (
        id SERIAL PRIMARY KEY,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        image_url TEXT,
        value DECIMAL NOT NULL,
        gift_value DECIMAL,
        probability DECIMAL NOT NULL,
        rarity VARCHAR(50) DEFAULT 'common',
        color VARCHAR(50) DEFAULT '#ffffff',
        is_nft BOOLEAN DEFAULT FALSE,
        min_win DECIMAL,
        max_win DECIMAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Инвентарь
      CREATE TABLE IF NOT EXISTS user_nft (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        item_id INTEGER REFERENCES case_items(id) ON DELETE CASCADE,
        case_id INTEGER REFERENCES cases(id),
        win_amount DECIMAL,
        rarity VARCHAR(50),
        is_equipped BOOLEAN DEFAULT FALSE,
        is_sold BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Открытия кейсов
      CREATE TABLE IF NOT EXISTS case_openings (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
        item_id INTEGER REFERENCES case_items(id) ON DELETE CASCADE,
        win_amount DECIMAL NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Покупки
      CREATE TABLE IF NOT EXISTS gift_purchases (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        username VARCHAR(255),
        photo_url TEXT,
        stars_amount INTEGER NOT NULL,
        gift_amount INTEGER NOT NULL,
        promo_code VARCHAR(50),
        screenshot_url TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        completed_at TIMESTAMP
      );

      -- Рефералы
      CREATE TABLE IF NOT EXISTS referrals (
        id SERIAL PRIMARY KEY,
        referrer_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        referred_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        reward_amount DECIMAL DEFAULT 25,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Транзакции
      CREATE TABLE IF NOT EXISTS transactions (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        amount DECIMAL,
        type VARCHAR(50),
        method VARCHAR(50),
        status VARCHAR(50) DEFAULT 'completed',
        tx_hash TEXT UNIQUE,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Промокоды
      CREATE TABLE IF NOT EXISTS promo_codes (
        id SERIAL PRIMARY KEY,
        code VARCHAR(50) UNIQUE NOT NULL,
        reward_amount INTEGER NOT NULL,
        max_uses INTEGER DEFAULT 1,
        uses_count INTEGER DEFAULT 0,
        expires_at TIMESTAMP,
        created_by INTEGER REFERENCES users(id),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Админ логи
      CREATE TABLE IF NOT EXISTS admin_logs (
        id SERIAL PRIMARY KEY,
        admin_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        action VARCHAR(255),
        target_type VARCHAR(50),
        target_id INTEGER,
        details JSONB,
        ip_address TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log('✅ Таблицы созданы');

    // Создаем админов
    const admins = [
      { username: 'Aries', password: 'cheesecakes' },
      { username: 'Aneba', password: 'admin' }
    ];

    for (const admin of admins) {
      const existing = await pool.query('SELECT * FROM users WHERE username = $1', [admin.username]);
      if (existing.rows.length === 0) {
        const hash = await bcrypt.hash(admin.password, 10);
        await pool.query(
          `INSERT INTO users (username, password, balance, is_admin, is_premium, referral_code, notifications_enabled) 
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [admin.username, hash, 0, true, true, `ADMIN_${admin.username}`, true]
        );
        console.log(`✅ Админ ${admin.username} создан`);
      }
    }

  } catch (error) {
    console.error('❌ Ошибка инициализации БД:', error);
  }
}

// ===== ФУНКЦИЯ ДЛЯ ГЕНЕРАЦИИ ЧЕСТНОГО КРАШ-ПОИНТА =====
function generateCrashPoint(seed) {
  // Используем криптографически безопасный генератор
  const hmac = crypto.createHmac('sha256', seed);
  const hash = hmac.digest('hex');
  
  // Берем первые 8 символов и конвертируем в число
  const n = parseInt(hash.substring(0, 8), 16) / Math.pow(2, 32);
  
  // Формула краш-поинта (честная математика)
  // Шанс краша на 1% при множителе 1.00x
  const crashPoint = Math.max(1.0, 1.0 / (1.0 - n));
  
  // Ограничиваем максимальный множитель до 10.0x
  return Math.min(10.0, parseFloat(crashPoint.toFixed(2)));
}

// ===== ГЕНЕРАЦИЯ НОВОГО РАУНДА =====
async function generateNewRound() {
  const roundId = uuidv4();
  const seed = crypto.randomBytes(32).toString('hex');
  const crashPoint = generateCrashPoint(seed);
  
  try {
    const result = await pool.query(
      `INSERT INTO crash_rounds (round_id, seed, hash, crash_point, status) 
       VALUES ($1, $2, $3, $4, 'waiting') RETURNING id`,
      [roundId, seed, crypto.createHash('sha256').update(seed).digest('hex'), crashPoint]
    );
    
    return {
      id: result.rows[0].id,
      roundId,
      crashPoint
    };
  } catch (error) {
    console.error('Ошибка создания раунда:', error);
    return null;
  }
}

// ===== WEBSOCKET ДЛЯ КРАШ-ИГРЫ =====
let currentRound = null;
let roundInterval = null;
let gameActive = false;

io.on('connection', (socket) => {
  console.log('🔌 Реальный игрок подключился:', socket.id);
  
  socket.on('join_game', async (data) => {
    const { userId, betAmount } = data;
    
    try {
      await pool.query(
        `INSERT INTO active_players (user_id, bet_amount, socket_id, status) 
         VALUES ($1, $2, $3, 'waiting')
         ON CONFLICT (user_id) DO UPDATE 
         SET bet_amount = $2, socket_id = $3, status = 'waiting', updated_at = CURRENT_TIMESTAMP`,
        [userId, betAmount, socket.id]
      );
      
      broadcastPlayers();
    } catch (error) {
      console.error('Ошибка join_game:', error);
    }
  });
  
  socket.on('place_bet', async (data) => {
    const { userId, betAmount, roundId } = data;
    
    try {
      // Проверяем баланс
      const user = await pool.query('SELECT balance FROM users WHERE id = $1', [userId]);
      if (user.rows[0].balance < betAmount) {
        socket.emit('bet_error', { message: 'Недостаточно средств' });
        return;
      }
      
      // Списываем ставку
      await pool.query('UPDATE users SET balance = balance - $1 WHERE id = $2', [betAmount, userId]);
      
      // Сохраняем ставку
      await pool.query(
        `INSERT INTO round_bets (round_id, user_id, bet_amount, status) 
         VALUES ($1, $2, $3, 'active')`,
        [roundId, userId, betAmount]
      );
      
      socket.emit('bet_placed', { success: true, betAmount });
      broadcastPlayers();
      
    } catch (error) {
      console.error('Ошибка ставки:', error);
    }
  });
  
  socket.on('cashout', async (data) => {
    const { userId, roundId, multiplier } = data;
    
    try {
      const bet = await pool.query(
        'SELECT * FROM round_bets WHERE round_id = $1 AND user_id = $2 AND status = $3',
        [roundId, userId, 'active']
      );
      
      if (bet.rows.length > 0) {
        const winAmount = bet.rows[0].bet_amount * multiplier;
        
        await pool.query(
          `UPDATE round_bets SET status = 'cashed_out', cashout_multiplier = $1, win_amount = $2 
           WHERE id = $3`,
          [multiplier, winAmount, bet.rows[0].id]
        );
        
        await pool.query('UPDATE users SET balance = balance + $1 WHERE id = $2', [winAmount, userId]);
        
        socket.emit('cashout_success', { winAmount, multiplier });
        broadcastPlayers();
      }
    } catch (error) {
      console.error('Ошибка кэшаута:', error);
    }
  });
  
  socket.on('disconnect', async () => {
    try {
      await pool.query(
        `DELETE FROM active_players WHERE socket_id = $1`,
        [socket.id]
      );
      
      broadcastPlayers();
    } catch (error) {
      console.error('Ошибка disconnect:', error);
    }
  });
});

// Функция для трансляции списка игроков
async function broadcastPlayers() {
  try {
    const players = await pool.query(`
      SELECT 
        ap.*,
        u.username,
        u.first_name,
        u.photo_url
      FROM active_players ap
      JOIN users u ON u.id = ap.user_id
      ORDER BY ap.updated_at DESC
    `);
    
    io.emit('players_update', players.rows);
  } catch (error) {
    console.error('Ошибка broadcastPlayers:', error);
  }
}

// Функция для запуска игрового цикла
async function startGameLoop() {
  if (gameActive) return;
  gameActive = true;
  
  while (gameActive) {
    // Создаем новый раунд
    currentRound = await generateNewRound();
    if (!currentRound) continue;
    
    // Оповещаем всех о новом раунде
    io.emit('new_round', {
      roundId: currentRound.roundId,
      timeToStart: 5
    });
    
    // Даем 5 секунд на ставки
    await new Promise(resolve => setTimeout(resolve, 5000));
    
    // Запускаем игру
    io.emit('round_started', { roundId: currentRound.roundId });
    
    let currentTime = 0;
    let currentMultiplier = 1.0;
    const startTime = Date.now();
    const crashPoint = currentRound.crashPoint;
    
    // Игровой цикл
    while (currentMultiplier < crashPoint) {
      await new Promise(resolve => setTimeout(resolve, 50));
      currentTime += 0.05;
      currentMultiplier = 1.0 + currentTime * 0.5; // скорость роста
      
      io.emit('multiplier_update', {
        multiplier: currentMultiplier.toFixed(2)
      });
    }
    
    // Краш!
    io.emit('game_crashed', {
      crashPoint: crashPoint.toFixed(2)
    });
    
    // Обновляем статус раунда
    await pool.query(
      `UPDATE crash_rounds SET status = 'finished', end_time = CURRENT_TIMESTAMP WHERE id = $1`,
      [currentRound.id]
    );
    
    // Обрабатываем проигравшие ставки
    await pool.query(
      `UPDATE round_bets SET status = 'lost' WHERE round_id = $1 AND status = 'active'`,
      [currentRound.id]
    );
    
    // Пауза между раундами
    await new Promise(resolve => setTimeout(resolve, 3000));
  }
}

// ===== API ПОЛЬЗОВАТЕЛИ =====
app.post('/api/user', async (req, res) => {
  const { telegram_id, username, first_name, last_name, photo_url } = req.body;
  const ip = req.ip;
  const fingerprint = req.headers['x-fingerprint'] || `fp_${Date.now()}`;
  
  try {
    let user = await pool.query('SELECT * FROM users WHERE telegram_id = $1', [telegram_id]);
    
    if (user.rows.length === 0) {
      const referralCode = `ref_${telegram_id || Math.floor(Math.random() * 1000000)}`;
      const result = await pool.query(
        `INSERT INTO users (telegram_id, username, first_name, last_name, photo_url, ip_address, fingerprint, referral_code, balance, gift_balance, notifications_enabled) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) RETURNING *`,
        [telegram_id, username, first_name, last_name, photo_url, ip, fingerprint, referralCode, 0, 0, true]
      );
      user = result.rows[0];
    } else {
      user = user.rows[0];
      await pool.query(
        'UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = $1',
        [user.id]
      );
    }
    
    // Получаем NFT инвентарь
    const nftInventory = await pool.query(`
      SELECT 
        un.*,
        ci.name,
        ci.image_url,
        ci.rarity,
        ci.color,
        ci.value,
        ci.gift_value
      FROM user_nft un
      JOIN case_items ci ON ci.id = un.item_id
      WHERE un.user_id = $1 AND un.is_sold = false
      ORDER BY un.created_at DESC
    `, [user.id]);
    
    res.json({
      id: user.id,
      telegram_id: user.telegram_id,
      username: user.username,
      first_name: user.first_name,
      photo_url: user.photo_url,
      balance: parseFloat(user.balance),
      gift_balance: parseFloat(user.gift_balance),
      is_admin: user.is_admin,
      is_premium: user.is_premium,
      referral_code: user.referral_code,
      referral_count: user.referral_count,
      referral_earnings: parseFloat(user.referral_earnings),
      total_games: user.total_games,
      total_wins: user.total_wins,
      win_rate: parseFloat(user.win_rate),
      notifications_enabled: user.notifications_enabled,
      nft_inventory: nftInventory.rows,
      settings: user.settings
    });
  } catch (error) {
    console.error('Ошибка получения пользователя:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== API ДЛЯ КРАШ-ИГРЫ =====
app.get('/api/crash/current', async (req, res) => {
  try {
    const round = await pool.query(
      'SELECT * FROM crash_rounds ORDER BY id DESC LIMIT 1'
    );
    
    const bets = await pool.query(`
      SELECT rb.*, u.username, u.first_name, u.photo_url
      FROM round_bets rb
      JOIN users u ON u.id = rb.user_id
      WHERE rb.round_id = $1
    `, [round.rows[0]?.id || 0]);
    
    res.json({
      currentRound: round.rows[0] || null,
      bets: bets.rows
    });
  } catch (error) {
    console.error('Ошибка получения текущего раунда:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/crash/history', async (req, res) => {
  try {
    const history = await pool.query(`
      SELECT crash_point, created_at 
      FROM crash_rounds 
      WHERE status = 'finished' 
      ORDER BY id DESC 
      LIMIT 50
    `);
    
    res.json(history.rows);
  } catch (error) {
    console.error('Ошибка получения истории:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== API АКТИВНЫЕ ИГРОКИ =====
app.get('/api/players', async (req, res) => {
  try {
    const players = await pool.query(`
      SELECT 
        ap.*,
        u.username,
        u.first_name,
        u.photo_url
      FROM active_players ap
      JOIN users u ON u.id = ap.user_id
      ORDER BY ap.updated_at DESC
    `);
    
    res.json(players.rows);
  } catch (error) {
    console.error('Ошибка получения игроков:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

app.get('/api/stats', async (req, res) => {
  try {
    const usersCount = await pool.query('SELECT COUNT(*) FROM users');
    const activePlayers = await pool.query(`
      SELECT COUNT(*) FROM active_players 
      WHERE updated_at > NOW() - INTERVAL '5 minutes'
    `);
    
    res.json({
      total_users: parseInt(usersCount.rows[0].count),
      online: parseInt(activePlayers.rows[0].count)
    });
  } catch (error) {
    console.error('Ошибка получения статистики:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== АДМИНКА API =====
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
    console.error('Ошибка логина:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

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

// ===== ЗАПУСК =====
initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`✅ Сервер запущен на порту ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`👑 Админка: http://localhost:${PORT}/admin`);
    console.log(`🚀 Краш-игра запущена`);
    
    // Запускаем игровой цикл
    startGameLoop();
  });
});

// Graceful shutdown
process.once('SIGINT', () => {
  gameActive = false;
  process.exit();
});
process.once('SIGTERM', () => {
  gameActive = false;
  process.exit();
});
