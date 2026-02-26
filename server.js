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

// ===== TELEGRAM БОТ =====
let bot;
if (BOT_TOKEN) {
  bot = new Telegraf(BOT_TOKEN);
  
  bot.start(async (ctx) => {
    const startPayload = ctx.payload;
    const userId = ctx.from.id;
    const username = ctx.from.username || ctx.from.first_name;
    const firstName = ctx.from.first_name;
    const photoUrl = ctx.from.photo_url;
    
    // Сохраняем реферальный код
    if (startPayload && startPayload.startsWith('ref_')) {
      const referrerId = startPayload.replace('ref_', '');
      await saveReferral(userId, referrerId);
    }
    
    // Отправляем приветственное сообщение
    ctx.reply(`🎮 Добро пожаловать в GiftDrop, ${firstName}!`, {
      reply_markup: {
        inline_keyboard: [[
          { text: '🎁 Открыть приложение', web_app: { url: 'https://mode-goto.onrender.com' } }
        ]]
      }
    });
  });
  
  bot.launch();
  console.log('✅ Telegram Bot запущен');
}

// ===== ПОДКЛЮЧЕНИЕ К POSTGRESQL =====
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://gifts_db_i4ig_user:pDtsgu5KrXJnReT2zW2zFxzAWd0XF57L@dpg-d6fvlha4d50c73dfc1n0-a/gifts_db_i4ig',
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
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB
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

      -- Предметы кейсов (NFT)
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
        nft_type VARCHAR(50),
        min_win DECIMAL,
        max_win DECIMAL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Инвентарь NFT
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
        is_test BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- Покупки GiftDrop
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

      -- Активные игроки
      CREATE TABLE IF NOT EXISTS active_players (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE UNIQUE,
        bet_amount DECIMAL,
        current_multiplier DECIMAL DEFAULT 1.0,
        status VARCHAR(50) DEFAULT 'waiting',
        socket_id VARCHAR(255),
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- История игр
      CREATE TABLE IF NOT EXISTS game_history (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        game_type VARCHAR(50),
        bet_amount DECIMAL,
        win_amount DECIMAL,
        multiplier DECIMAL,
        crashed_at DECIMAL,
        result JSONB,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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

    // Создаем тестовые кейсы
    const casesCount = await pool.query('SELECT COUNT(*) FROM cases');
    if (parseInt(casesCount.rows[0].count) === 0) {
      await pool.query(
        `INSERT INTO cases (name, description, price, gift_price, image_url, sort_order) VALUES 
         ($1, $2, $3, $4, $5, $6),
         ($7, $8, $9, $10, $11, $12),
         ($13, $14, $15, $16, $17, $18),
         ($19, $20, $21, $22, $23, $24)`,
        [
          'Обычный кейс', 'Обычные предметы', 10, 5, '/cases/common.png', 1,
          'Редкий кейс', 'Редкие предметы', 50, 25, '/cases/rare.png', 2,
          'Эпический кейс', 'Эпические предметы', 200, 100, '/cases/epic.png', 3,
          'Легендарный кейс', 'Легендарные предметы', 1000, 500, '/cases/legendary.png', 4
        ]
      );

      // Добавляем предметы
      const cases = await pool.query('SELECT id FROM cases ORDER BY id');
      
      for (let i = 0; i < cases.rows.length; i++) {
        const caseId = cases.rows[i].id;
        await pool.query(
          `INSERT INTO case_items (case_id, name, value, gift_value, probability, rarity, is_nft) VALUES 
           ($1, $2, $3, $4, $5, $6, $7),
           ($1, $8, $9, $10, $11, $12, $13),
           ($1, $14, $15, $16, $17, $18, $19)`,
          [caseId, 'Обычный предмет', 5, 3, 50, 'common', false,
           'Редкий предмет', 20, 10, 30, 'rare', true,
           'Эпический предмет', 50, 25, 20, 'epic', true]
        );
      }
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
        await pool.query(
          `INSERT INTO users (username, password, balance, gift_balance, is_admin, is_premium, referral_code, notifications_enabled) 
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
          [admin.username, hash, 1000000, 10000, true, true, `ADMIN_${admin.username}`, true]
        );
        console.log(`✅ Админ ${admin.username} создан`);
      }
    }

    // Создаем промокоды
    const promoCount = await pool.query('SELECT COUNT(*) FROM promo_codes');
    if (parseInt(promoCount.rows[0].count) === 0) {
      await pool.query(
        `INSERT INTO promo_codes (code, reward_amount, max_uses) VALUES 
         ($1, $2, $3),
         ($4, $5, $6),
         ($7, $8, $9)`,
        ['WELCOME', 50, 1000, 'GIFT2025', 100, 500, 'STARS', 25, 1000]
      );
    }

  } catch (error) {
    console.error('❌ Ошибка инициализации БД:', error);
  }
}

// ===== ФУНКЦИЯ СОХРАНЕНИЯ РЕФЕРАЛА =====
async function saveReferral(userId, referrerId) {
  try {
    const existing = await pool.query(
      'SELECT * FROM referrals WHERE referred_id = $1',
      [userId]
    );
    
    if (existing.rows.length === 0 && userId !== parseInt(referrerId)) {
      await pool.query(
        `INSERT INTO referrals (referrer_id, referred_id, reward_amount) 
         VALUES ($1, $2, $3)`,
        [referrerId, userId, 25]
      );
      
      await pool.query(
        `UPDATE users SET balance = balance + 25, referral_count = referral_count + 1, referral_earnings = referral_earnings + 25 
         WHERE id = $1`,
        [referrerId]
      );
      
      await pool.query(
        `UPDATE users SET balance = balance + 25 WHERE id = $1`,
        [userId]
      );
      
      console.log(`✅ Реферал активирован: ${referrerId} -> ${userId}`);
    }
  } catch (error) {
    console.error('Ошибка сохранения реферала:', error);
  }
}

// ===== WEBSOCKET =====
io.on('connection', (socket) => {
  console.log('🔌 Новое подключение:', socket.id);
  
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
  
  socket.on('start_game', async (data) => {
    const { userId, betAmount } = data;
    
    try {
      await pool.query(
        `UPDATE active_players 
         SET status = 'playing', bet_amount = $2, updated_at = CURRENT_TIMESTAMP 
         WHERE user_id = $1`,
        [userId, betAmount]
      );
      
      broadcastPlayers();
    } catch (error) {
      console.error('Ошибка start_game:', error);
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

// ===== API ПОЛЬЗОВАТЕЛИ =====

// Получение/создание пользователя
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
      
      // Отправляем приветственное сообщение в бот
      if (bot && telegram_id) {
        await bot.telegram.sendMessage(telegram_id, 
          `🎁 Добро пожаловать в GiftDrop, ${first_name || username}!\n\nВы успешно авторизовались в приложении. Теперь вы будете получать уведомления о новых кейсах и выигрышах.`,
          { parse_mode: 'HTML' }
        );
      }
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

// ===== API ПОКУПКИ GIFT DROP =====

// Создание покупки
app.post('/api/gift/purchase', async (req, res) => {
  const { user_id, stars_amount, gift_amount, promo_code } = req.body;
  
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [user_id]);
    if (user.rows.length === 0) {
      return res.status(404).json({ error: 'Пользователь не найден' });
    }
    
    const result = await pool.query(
      `INSERT INTO gift_purchases (user_id, username, photo_url, stars_amount, gift_amount, promo_code, status) 
       VALUES ($1, $2, $3, $4, $5, $6, 'pending') RETURNING id`,
      [user_id, user.rows[0].username, user.rows[0].photo_url, stars_amount, gift_amount, promo_code]
    );
    
    res.json({
      success: true,
      purchase_id: result.rows[0].id,
      message: 'Заявка на покупку создана'
    });
  } catch (error) {
    console.error('Ошибка создания покупки:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Загрузка скриншота
app.post('/api/gift/upload-screenshot/:purchaseId', upload.single('screenshot'), async (req, res) => {
  const { purchaseId } = req.params;
  const screenshotUrl = req.file ? `/uploads/screenshots/${req.file.filename}` : null;
  
  try {
    await pool.query(
      `UPDATE gift_purchases SET screenshot_url = $1 WHERE id = $2`,
      [screenshotUrl, purchaseId]
    );
    
    res.json({ success: true, screenshot_url: screenshotUrl });
  } catch (error) {
    console.error('Ошибка загрузки скриншота:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Подтверждение покупки (админка)
app.post('/api/admin/gift/confirm/:purchaseId', async (req, res) => {
  const { purchaseId } = req.params;
  
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await pool.query('SELECT * FROM users WHERE id = $1 AND is_admin = true', [decoded.id]);
    if (!admin.rows[0]) return res.status(403).json({ error: 'Forbidden' });
    
    const purchase = await pool.query('SELECT * FROM gift_purchases WHERE id = $1', [purchaseId]);
    if (purchase.rows.length === 0) {
      return res.status(404).json({ error: 'Покупка не найдена' });
    }
    
    const p = purchase.rows[0];
    
    // Начисляем GiftDrop пользователю
    await pool.query(
      `UPDATE users SET gift_balance = gift_balance + $1 WHERE id = $2`,
      [p.gift_amount, p.user_id]
    );
    
    await pool.query(
      `UPDATE gift_purchases SET status = 'completed', completed_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [purchaseId]
    );
    
    await pool.query(
      `INSERT INTO transactions (user_id, amount, type, method, description) VALUES ($1, $2, 'gift_purchase', 'stars', $3)`,
      [p.user_id, p.gift_amount, `Покупка GiftDrop за ${p.stars_amount} ⭐`]
    );
    
    // Отправляем уведомление в Telegram
    if (bot) {
      const user = await pool.query('SELECT * FROM users WHERE id = $1', [p.user_id]);
      if (user.rows[0]?.telegram_id && user.rows[0].notifications_enabled) {
        await bot.telegram.sendMessage(user.rows[0].telegram_id,
          `✅ Ваш платёж подтверждён!\n\n➕ Зачислено: ${p.gift_amount} 🎁\n💰 Новый баланс: ${parseFloat(user.rows[0].gift_balance) + p.gift_amount} 🎁`
        );
      }
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Ошибка подтверждения покупки:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Отклонение покупки
app.post('/api/admin/gift/reject/:purchaseId', async (req, res) => {
  const { purchaseId } = req.params;
  
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await pool.query('SELECT * FROM users WHERE id = $1 AND is_admin = true', [decoded.id]);
    if (!admin.rows[0]) return res.status(403).json({ error: 'Forbidden' });
    
    await pool.query(
      `UPDATE gift_purchases SET status = 'rejected' WHERE id = $1`,
      [purchaseId]
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Ошибка отклонения покупки:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// Получение всех покупок (админка)
app.get('/api/admin/gift/purchases', async (req, res) => {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await pool.query('SELECT * FROM users WHERE id = $1 AND is_admin = true', [decoded.id]);
    if (!admin.rows[0]) return res.status(403).json({ error: 'Forbidden' });
    
    const purchases = await pool.query(`
      SELECT * FROM gift_purchases 
      ORDER BY created_at DESC 
      LIMIT 100
    `);
    
    res.json(purchases.rows);
  } catch (error) {
    console.error('Ошибка получения покупок:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== API ПРОМОКОДЫ =====

// Применение промокода
app.post('/api/promo/apply', async (req, res) => {
  const { user_id, code } = req.body;
  
  try {
    const promo = await pool.query(
      'SELECT * FROM promo_codes WHERE code = $1 AND (expires_at IS NULL OR expires_at > NOW()) AND uses_count < max_uses',
      [code]
    );
    
    if (promo.rows.length === 0) {
      return res.status(404).json({ error: 'Промокод недействителен' });
    }
    
    const p = promo.rows[0];
    
    await pool.query(
      `UPDATE users SET gift_balance = gift_balance + $1 WHERE id = $2`,
      [p.reward_amount, user_id]
    );
    
    await pool.query(
      `UPDATE promo_codes SET uses_count = uses_count + 1 WHERE id = $1`,
      [p.id]
    );
    
    res.json({ success: true, reward: p.reward_amount });
  } catch (error) {
    console.error('Ошибка применения промокода:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== API СТАТИСТИКА =====

app.get('/api/stats', async (req, res) => {
  try {
    const usersCount = await pool.query('SELECT COUNT(*) FROM users');
    const activePlayers = await pool.query('SELECT COUNT(*) FROM active_players');
    const totalPurchases = await pool.query('SELECT COUNT(*) FROM gift_purchases WHERE status = $1', ['completed']);
    const totalGift = await pool.query('SELECT COALESCE(SUM(gift_amount), 0) FROM gift_purchases WHERE status = $1', ['completed']);
    
    res.json({
      total_users: parseInt(usersCount.rows[0].count),
      online: parseInt(activePlayers.rows[0].count),
      total_purchases: parseInt(totalPurchases.rows[0].count),
      total_gift: parseFloat(totalGift.rows[0].sum)
    });
  } catch (error) {
    console.error('Ошибка получения статистики:', error);
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
    console.error('Ошибка логина:', error);
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

// Получение всех пользователей (админка)
app.get('/api/admin/users', async (req, res) => {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const admin = await pool.query('SELECT * FROM users WHERE id = $1 AND is_admin = true', [decoded.id]);
    if (!admin.rows[0]) return res.status(403).json({ error: 'Forbidden' });
    
    const users = await pool.query(`
      SELECT id, username, first_name, photo_url, balance, gift_balance, 
             total_games, total_wins, is_premium, is_admin, is_banned,
             referral_count, created_at, last_seen, notifications_enabled
      FROM users ORDER BY id DESC LIMIT 100
    `);
    
    res.json(users.rows);
  } catch (error) {
    console.error('Ошибка получения пользователей:', error);
    res.status(500).json({ error: 'Ошибка сервера' });
  }
});

// ===== ЗАПУСК =====

initDB().then(() => {
  server.listen(PORT, () => {
    console.log(`✅ Сервер запущен на порту ${PORT}`);
    console.log(`🌐 http://localhost:${PORT}`);
    console.log(`👑 Админка: http://localhost:${PORT}/admin`);
    console.log(`🔌 WebSocket сервер запущен`);
  });
});

// Graceful shutdown
process.once('SIGINT', () => {
  if (bot) bot.stop('SIGINT');
  process.exit();
});
process.once('SIGTERM', () => {
  if (bot) bot.stop('SIGTERM');
  process.exit();
});
