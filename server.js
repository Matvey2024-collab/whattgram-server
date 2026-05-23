const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

function sanitize(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, 1000);
}

function isValidLogin(login) {
    return /^[a-zA-Z0-9_]{3,20}$/.test(login);
}

function isValidObjectId(id) {
    return mongoose.Types.ObjectId.isValid(id) && new mongoose.Types.ObjectId(id).toString() === id;
}

function sanitizeAndValidateLogin(str) {
    const sanitized = sanitize(str);
    return isValidLogin(sanitized) ? sanitized : null;
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isValidPhone(phone) {
    const cleaned = phone.replace(/\D/g, '');
    return /^\+?\d{11}$/.test(phone) && cleaned.length === 11;
}

const rateLimitStore = new Map();
const rateLimitLocks = new Map();

function rateLimit(key, limit, windowMs) {
    const now = Date.now();
    
    while (rateLimitLocks.get(key)) {
        // Wait for any pending operation
    }
    rateLimitLocks.set(key, true);
    
    try {
        const record = rateLimitStore.get(key);
        
        if (!record || now > record.resetAt) {
            rateLimitStore.set(key, { count: 1, resetAt: now + windowMs });
            return true;
        }
        
        record.count++;
        rateLimitStore.set(key, record);
        
        return record.count <= limit;
    } finally {
        rateLimitLocks.delete(key);
    }
}

function cleanupRateLimit() {
    const now = Date.now();
    for (const [key, record] of rateLimitStore.entries()) {
        if (now > record.resetAt) {
            rateLimitStore.delete(key);
        }
    }
}
setInterval(cleanupRateLimit, 60000);

const app = express();
const server = http.createServer(app);

const originalConsoleError = console.error;
const originalConsoleWarn = console.warn;

console.error = function(...args) {
    const message = args.join(' ');
    if (message.includes('ECONNRESET') || 
        message.includes('polling_error') || 
        message.includes('EFATAL') ||
        message.includes('read ECONNRESET')) {
        return;
    }
    originalConsoleError.apply(console, args);
};

console.warn = function(...args) {
    const message = args.join(' ');
    if (message.includes('ECONNRESET') || message.includes('polling_error')) {
        return;
    }
    originalConsoleWarn.apply(console, args);
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

async function sendVerificationEmail(email, code, login) {
    console.log(`>>> [EMAIL] Попытка отправки на ${email}`);
    const mailOptions = {
        from: `"WhattGram" <${process.env.EMAIL_USER}>`,
        to: email,
        subject: 'Подтверждение регистрации в WhattGram',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px; background: #1a1a1a; color: #fff; border-radius: 10px;">
                <h2 style="color: #5D5FEF;">Добро пожаловать в WhattGram!</h2>
                <p>Здравствуйте, <strong>${login}</strong>!</p>
                <p>Ваш код подтверждения:</p>
                <div style="font-size: 32px; font-weight: bold; text-align: center; padding: 20px; background: #333; border-radius: 8px; margin: 20px 0;">
                    ${code}
                </div>
                <p>Введите этот код в приложении для завершения регистрации.</p>
                <p style="font-size: 12px; color: #888; margin-top: 20px;">Если вы не регистрировались в WhattGram, проигнорируйте это письмо.</p>
            </div>
        `
    };
    
    try {
        await transporter.sendMail(mailOptions);
        console.log(`>>> [EMAIL] Код отправлен на ${email}`);
        return true;
    } catch (err) {
        console.error('>>> [EMAIL] Ошибка отправки:', err.message);
        console.error('>>> [EMAIL] Код ошибки:', err.code);
        console.error('>>> [EMAIL] Ответ сервера:', err.response);
        return false;
    }
}

const io = new Server(server, { 
    cors: {
        origin: true,
        methods: ["GET", "POST"],
        credentials: true
    },
    maxHttpBufferSize: 2e7,
    pingTimeout: 120000,
    pingInterval: 30000,
    transports: ['polling', 'websocket'],
    allowEIO3: true,
    connectTimeout: 45000,
    allowUpgrades: true
});

mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/whattgram_final', {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 60000,
    family: 4
})
    .then(() => console.log(">>> [DB] Успешное подключение"))
    .catch(err => console.error(">>> [DB] Ошибка подключения:", err.message));

const CURRENT_VERSION = '1.1.0';
const UPDATE_SERVER = process.env.UPDATE_SERVER || 'http://localhost:3001';

app.get('/api/version', (req, res) => {
    res.json({
        version: CURRENT_VERSION,
        updateServer: UPDATE_SERVER,
        required: false
    });
});

app.get('/api/check-update', async (req, res) => {
    try {
        const response = await fetch(`${UPDATE_SERVER}/api/version`);
        const data = await response.json();
        res.json(data);
    } catch (err) {
        res.json({ version: CURRENT_VERSION, updateServer: UPDATE_SERVER });
    }
});

mongoose.connection.on('disconnected', () => {
    console.log(">>> [DB] Соединение разорвано, переподключаемся...");
    setTimeout(() => {
        mongoose.connect(process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/whattgram_final');
    }, 5000);
});

mongoose.connection.on('error', (err) => {
    console.error(">>> [DB] Ошибка соединения:", err.message);
});

const User = mongoose.model('User', new mongoose.Schema({
    login: { type: String, unique: true },
    password: { type: String },
    phone: { type: String, unique: true },
    email: { type: String, unique: true },
    verifyCode: { type: String },
    isVerified: { type: Boolean, default: false },
    bio: { type: String, default: "Нет описания" },
    avatar: { type: String, default: null },
    blackList: [{ type: String }], 
    publicKey: { type: String, default: null },
    sessions: [{
        socketId: String,
        device: String,
        ip: String,
        lastSeen: { type: Date, default: Date.now }
    }],
    createdAt: { type: Date, default: Date.now }
}));

const Group = mongoose.model('Group', new mongoose.Schema({
    name: String,
    admin: String,
    admins: [{ type: String }],
    members: [String],
    avatar: { type: String, default: null },
    bio: { type: String, default: "Групповой чат" },
    createdAt: { type: Date, default: Date.now },
    inviteLinks: [{
        code: String,
        createdBy: String,
        createdAt: { type: Date, default: Date.now },
        expiresAt: Date,
        maxUses: { type: Number, default: 0 },
        uses: { type: Number, default: 0 }
    }],
    messageCount: { type: Number, default: 0 }
}));

const Channel = mongoose.model('Channel', new mongoose.Schema({
    name: String,
    description: { type: String, default: "Канал" },
    admin: String,
    avatar: { type: String, default: null },
    subscribers: [String],
    createdAt: { type: Date, default: Date.now },
    views: { type: Number, default: 0 }
}));

const ChannelMessage = mongoose.model('ChannelMessage', new mongoose.Schema({
    user: String,
    channelId: String,
    text: String,
    type: { type: String, default: 'text' },
    time: { type: Date, default: Date.now }
}));

const messageSchema = new mongoose.Schema({
    user: String, 
    to: String, 
    text: String,
    voice: { type: String, default: null }, 
    type: { type: String, default: 'text' },
    isGroup: { type: Boolean, default: false },
    encrypted: { type: Boolean, default: false },
    read: { type: Boolean, default: false },
    time: { type: Date, default: Date.now },
    edited: { type: Boolean, default: false },
    editHistory: [{
        text: String,
        editedAt: { type: Date, default: Date.now }
    }],
    reactions: [{
        user: String,
        emoji: String,
        time: { type: Date, default: Date.now }
    }]
});

const Message = mongoose.model('Message', messageSchema);

app.use(express.json({ limit: '20mb' }));
app.use(express.static(__dirname, { index: 'index.html' }));

app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

let onlineUsers = {};

async function sendSecurityUpdate(socket) {
    if (!socket.user) return;
    try {
        const user = await User.findOne({ login: socket.user }).lean();
        if (user) {
            socket.emit('security_data', {
                sessions: user.sessions || [],
                blackList: user.blackList || []
            });
        }
    } catch (err) {
        console.error('Ошибка отправки security данных:', err.message);
    }
}

const SYSTEM_USER = "WhattGram";

async function initSystemUser() {
    const existing = await User.findOne({ login: SYSTEM_USER });
    const systemPassword = process.env.SYSTEM_USER_PASSWORD;

    if (!systemPassword) {
        console.log(">>> [SYSTEM] SYSTEM_USER_PASSWORD не задан в .env");
        return;
    }

    if (!existing) {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(systemPassword, salt);
        const systemUser = new User({
            login: SYSTEM_USER,
            password: hashedPassword,
            phone: "0000000000",
            email: "system@whattgram.com",
            isVerified: true,
            bio: "Официальный канал новостей WhattGram",
            blackList: []
        });
        await systemUser.save();
        console.log(`>>> [SYSTEM] Создан пользователь ${SYSTEM_USER}`);
    } else {
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(systemPassword, salt);
        await User.findOneAndUpdate({ login: SYSTEM_USER }, { password: hashedPassword });
        console.log(`>>> [SYSTEM] Пароль для ${SYSTEM_USER} обновлён`);
    }
}

app.post('/api/join-by-link', async (req, res) => {
    try {
        const { code, userId } = req.body;
        
        if (!code || typeof code !== 'string' || code.length < 8 || code.length > 50) {
            return res.json({ success: false, msg: "Некорректный код" });
        }
        
        const safeCode = sanitize(code);
        const safeUserId = sanitizeAndValidateLogin(userId);
        
        if (!safeUserId) {
            return res.json({ success: false, msg: "Некорректный пользователь" });
        }
        
        const group = await Group.findOne({ 'inviteLinks.code': safeCode });
        if (!group) {
            return res.json({ success: false, msg: "Ссылка недействительна" });
        }
        
        const link = group.inviteLinks.find(l => l.code === code);
        
        if (link.expiresAt && new Date() > link.expiresAt) {
            return res.json({ success: false, msg: "Срок действия ссылки истек" });
        }
        
        if (link.maxUses > 0 && link.uses >= link.maxUses) {
            return res.json({ success: false, msg: "Лимит использований исчерпан" });
        }
        
        if (!group.members.includes(userId)) {
            group.members.push(userId);
            link.uses += 1;
            await group.save();
            
            res.json({ success: true, groupId: group._id, groupName: group.name });
        } else {
            res.json({ success: false, msg: "Вы уже в группе" });
        }
    } catch (err) {
        console.error('Ошибка join-by-link:', err.message);
        res.json({ success: false, msg: "Ошибка сервера" });
    }
});

app.post('/api/auth', async (req, res) => {
    const { login, password, phone, email, isReg } = req.body;
    
    const clientIp = req.ip || req.socket?.remoteAddress;
    if (!rateLimit(`auth:${clientIp}`, 5, 60000)) {
        return res.json({ success: false, msg: 'Слишком много попыток. Попробуйте позже.' });
    }
    
    try {
        if (isReg) {
            if (!isValidLogin(login) || !isValidEmail(email) || !isValidPhone(phone) || password.length < 6) {
                return res.json({ success: false, msg: 'Некорректные данные' });
            }
            
            const existingUser = await User.findOne({ $or: [{ login: sanitize(login) }, { phone: sanitize(phone) }, { email: sanitize(email) }] });
            if (existingUser) {
                return res.json({ success: false, msg: 'Пользователь уже существует' });
            }
            
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);
            const code = Math.floor(100000 + Math.random() * 900000).toString();
            
            const newUser = new User({ 
                login: sanitize(login), 
                password: hashedPassword, 
                phone: sanitize(phone), 
                email: sanitize(email),
                verifyCode: code,
                isVerified: false,
                blackList: [] 
            });
            await newUser.save();
            
            const sent = await sendVerificationEmail(email, code, login);
            
            if (sent) {
                res.json({ success: true, needVerify: true, msg: 'Код отправлен на email' });
            } else {
                await User.deleteOne({ login });
                res.json({ success: false, msg: 'Не удалось отправить код на email' });
            }
        } else {
            const user = await User.findOne({ login });
            if (!user) return res.json({ success: false, msg: "Неверный логин или пароль" });
            
            const validPass = await bcrypt.compare(password, user.password);
            if (!validPass) return res.json({ success: false, msg: "Неверный логин или пароль" });
            
            if (!user.isVerified) return res.json({ success: false, msg: "Аккаунт не подтвержден. Проверьте email!" });
            
            res.json({ success: true });
        }
    } catch (e) { 
        console.error('Ошибка auth:', e.message);
        res.json({ success: false, msg: "Ошибка сервера" }); 
    }
});

app.post('/api/verify', async (req, res) => {
    const { login, code } = req.body;
    
    if (!isValidLogin(login)) {
        return res.json({ success: false, msg: "Некорректные данные" });
    }
    
    try {
        const user = await User.findOne({ login });
        if (!user) {
            return res.json({ success: false, msg: "Пользователь не найден" });
        }
        
        if (user.verifyCode !== code) {
            return res.json({ success: false, msg: "Неверный код подтверждения" });
        }
        
        user.isVerified = true;
        user.verifyCode = null;
        await user.save();
        
        res.json({ success: true, msg: "Аккаунт подтвержден!" });
    } catch (err) {
        console.error('Ошибка verify:', err.message);
        res.json({ success: false, msg: "Ошибка подтверждения" });
    }
});

app.post('/api/resend-code', async (req, res) => {
    const { login } = req.body;
    
    if (!isValidLogin(login)) {
        return res.json({ success: false, msg: "Некорректные данные" });
    }
    
    const clientIp = req.ip || req.socket?.remoteAddress;
    if (!rateLimit(`resend:${clientIp}`, 3, 60000)) {
        return res.json({ success: false, msg: 'Слишком много попыток. Попробуйте позже.' });
    }
    
    try {
        const user = await User.findOne({ login });
        if (!user) {
            return res.json({ success: false, msg: "Пользователь не найден" });
        }
        
        if (user.isVerified) {
            return res.json({ success: false, msg: "Аккаунт уже подтвержден" });
        }
        
        const newCode = Math.floor(100000 + Math.random() * 900000).toString();
        user.verifyCode = newCode;
        await user.save();
        
        const sent = await sendVerificationEmail(user.email, newCode, user.login);
        
        if (sent) {
            res.json({ success: true, msg: "Код отправлен повторно" });
        } else {
            res.json({ success: false, msg: "Ошибка отправки" });
        }
    } catch (err) {
        console.error('Ошибка resend:', err.message);
        res.json({ success: false, msg: "Ошибка сервера" });
    }
});

app.post('/api/find', async (req, res) => {
    const clientIp = req.ip || req.socket?.remoteAddress;
    if (!rateLimit(`find:${clientIp}`, 10, 60000)) {
        return res.json({ success: false, msg: 'Слишком много запросов' });
    }
    
    const { phone } = req.body;
    if (!phone || !isValidPhone(phone)) {
        return res.json({ success: false, msg: "Некорректный номер телефона" });
    }
    
    try {
        const user = await User.findOne({ phone: sanitize(phone) });
        if (user) res.json({ success: true, login: user.login });
        else res.json({ success: false, msg: "Пользователь не найден" });
    } catch (err) {
        console.error('Ошибка find:', err.message);
        res.json({ success: false, msg: "Ошибка поиска" });
    }
});

app.post('/api/system-broadcast', async (req, res) => {
    const { secret, message } = req.body;
    const SYSTEM_SECRET = process.env.SYSTEM_SECRET;
    const ALLOWED_BROADCAST_IPS = (process.env.ALLOWED_BROADCAST_IPS || '127.0.0.1').split(',');
    
    const clientIp = req.ip || req.socket?.remoteAddress || req.headers['x-forwarded-for'];
    const cleanIp = clientIp.replace(/^::ffff:/, '');
    
    if (!ALLOWED_BROADCAST_IPS.includes(cleanIp) && !ALLOWED_BROADCAST_IPS.includes('0.0.0.0')) {
        return res.status(403).json({ success: false, msg: "Доступ запрещён" });
    }
    
    if (!rateLimit(`broadcast:${cleanIp}`, 10, 3600000)) {
        return res.status(429).json({ success: false, msg: 'Слишком много запросов' });
    }
    
    if (!SYSTEM_SECRET) {
        return res.status(503).json({ success: false, msg: "Система рассылки отключена" });
    }
    
    if (secret !== SYSTEM_SECRET) {
        return res.status(403).json({ success: false, msg: "Неверный ключ" });
    }
    
    if (!message || typeof message !== 'string' || message.trim() === '' || message.length > 5000) {
        return res.status(400).json({ success: false, msg: "Текст сообщения обязателен (макс. 5000 символов)" });
    }
    
    try {
        const users = await User.find({}, 'login');
        const now = new Date();
        const systemMsgData = {
            user: SYSTEM_USER,
            text: message.trim(),
            type: 'text',
            time: now,
            isGroup: false,
            edited: false,
            encrypted: false,
            reactions: [],
            editHistory: []
        };
        
        const messages = users.map(u => ({
            ...systemMsgData,
            to: u.login,
            _id: new mongoose.Types.ObjectId()
        }));
        
        await Message.insertMany(messages);
        
        for (const msg of messages) {
            if (onlineUsers[msg.to] && onlineUsers[msg.to].online) {
                io.to(msg.to).emit('msg', msg);
            }
        }
        
        console.log(`>>> [SYSTEM] Рассылка через API отправлена ${users.length} пользователям`);
        res.json({ success: true, msg: `Сообщение отправлено ${users.length} пользователям` });
    } catch (err) {
        console.error('Ошибка системной рассылки:', err);
        res.status(500).json({ success: false, msg: "Ошибка сервера" });
    }
});

io.on('connection', (socket) => {
    
    socket.authenticatedUser = null;
    
    socket.on('error', (err) => {
        if (err.code !== 'ECONNRESET') {
            console.error(`>>> [SOCKET] Ошибка:`, err.message);
        }
    });
    
    socket.on('disconnect', (reason) => {
        if (reason !== 'transport close' && reason !== 'ping timeout') {
            console.log(`>>> [SOCKET] Отключение: ${socket.user || 'unknown'} - ${reason}`);
        }
        if (socket.user) {
            handleUserDisconnect(socket.user, socket.id);
        }
    });
    
    socket.on('join', async (username) => {
        try {
            if (!username || typeof username !== 'string') return;
            const sanitizedUsername = sanitize(username);
            if (!isValidLogin(sanitizedUsername)) return;
            
            socket.join(sanitizedUsername);
            socket.user = sanitizedUsername;
            
            onlineUsers[username] = {
                socketId: socket.id,
                lastSeen: new Date(),
                online: true
            };

            const userGroups = await Group.find({ members: username });
            userGroups.forEach(g => socket.join(g._id.toString()));
            
            const userChannels = await Channel.find({ subscribers: username });
            userChannels.forEach(ch => socket.join(`channel_${ch._id}`));

            const deviceName = socket.handshake.headers['user-agent'] || 'Desktop App';
            const clientIp = socket.handshake.address || "127.0.0.1";
            
            await User.findOneAndUpdate(
                { login: username },
                { $pull: { sessions: { socketId: socket.id } } }
            );
            
            await User.findOneAndUpdate(
                { login: username },
                { $push: { sessions: { socketId: socket.id, device: deviceName, ip: clientIp } } }
            );

            io.emit('online_list', Object.keys(onlineUsers).filter(u => onlineUsers[u]?.online));

            const user = await User.findOne({ login: username }).lean();
            socket.broadcast.emit('user_public_key', {
                user: username,
                hasKey: !!user?.publicKey
            });

            for (const onlineUser of Object.keys(onlineUsers)) {
                if (onlineUser !== username) {
                    const targetUser = await User.findOne({ login: onlineUser }).lean();
                    if (targetUser && targetUser.publicKey) {
                        socket.emit('public_key', {
                            user: onlineUser,
                            key: targetUser.publicKey
                        });
                    }
                }
            }

            socket.emit('my_groups', userGroups.map(g => ({
                id: g._id,
                name: g.name,
                avatar: g.avatar,
                isGroup: true,
                memberCount: g.members.length,
                admin: g.admin,
                admins: g.admins || []
            })));

            const groupIds = userGroups.map(g => g._id.toString());
            const history = await Message.find({
                $or: [
                    { user: username },
                    { to: username },
                    { to: { $in: groupIds }, isGroup: true }
                ]
            }).lean().sort({ time: 1 });
            
            socket.emit('history', history);
            sendSecurityUpdate(socket);
            
            console.log(`>>> [SOCKET] Пользователь вошел: ${username}`);
        } catch (err) {
            console.error(`>>> [SOCKET] Ошибка при входе ${username}:`, err.message);
            socket.emit('error_msg', { text: "Ошибка при входе" });
        }
    });

    socket.on('save_public_key', async (data) => {
        try {
            if (!socket.user) return;
            await User.findOneAndUpdate(
                { login: socket.user },
                { publicKey: data.publicKey }
            );
            socket.broadcast.emit('public_key', {
                user: socket.user,
                key: data.publicKey
            });
        } catch (err) {
            console.error('Ошибка сохранения ключа:', err.message);
        }
    });

    socket.on('get_public_key', async (data) => {
        try {
            const targetUser = await User.findOne({ login: data.target }).lean();
            if (targetUser && targetUser.publicKey) {
                socket.emit('public_key', {
                    user: data.target,
                    key: targetUser.publicKey
                });
            }
        } catch (err) {
            console.error('Ошибка получения ключа:', err.message);
        }
    });

    socket.on('get_channels', async () => {
        try {
            const channels = await Channel.find().lean();
            socket.emit('channels_list', channels.map(ch => ({
                _id: ch._id,
                name: ch.name,
                description: ch.description,
                subscribers: ch.subscribers || [],
                admin: ch.admin,
                views: ch.views || 0,
                createdAt: ch.createdAt
            })));
        } catch (err) {
            console.error('Ошибка получения каналов:', err.message);
        }
    });

    socket.on('create_channel', async (data) => {
        if (!socket.user || !data || !data.name || typeof data.name !== 'string') return;
        
        const safeName = sanitize(data.name);
        if (!safeName || safeName.length < 1 || safeName.length > 50) return;
        
        try {
            const channel = new Channel({
                name: safeName,
                description: data.description ? sanitize(data.description).slice(0, 200) : "Канал",
                admin: socket.user,
                subscribers: [socket.user],
                views: 0
            });
            await channel.save();
            
            socket.join(`channel_${channel._id}`);
            
            socket.emit('channel_created', {
                id: channel._id,
                name: channel.name,
                description: channel.description,
                isChannel: true
            });
            
            const systemMsg = new ChannelMessage({
                user: "System",
                channelId: channel._id,
                text: `Канал "${data.name}" создан пользователем ${socket.user}`,
                time: new Date()
            });
            await systemMsg.save();
            io.to(`channel_${channel._id}`).emit('channel_msg', systemMsg);
            
        } catch (err) {
            console.error("Ошибка при создании канала:", err.message);
            socket.emit('error_msg', { text: "Ошибка при создании канала" });
        }
    });

    socket.on('subscribe_channel', async (data) => {
        const { channelId } = data;
        
        try {
            const channel = await Channel.findById(channelId);
            if (!channel) return socket.emit('error_msg', { text: "Канал не найден" });
            
            if (!channel.subscribers.includes(socket.user)) {
                channel.subscribers.push(socket.user);
                await channel.save();
                
                socket.join(`channel_${channelId}`);
                socket.emit('subscribed_to_channel', { channelId });
            }
        } catch (err) {
            console.error('Ошибка подписки:', err.message);
        }
    });

    socket.on('unsubscribe_channel', async (data) => {
        const { channelId } = data;
        
        try {
            const channel = await Channel.findById(channelId);
            if (!channel) return;
            
            channel.subscribers = channel.subscribers.filter(s => s !== socket.user);
            await channel.save();
            
            socket.leave(`channel_${channelId}`);
            socket.emit('unsubscribed_from_channel', { channelId });
        } catch (err) {
            console.error('Ошибка отписки:', err.message);
        }
    });

    socket.on('channel_post', async (data) => {
        const { channelId, text } = data;
        
        try {
            const channel = await Channel.findById(channelId);
            if (!channel) return socket.emit('error_msg', { text: "Канал не найден" });
            
            if (channel.admin !== socket.user) {
                return socket.emit('error_msg', { text: "Только администратор может писать в канал" });
            }
            
            const msg = new ChannelMessage({
                user: socket.user,
                channelId: channelId,
                text: text,
                time: new Date()
            });
            await msg.save();
            
            channel.views = (channel.views || 0) + 1;
            await channel.save();
            
            io.to(`channel_${channelId}`).emit('channel_msg', msg);
        } catch (err) {
            console.error('Ошибка отправки в канал:', err.message);
        }
    });

    socket.on('delete_channel', async (data) => {
        const { channelId } = data || {};
        if (!socket.user || !channelId) return;

        try {
            const channel = await Channel.findById(channelId);
            if (!channel) return socket.emit('channel_deleted', { channelId, error: 'Канал не найден' });
            if (channel.admin !== socket.user) return socket.emit('channel_deleted', { channelId, error: 'Только администратор может удалить канал' });

            await ChannelMessage.deleteMany({ channelId });
            await Channel.findByIdAndDelete(channelId);

            io.to(`channel_${channelId}`).emit('channel_deleted', { channelId });
            socket.emit('channel_deleted', { channelId });
        } catch (err) {
            console.error('Ошибка удаления канала:', err.message);
            socket.emit('channel_deleted', { channelId, error: err.message });
        }
    });

    socket.on('get_channel_history', async (channelId) => {
        try {
            const messages = await ChannelMessage.find({ channelId }).sort({ time: 1 }).lean();
            const channel = await Channel.findById(channelId);
            
            if (!channel) return socket.emit('error_msg', { text: "Канал не найден" });
            
            socket.emit('channel_history', {
                channelId,
                messages: messages || [],
                channel: {
                    name: channel.name,
                    description: channel.description,
                    subscribers: channel.subscribers?.length || 0,
                    views: channel.views || 0
                }
            });
        } catch (err) {
            console.error('Ошибка получения истории канала:', err.message);
        }
    });

    socket.on('create_invite_link', async (data) => {
        try {
            const { groupId, expiresIn, maxUses } = data;
            
            const group = await Group.findById(groupId);
            if (!group) return socket.emit('error_msg', { text: "Группа не найдена" });
            
            const isAdmin = group.admin === socket.user || (group.admins || []).includes(socket.user);
            if (!isAdmin) return socket.emit('error_msg', { text: "Недостаточно прав" });
            
            const code = crypto.randomBytes(8).toString('hex');
            
            const link = {
                code,
                createdBy: socket.user,
                createdAt: new Date(),
                maxUses: maxUses || 0,
                uses: 0
            };
            
            if (expiresIn && expiresIn > 0) {
                link.expiresAt = new Date(Date.now() + expiresIn * 24 * 60 * 60 * 1000);
            }
            
            if (!group.inviteLinks) group.inviteLinks = [];
            group.inviteLinks.push(link);
            await group.save();
            
            socket.emit('invite_link_created', {
                code,
                url: `https://whattgram-chat-2026.serveousercontent.com/join/${code}`,
                expiresAt: link.expiresAt,
                maxUses: link.maxUses
            });
        } catch (err) {
            console.error('Ошибка create_invite_link:', err.message);
            socket.emit('error_msg', { text: "Ошибка создания ссылки" });
        }
    });

    socket.on('make_admin', async (data) => {
        try {
            const { groupId, userId } = data;
            
            const group = await Group.findById(groupId);
            if (!group) return socket.emit('error_msg', { text: "Группа не найдена" });
            
            if (group.admin !== socket.user) {
                return socket.emit('error_msg', { text: "Только создатель группы может назначать администраторов" });
            }
            
            if (!group.members.includes(userId)) {
                return socket.emit('error_msg', { text: "Пользователь не в группе" });
            }
            
            if (!group.admins) group.admins = [];
            if (!group.admins.includes(userId)) {
                group.admins.push(userId);
                await group.save();
                
                io.to(groupId).emit('group_admin_added', { groupId, userId, by: socket.user });
                
                const updatedGroup = await Group.findById(groupId).lean();
                io.to(groupId).emit('receive_profile', {
                    user: groupId,
                    name: updatedGroup.name,
                    isGroup: true,
                    bio: updatedGroup.bio,
                    avatar: updatedGroup.avatar,
                    members: updatedGroup.members,
                    admin: updatedGroup.admin,
                    admins: updatedGroup.admins || [],
                    createdAt: updatedGroup.createdAt,
                    messageCount: updatedGroup.messageCount || 0
                });
            }
        } catch (err) {
            console.error('Ошибка make_admin:', err.message);
            socket.emit('error_msg', { text: "Ошибка назначения администратора" });
        }
    });

    socket.on('kick_from_group', async (data) => {
        try {
            const { groupId, userId } = data;
            
            const group = await Group.findById(groupId);
            if (!group) return socket.emit('error_msg', { text: "Группа не найдена" });
            
            const isAdmin = group.admin === socket.user || (group.admins || []).includes(socket.user);
            if (!isAdmin) return socket.emit('error_msg', { text: "Недостаточно прав" });
            
            if (userId === group.admin) {
                return socket.emit('error_msg', { text: "Нельзя удалить создателя группы" });
            }
            
            group.members = group.members.filter(m => m !== userId);
            if (group.admins) {
                group.admins = group.admins.filter(a => a !== userId);
            }
            
            await group.save();
            
            const userSocketId = onlineUsers[userId]?.socketId;
            if (userSocketId) {
                const userSocket = io.sockets.sockets.get(userSocketId);
                if (userSocket) userSocket.leave(groupId);
            }
            
            io.to(groupId).emit('group_member_kicked', { groupId, userId, by: socket.user });
            
            const systemMsg = new Message({
                user: "System",
                to: groupId,
                text: `Пользователь ${userId} удален из группы`,
                isGroup: true,
                time: new Date()
            });
            await systemMsg.save();
            io.to(groupId).emit('msg', systemMsg);
        } catch (err) {
            console.error('Ошибка kick_from_group:', err.message);
            socket.emit('error_msg', { text: "Ошибка удаления участника" });
        }
    });

    socket.on('get_group_stats', async (groupId) => {
        try {
            const group = await Group.findById(groupId);
            if (!group) return;
            
            const messageCount = await Message.countDocuments({ to: groupId, isGroup: true });
            const lastMessage = await Message.findOne({ to: groupId, isGroup: true }).sort({ time: -1 });
            
            socket.emit('group_stats', {
                groupId,
                memberCount: group.members?.length || 0,
                messageCount,
                createdAt: group.createdAt,
                lastMessageAt: lastMessage?.time || null,
                inviteLinksCount: group.inviteLinks?.length || 0
            });
        } catch (err) {
            console.error('Ошибка get_group_stats:', err.message);
        }
    });

    socket.on('create_group', async (data) => {
        if (!socket.user || !data || !data.name || typeof data.name !== 'string') return;
        
        const safeName = sanitize(data.name);
        if (!safeName || safeName.length < 1 || safeName.length > 50) return;
        
        try {
            const group = new Group({ 
                name: safeName, 
                admin: socket.user, 
                admins: [],
                members: [socket.user],
                bio: data.bio ? sanitize(data.bio).slice(0, 200) : "Групповой чат",
                inviteLinks: []
            });
            await group.save();
            
            socket.join(group._id.toString());
            
            socket.emit('group_created', { 
                id: group._id, 
                name: group.name,
                isGroup: true,
                admin: socket.user,
                admins: []
            });

            const systemMsg = new Message({
                user: "System",
                to: group._id.toString(),
                text: `Группа "${data.name}" создана пользователем ${socket.user}`,
                isGroup: true,
                time: new Date()
            });
            await systemMsg.save();
            io.to(group._id.toString()).emit('msg', systemMsg);
            
        } catch (err) {
            console.error("Ошибка при создании группы:", err.message);
            socket.emit('error_msg', { text: "Ошибка создания группы" });
        }
    });

    socket.on('add_to_group', async (data) => {
        try {
            const group = await Group.findById(data.groupId);
            
            if (!group) {
                return socket.emit('error_msg', { text: "Группа не найдена" });
            }
            
            const isAdmin = group.admin === socket.user || (group.admins || []).includes(socket.user);
            if (!isAdmin) {
                return socket.emit('error_msg', { text: "Недостаточно прав для добавления участников" });
            }
            
            if (!group.members.includes(data.userToAdd)) {
                group.members.push(data.userToAdd);
                await group.save();
                
                const targetSocketId = onlineUsers[data.userToAdd]?.socketId;
                if (targetSocketId) {
                    const targetSocket = io.sockets.sockets.get(targetSocketId);
                    if (targetSocket) {
                        targetSocket.join(group._id.toString());
                    }
                }
                
                io.to(group._id.toString()).emit('group_member_added', { 
                    groupId: group._id, 
                    user: data.userToAdd,
                    by: socket.user
                });
                
                const systemMsg = new Message({
                    user: "System",
                    to: group._id.toString(),
                    text: `Пользователь ${data.userToAdd} добавлен в группу`,
                    isGroup: true,
                    time: new Date()
                });
                await systemMsg.save();
                io.to(group._id.toString()).emit('msg', systemMsg);
                
                const updatedGroup = await Group.findById(group._id).lean();
                io.to(group._id.toString()).emit('receive_profile', {
                    user: group._id.toString(),
                    name: updatedGroup.name,
                    isGroup: true,
                    bio: updatedGroup.bio,
                    avatar: updatedGroup.avatar,
                    members: updatedGroup.members,
                    admin: updatedGroup.admin,
                    admins: updatedGroup.admins || [],
                    createdAt: updatedGroup.createdAt,
                    messageCount: updatedGroup.messageCount || 0
                });
            } else {
                socket.emit('error_msg', { text: "Пользователь уже в группе" });
            }
        } catch (err) {
            console.error('Ошибка add_to_group:', err.message);
            socket.emit('error_msg', { text: "Ошибка добавления участника" });
        }
    });

    socket.on('message_reaction', async (data) => {
        try {
            const { msgId, reactions } = data;
            
            const message = await Message.findById(msgId);
            if (message) {
                message.reactions = reactions;
                await message.save();
                
                if (message.isGroup) {
                    io.to(message.to).emit('message_reaction', {
                        msgId,
                        reactions,
                        to: message.to,
                        from: socket.user
                    });
                } else {
                    io.to(message.to).to(message.user).emit('message_reaction', {
                        msgId,
                        reactions,
                        to: message.to,
                        from: socket.user
                    });
                }
            }
        } catch (err) {
            console.error('Ошибка message_reaction:', err.message);
        }
    });

    socket.on('edit_message', async (data) => {
        try {
            const { msgId, newText } = data;
            
            const message = await Message.findById(msgId);
            if (!message) {
                return socket.emit('error_msg', { text: "Сообщение не найдено" });
            }
            
            if (message.user !== socket.user) {
                return socket.emit('error_msg', { text: "Нельзя редактировать чужие сообщения" });
            }
            
            if (!message.editHistory) message.editHistory = [];
            message.editHistory.push({
                text: message.text,
                editedAt: new Date()
            });
            
            message.text = newText;
            message.edited = true;
            
            await message.save();
            
            if (message.isGroup) {
                io.to(message.to).emit('message_edited', {
                    msgId,
                    newText,
                    edited: true,
                    to: message.to,
                    from: socket.user
                });
            } else {
                io.to(message.to).to(message.user).emit('message_edited', {
                    msgId,
                    newText,
                    edited: true,
                    to: message.to,
                    from: socket.user
                });
            }
        } catch (err) {
            console.error('Ошибка edit_message:', err.message);
            socket.emit('error_msg', { text: "Ошибка редактирования" });
        }
    });

    socket.on('get_message_history', async (msgId) => {
        try {
            const message = await Message.findById(msgId);
            if (message) {
                socket.emit('message_history', {
                    msgId,
                    history: message.editHistory || []
                });
            }
        } catch (err) {
            console.error('Ошибка get_message_history:', err.message);
        }
    });

    socket.on('delete_chat', async (data) => {
        try {
            const { chatId } = data;
            
            if (!socket.user) {
                socket.emit('chat_deleted', { chatId: chatId, error: 'no user' });
                return;
            }
            
            const isGroup = mongoose.Types.ObjectId.isValid(chatId);
            
            if (isGroup) {
                const group = await Group.findById(chatId);
                if (group && (group.admin === socket.user || (group.admins || []).includes(socket.user))) {
                    await Message.deleteMany({ to: chatId, isGroup: true });
                    socket.emit('chat_deleted', { chatId });
                } else {
                    socket.emit('chat_deleted', { chatId, error: 'no rights' });
                }
            } else {
                const result = await Message.deleteMany({
                    $or: [
                        { user: socket.user, to: chatId, isGroup: false },
                        { user: chatId, to: socket.user, isGroup: false }
                    ]
                });
                socket.emit('chat_deleted', { chatId, deleted: result.deletedCount });
            }
        } catch (err) {
            console.error('Ошибка delete_chat:', err.message);
            socket.emit('chat_deleted', { chatId: data.chatId, error: err.message });
        }
    });

    socket.on('delete_account', async () => {
        if (!socket.user) return;
        
        try {
            const username = socket.user;
            console.log(`>>> Удаление аккаунта: ${username}`);
            
            await Message.deleteMany({ 
                $or: [
                    { user: username },
                    { to: username }
                ] 
            });
            
            await Group.updateMany(
                { members: username },
                { $pull: { members: username, admins: username } }
            );
            
            const userChannels = await Channel.find({ admin: username });
            for (const channel of userChannels) {
                await ChannelMessage.deleteMany({ channelId: channel._id });
                await Channel.findByIdAndDelete(channel._id);
            }
            
            await Channel.updateMany(
                { subscribers: username },
                { $pull: { subscribers: username } }
            );
            
            const ownedGroups = await Group.find({ admin: username });
            for (const group of ownedGroups) {
                await Message.deleteMany({ to: group._id.toString(), isGroup: true });
                await Group.findByIdAndDelete(group._id);
            }
            
            await User.deleteOne({ login: username });
            console.log(`>>> Пользователь удален: ${username}`);
            
            delete onlineUsers[username];
            
            io.emit('online_list', Object.keys(onlineUsers).filter(u => onlineUsers[u]?.online));
            socket.emit('account_deleted');
            socket.disconnect();
            
        } catch (err) {
            console.error("Ошибка при удалении аккаунта:", err.message);
            socket.emit('error_msg', { text: "Ошибка при удалении аккаунта" });
        }
    });

    socket.on('msg', async (data) => {
        try {
            if (!socket.user || !data || !data.text || typeof data.text !== 'string') return;
            if (!rateLimit(`msg:${socket.user}`, 100, 60000)) {
                socket.emit('error_msg', { text: 'Слишком много сообщений. Попробуйте позже.' });
                return;
            }
            
            const safeText = sanitize(data.text);
            if (safeText.length > 5000) {
                socket.emit('error_msg', { text: 'Слишком длинное сообщение' });
                return;
            }
            
            const fromUser = sanitizeAndValidateLogin(data.user);
            const toUser = data.isGroup ? (isValidObjectId(data.to) ? data.to : null) : sanitizeAndValidateLogin(data.to);
            
            if (!fromUser || !toUser) return;
            
            if (data.user === SYSTEM_USER) {
                const users = await User.find({}, 'login');
                const now = new Date();
                const messages = users.map(u => ({
                    user: SYSTEM_USER,
                    to: u.login,
                    text: data.text,
                    type: data.type || 'text',
                    isGroup: false,
                    encrypted: data.encrypted || false,
                    time: now,
                    edited: false,
                    reactions: [],
                    editHistory: []
                }));

                await Message.insertMany(messages);

                for (const msg of messages) {
                    if (onlineUsers[msg.to] && onlineUsers[msg.to].online) {
                        io.to(msg.to).emit('msg', msg);
                    }
                }

                console.log(`>>> [SYSTEM] Рассылка от ${data.user}: "${data.text}" (${users.length} пользователей)`);
            } 
            else if (data.isGroup) {
                const m = new Message({ ...data, isGroup: true, reactions: [], editHistory: [] });
                await m.save();
                await Group.findByIdAndUpdate(data.to, { $inc: { messageCount: 1 } });
                io.to(data.to).emit('msg', m);
            } else {
                const recipient = await User.findOne({ login: data.to });
                const sender = await User.findOne({ login: data.user });
                if (recipient && recipient.blackList && recipient.blackList.includes(data.user)) return;
                if (sender && sender.blackList && sender.blackList.includes(data.to)) return;
                const m = new Message({ ...data, reactions: [], editHistory: [] });
                await m.save();
                io.to(data.to).to(data.user).emit('msg', m);
            }
        } catch (err) {
            console.error('Ошибка отправки сообщения:', err.message);
        }
    });

    socket.on('delete_msg', async (msgId) => {
        try {
            const msg = await Message.findById(msgId);
            if (msg && msg.user === socket.user) {
                await Message.findByIdAndDelete(msgId);
                if (msg.isGroup) {
                    io.to(msg.to).emit('msg_deleted', msgId);
                } else {
                    io.to(msg.to).to(msg.user).emit('msg_deleted', msgId);
                }
            }
        } catch (err) {
            console.error('Ошибка удаления сообщения:', err.message);
        }
    });

    socket.on('read_messages', async (data) => {
        try {
            if(!socket.user) return;
            await Message.updateMany(
                { user: data.from, to: socket.user, read: false },
                { $set: { read: true } }
            );
            io.to(data.from).emit('messages_marked_read', { by: socket.user });
        } catch (err) {
            console.error('Ошибка read_messages:', err.message);
        }
    });

    socket.on('typing', (data) => {
        try {
            if (data.to) socket.to(data.to).emit('display_typing', { from: data.from });
        } catch (err) {
            console.error('Ошибка typing:', err.message);
        }
    });

    socket.on('toggle_blacklist', async (targetUser) => {
        try {
            if(!socket.user) return;
            const user = await User.findOne({ login: socket.user });
            if (!user.blackList) user.blackList = [];
            
            if (user.blackList.includes(targetUser)) {
                user.blackList = user.blackList.filter(u => u !== targetUser);
            } else {
                user.blackList.push(targetUser);
            }
            await user.save();
            sendSecurityUpdate(socket);
        } catch (err) {
            console.error('Ошибка toggle_blacklist:', err.message);
        }
    });

    socket.on('unblock_user', async (targetUser) => {
        try {
            if(!socket.user) return;
            const user = await User.findOne({ login: socket.user });
            if (user.blackList && user.blackList.includes(targetUser)) {
                user.blackList = user.blackList.filter(u => u !== targetUser);
                await user.save();
                sendSecurityUpdate(socket);
            }
        } catch (err) {
            console.error('Ошибка unblock_user:', err.message);
        }
    });

    socket.on('terminate_session', async (socketId) => {
        try {
            const user = await User.findOne({ login: socket.user });
            if (user) {
                user.sessions = user.sessions.filter(s => s.socketId !== socketId);
                await user.save();
                io.sockets.sockets.get(socketId)?.disconnect();
                sendSecurityUpdate(socket);
            }
        } catch (err) {
            console.error('Ошибка terminate_session:', err.message);
        }
    });

    socket.on('get_security_data', async () => {
        try {
            sendSecurityUpdate(socket);
        } catch (err) {
            console.error('Ошибка get_security_data:', err.message);
        }
    });

    socket.on('get_last_seen', async (login) => {
        try {
            if (!socket.user || !login) return;
            
            const safeLogin = sanitizeAndValidateLogin(login);
            if (!safeLogin) return;
            
            if (onlineUsers[safeLogin] && onlineUsers[safeLogin].online) {
                socket.emit('last_seen_data', { login: safeLogin, online: true });
                return;
            }
            
            const user = await User.findOne({ login: safeLogin }).lean();
            if (user && user.sessions && user.sessions.length > 0) {
                const lastSeen = user.sessions
                    .map(s => s.lastSeen)
                    .sort((a, b) => new Date(b) - new Date(a))[0];
                
                socket.emit('last_seen_data', { 
                    login, 
                    online: false,
                    lastSeen: lastSeen || user.createdAt
                });
            }
        } catch (err) {
            console.error('Ошибка get_last_seen:', err.message);
        }
    });

    socket.on('get_profile', async (data) => {
        try {
            if (!data || !data.target) return;
            
            let target = data.target;
            let group = null;
            
            if (mongoose.Types.ObjectId.isValid(target) && isValidObjectId(target)) {
                group = await Group.findById(target).catch(() => null);
            }

            if (group) {
                const messageCount = await Message.countDocuments({ to: group._id.toString(), isGroup: true });
                const lastMessage = await Message.findOne({ to: group._id.toString(), isGroup: true }).sort({ time: -1 });
                
                return socket.emit('receive_profile', {
                    user: group._id.toString(),
                    name: group.name,
                    isGroup: true,
                    bio: group.bio || "Групповой чат",
                    avatar: group.avatar,
                    members: group.members || [],
                    admin: group.admin,
                    admins: group.admins || [],
                    createdAt: group.createdAt,
                    messageCount: messageCount,
                    lastMessageAt: lastMessage?.time || null,
                    inviteLinks: group.inviteLinks || []
                });
            }
            
            const targetUser = await User.findOne({ login: data.target }).lean();
            const me = await User.findOne({ login: socket.user }).lean();
            
            if (targetUser && me) {
                console.log(`>>> [GET_PROFILE] target=${targetUser.login}, bio="${targetUser.bio}"`);
                const tBL = targetUser.blackList || [];
                const myBL = me.blackList || [];
                
                socket.emit('receive_profile', {
                    user: targetUser.login, 
                    bio: targetUser.bio, 
                    avatar: targetUser.avatar,
                    amIBlocked: tBL.includes(socket.user),
                    didIBlock: myBL.includes(data.target)
                });
            } else if (!targetUser) {
                socket.emit('receive_profile', {
                    user: data.target,
                    bio: "Пользователь не найден",
                    isNotFound: true
                });
            }
        } catch (err) {
            console.error('Ошибка get_profile:', err.message);
        }
    });

    socket.on('update_profile', async (data) => {
        try {
            if(!socket.user) return;
            console.log(`>>> [UPDATE_PROFILE] user=${socket.user}, bio="${data.bio}", avatar=${data.avatar ? 'set' : 'undefined'}`);
            
            if (data.groupId) {
                const group = await Group.findById(data.groupId);
                if (group && (group.admin === socket.user || (group.admins || []).includes(socket.user))) {
                    const updates = {};
                    if (data.bio !== undefined) updates.bio = data.bio;
                    if (data.avatar !== undefined) updates.avatar = data.avatar;
                    if (data.name !== undefined) updates.name = data.name;
                    
                    await Group.findByIdAndUpdate(data.groupId, updates);
                    
                    const updatedGroup = await Group.findById(data.groupId).lean();
                    io.to(data.groupId).emit('profile_updated', { 
                        user: data.groupId,
                        ...updates,
                        isGroup: true,
                        members: updatedGroup.members,
                        admin: updatedGroup.admin,
                        admins: updatedGroup.admins
                    });
                }
            } else {
                const updates = {};
                if (data.bio !== undefined) updates.bio = data.bio;
                if (data.avatar !== undefined) updates.avatar = data.avatar;
                await User.findOneAndUpdate({ login: socket.user }, updates);
                io.emit('profile_updated', { user: socket.user, ...updates });
            }
        } catch (err) {
            console.error('Ошибка update_profile:', err.message);
        }
    });

    socket.on('call-offer', (data) => {
        try {
            const { to, offer } = data;
            console.log(`>>> [CALL] Offer от ${socket.user} для ${to}`);
            
            const recipient = onlineUsers[to];
            if (!recipient) {
                socket.emit('call-error', { text: 'Пользователь не в сети' });
                return;
            }
            
            io.to(to).emit('incoming-call', {
                from: socket.user,
                offer: offer
            });
        } catch (err) {
            console.error('Ошибка call-offer:', err.message);
        }
    });

    socket.on('call-answer', (data) => {
        try {
            const { to, answer } = data;
            console.log(`>>> [CALL] Answer от ${socket.user} для ${to}`);
            io.to(to).emit('call-answered', {
                from: socket.user,
                answer: answer
            });
        } catch (err) {
            console.error('Ошибка call-answer:', err.message);
        }
    });

    socket.on('call-ice', (data) => {
        try {
            const { to, candidate } = data;
            io.to(to).emit('call-ice', {
                from: socket.user,
                candidate: candidate
            });
        } catch (err) {
            console.error('Ошибка call-ice:', err.message);
        }
    });

    socket.on('call-end', (data) => {
        try {
            const { to } = data;
            console.log(`>>> [CALL] Завершение звонка от ${socket.user}`);
            io.to(to).emit('call-ended', { from: socket.user });
        } catch (err) {
            console.error('Ошибка call-end:', err.message);
        }
    });

    socket.on('call-reject', (data) => {
        try {
            const { to } = data;
            console.log(`>>> [CALL] Отказ от звонка от ${socket.user}`);
            io.to(to).emit('call-rejected', { from: socket.user });
        } catch (err) {
            console.error('Ошибка call-reject:', err.message);
        }
    });

    async function handleUserDisconnect(username, socketId) {
        try {
            if (!onlineUsers[username]) {
                delete onlineUsers[username];
                io.emit('online_list', Object.keys(onlineUsers).filter(u => onlineUsers[u]?.online));
                return;
            }
            
            await User.findOneAndUpdate(
                { login: username, 'sessions.socketId': socketId },
                { $pull: { sessions: { socketId: socketId } } }
            );
            
            const user = await User.findOne({ login: username }).lean();
            if (user && user.sessions && user.sessions.length > 0) {
                const activeSession = user.sessions.find(s => {
                    const sessionSocket = io.sockets.sockets.get(s.socketId);
                    return sessionSocket && sessionSocket.connected;
                });
                
                if (activeSession) {
                    onlineUsers[username] = {
                        socketId: activeSession.socketId,
                        lastSeen: new Date(),
                        online: true
                    };
                } else {
                    delete onlineUsers[username];
                }
            } else {
                delete onlineUsers[username];
            }
            
            io.emit('online_list', Object.keys(onlineUsers).filter(u => onlineUsers[u]?.online));
        } catch (err) {
            console.error('Ошибка handleUserDisconnect:', err.message);
            delete onlineUsers[username];
            io.emit('online_list', Object.keys(onlineUsers).filter(u => onlineUsers[u]?.online));
        }
    }
});

const PORT = process.env.PORT || 3000;
server.on('error', (err) => {
    console.error(`>>> [SERVER] Ошибка: ${err.message}`);
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`>>> [SERVER] Запуск на порту ${PORT}`);
    initSystemUser();
});