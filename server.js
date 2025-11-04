require('dotenv').config();
const express = require('express');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const fetch = require('node-fetch');

const app = express();
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const JWT_EXPIRES = '1h';

// OTP store
const otps = {};

// storing users info
const USERS_FILE = path.join(__dirname, 'users.json');

// Safe read/write functions
function readUsers() {
    if (!fs.existsSync(USERS_FILE)) return {};
    try {
        const data = fs.readFileSync(USERS_FILE, 'utf8');
        return data ? JSON.parse(data) : {};
    } catch (err) {
        console.error('Error reading users.json:', err);
        return {};
    }
}

function writeUsers(users) {
    try {
        fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
    } catch (err) {
        console.error('Error writing users.json:', err);
    }
}

// OTP generator
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000).toString();
}

// Send OTP email
async function sendOTPEmail(userEmail, otp) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS
        }
    });

    await transporter.sendMail({
        from: `"AuthSystem" <${process.env.EMAIL_USER}>`,
        to: userEmail,
        subject: "AuthSystem",
        text: `Your verification code is: ${otp} 
It expires in 3 minutes.`
    });
}

// Serve static files
app.use(express.static(__dirname));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/protected.html', (req, res) => res.sendFile(path.join(__dirname, 'protected.html')));

app.get('/me', (req, res) => {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Bearer ')) return res.status(401).json({ error: 'Missing token' });

    const token = header.slice(7);
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ ok: true, user: decoded });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

// REGISTER
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body || {};
    if (!username || !email || !password) return res.status(400).json({ error: 'Missing fields' });

    const users = readUsers();
    if (users[username]) return res.status(400).json({ error: 'User already exists' });

    const passwordHash = await bcrypt.hash(password, 10);
    users[username] = { username, email, passwordHash, token: null };

    writeUsers(users);
    res.json({ ok: true, message: 'Registered successfully' });
});

// LOGIN
app.post('/login', async (req, res) => {
    const { username, password, recaptcha } = req.body || {};
    if (!username || !password || !recaptcha) {
        return res.status(400).json({ error: 'Missing fields or reCAPTCHA' });
    }

    // Verify reCAPTCHA with Google
    const secret = process.env.RECAPTCHA_SECRET;
    const recaptchaVerifyUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secret}&response=${recaptcha}`;

    try {
        const recaptchaRes = await fetch(recaptchaVerifyUrl, { method: 'POST' });
        const recaptchaData = await recaptchaRes.json();

        if (!recaptchaData.success) {
            return res.status(400).json({ error: 'reCAPTCHA verification failed' });
        }
    } catch (err) {
        console.error('reCAPTCHA error:', err);
        return res.status(500).json({ error: 'Failed to verify reCAPTCHA' });
    }

    // Continue login logic
    const users = readUsers();
    const user = users[username];
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Generate OTP
    const otp = generateOTP();
    otps[username] = { otp, expiry: Date.now() + 3 * 60 * 1000 };

    try {
        await sendOTPEmail(user.email, otp);
        res.json({ ok: true, message: 'OTP sent to your email' });
    } catch (err) {
        console.error('Email send error:', err);
        res.status(500).json({ error: 'Failed to send OTP email' });
    }
});

// VERIFY OTP
app.post('/verify-otp', (req, res) => {
    const { username, otp } = req.body || {};
    if (!username || !otp) return res.status(400).json({ error: 'Missing fields' });

    const record = otps[username];
    if (!record) return res.status(401).json({ error: 'OTP not found. Please login again.' });
    if (record.otp !== otp) return res.status(401).json({ error: 'Invalid OTP' });
    if (Date.now() > record.expiry) return res.status(401).json({ error: 'OTP expired' });

    const users = readUsers();
    const user = users[username];
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const token = jwt.sign({ username: user.username, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES });

    user.token = token;
    writeUsers(users);

    delete otps[username];
    res.json({ ok: true, token });
});

// VERIFY TOKEN endpoint
app.post('/verify-token', (req, res) => {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'Missing token' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        res.json({ valid: true, decoded });
    } catch (err) {
        res.status(401).json({ valid: false, error: err.message });
    }
});

// LOGOUT endpoint
app.post('/logout', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: 'Missing username' });

    const users = readUsers();
    if (users[username]) {
        users[username].token = null;
        writeUsers(users);
        return res.json({ ok: true, message: 'Logged out' });
    }
    res.status(404).json({ error: 'User not found' });
});

// FORGOT PASSWORD
app.post('/forgot-password', async (req, res) => {
    const { username } = req.body || {};
    if (!username) return res.status(400).json({ error: 'Missing username' });

    const users = readUsers();
    const user = users[username];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const otp = generateOTP();
    otps[username] = { otp, expiry: Date.now() + 3 * 60 * 1000, type: 'reset' };

    try {
        await sendOTPEmail(user.email, otp);
        res.json({ ok: true, message: 'Reset OTP sent to your email' });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to send reset OTP' });
    }
});

// RESET PASSWORD
app.post('/reset-password', async (req, res) => {
    const { username, otp, newPassword } = req.body || {};
    if (!username || !otp || !newPassword)
        return res.status(400).json({ error: 'Missing fields' });

    const record = otps[username];
    if (!record || record.type !== 'reset')
        return res.status(401).json({ error: 'No reset OTP found' });
    if (record.otp !== otp)
        return res.status(401).json({ error: 'Invalid OTP' });
    if (Date.now() > record.expiry)
        return res.status(401).json({ error: 'OTP expired' });

    const users = readUsers();
    const user = users[username];
    if (!user) return res.status(404).json({ error: 'User not found' });

    const passwordHash = await bcrypt.hash(newPassword, 10);
    user.passwordHash = passwordHash;
    writeUsers(users);
    delete otps[username];

    res.json({ ok: true, message: 'Password reset successfully' });
});


// Server Start Log
app.listen(3000, () => console.log('✅ Server running on http://localhost:3000'));
