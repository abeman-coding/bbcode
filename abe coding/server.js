const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const app = express();

// ==================== MIDDLEWARE ====================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// ==================== DATABASE CONNECTION ====================
mongoose.connect(process.env.MONGODB_URI)
    .then(() => console.log('✅ MongoDB Connected Successfully'))
    .catch(err => console.error('❌ MongoDB Connection Error:', err));

// ==================== USER SCHEMA ====================
const userSchema = new mongoose.Schema({
    // Authentication
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    
    // Personal Information
    personalInfo: {
        firstName: { type: String, required: true },
        lastName: { type: String, required: true },
        dateOfBirth: Date,
        gender: { type: String, enum: ['male', 'female', 'other', 'prefer-not-to-say'] },
        phoneNumber: String,
        bio: String
    },
    
    // Address
    address: {
        street: String,
        city: String,
        state: String,
        country: String,
        zipCode: String
    },
    
    // Professional
    professional: {
        occupation: String,
        company: String,
        experience: Number,
        skills: [String],
        education: [{
            degree: String,
            institution: String,
            year: Number,
            grade: String
        }]
    },
    
    // Social Links
    social: {
        linkedin: String,
        github: String,
        twitter: String,
        facebook: String,
        instagram: String,
        website: String
    },
    
    // Preferences
    preferences: {
        newsletter: { type: Boolean, default: false },
        language: { type: String, default: 'en' },
        theme: { type: String, enum: ['light', 'dark'], default: 'light' },
        notifications: { type: Boolean, default: true }
    },
    
    // Account Stats
    stats: {
        lastLogin: Date,
        loginCount: { type: Number, default: 0 },
        isActive: { type: Boolean, default: true },
        profileViews: { type: Number, default: 0 }
    },
    
    // Timestamps
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now }
});

// Update timestamp on save
userSchema.pre('save', function(next) {
    this.updatedAt = Date.now();
    next();
});

const User = mongoose.model('User', userSchema);

// ==================== AUTH MIDDLEWARE ====================
const requireAuth = (req, res, next) => {
    if (!req.session.userId) {
        return res.status(401).json({ error: 'Please login to continue' });
    }
    next();
};

// ==================== ROUTES - HTML PAGES ====================
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ==================== API ROUTES - AUTHENTICATION ====================

// Register User
app.post('/api/register', async (req, res) => {
    try {
        const { email, password, firstName, lastName, phoneNumber } = req.body;

        // Validation
        if (!email || !password || !firstName || !lastName) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters' });
        }

        // Check existing user
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already registered' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            email,
            password: hashedPassword,
            personalInfo: {
                firstName,
                lastName,
                phoneNumber: phoneNumber || ''
            }
        });

        await user.save();

        // Set session
        req.session.userId = user._id;
        req.session.userEmail = user.email;

        res.status(201).json({ 
            message: 'Registration successful!',
            user: {
                id: user._id,
                name: `${user.personalInfo.firstName} ${user.personalInfo.lastName}`,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration' });
    }
});

// Login User
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validation
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Find user
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Check password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ error: 'Invalid email or password' });
        }

        // Update stats
        user.stats.lastLogin = new Date();
        user.stats.loginCount += 1;
        await user.save();

        // Set session
        req.session.userId = user._id;
        req.session.userEmail = user.email;

        res.json({ 
            message: 'Login successful!',
            user: {
                id: user._id,
                name: `${user.personalInfo.firstName} ${user.personalInfo.lastName}`,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ message: 'Logout successful' });
    });
});

// Check Auth Status
app.get('/api/auth/status', (req, res) => {
    if (req.session.userId) {
        res.json({ authenticated: true });
    } else {
        res.json({ authenticated: false });
    }
});

// ==================== API ROUTES - USER DATA ====================

// Get Complete User Profile
app.get('/api/user/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('-password');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ user });
    } catch (error) {
        console.error('Error fetching profile:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Dashboard Data
app.get('/api/user/dashboard', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId).select('personalInfo email stats createdAt');
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        // Calculate profile completion
        const fields = [
            user.personalInfo.firstName,
            user.personalInfo.lastName,
            user.personalInfo.phoneNumber,
            user.personalInfo.bio,
            user.address?.street,
            user.address?.city,
            user.address?.country,
            user.professional?.occupation,
            user.professional?.company,
            user.social?.linkedin,
            user.social?.github
        ].filter(Boolean).length;

        const totalFields = 15;
        const completion = Math.round((fields / totalFields) * 100);

        res.json({
            user: {
                name: `${user.personalInfo.firstName} ${user.personalInfo.lastName}`,
                email: user.email,
                memberSince: user.createdAt,
                lastLogin: user.stats.lastLogin,
                loginCount: user.stats.loginCount,
                profileCompletion: completion
            }
        });
    } catch (error) {
        console.error('Error fetching dashboard:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Personal Information
app.put('/api/user/personal', requireAuth, async (req, res) => {
    try {
        const { firstName, lastName, dateOfBirth, gender, phoneNumber, bio } = req.body;
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.personalInfo = {
            ...user.personalInfo,
            firstName: firstName || user.personalInfo.firstName,
            lastName: lastName || user.personalInfo.lastName,
            dateOfBirth: dateOfBirth || user.personalInfo.dateOfBirth,
            gender: gender || user.personalInfo.gender,
            phoneNumber: phoneNumber || user.personalInfo.phoneNumber,
            bio: bio || user.personalInfo.bio
        };

        await user.save();
        res.json({ 
            message: 'Personal information updated',
            personalInfo: user.personalInfo
        });
    } catch (error) {
        console.error('Error updating personal info:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Address
app.put('/api/user/address', requireAuth, async (req, res) => {
    try {
        const { street, city, state, country, zipCode } = req.body;
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.address = { street, city, state, country, zipCode };
        await user.save();
        
        res.json({ 
            message: 'Address updated',
            address: user.address
        });
    } catch (error) {
        console.error('Error updating address:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Professional Information
app.put('/api/user/professional', requireAuth, async (req, res) => {
    try {
        const { occupation, company, experience, skills } = req.body;
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.professional = {
            ...user.professional,
            occupation: occupation || user.professional?.occupation,
            company: company || user.professional?.company,
            experience: experience || user.professional?.experience,
            skills: skills ? skills.split(',').map(s => s.trim()) : user.professional?.skills
        };

        await user.save();
        
        res.json({ 
            message: 'Professional information updated',
            professional: user.professional
        });
    } catch (error) {
        console.error('Error updating professional info:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Add Education
app.post('/api/user/education', requireAuth, async (req, res) => {
    try {
        const { degree, institution, year, grade } = req.body;
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        if (!user.professional) {
            user.professional = {};
        }
        if (!user.professional.education) {
            user.professional.education = [];
        }

        user.professional.education.push({ degree, institution, year, grade });
        await user.save();
        
        res.json({ 
            message: 'Education added',
            education: user.professional.education
        });
    } catch (error) {
        console.error('Error adding education:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Social Links
app.put('/api/user/social', requireAuth, async (req, res) => {
    try {
        const { linkedin, github, twitter, facebook, instagram, website } = req.body;
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.social = { linkedin, github, twitter, facebook, instagram, website };
        await user.save();
        
        res.json({ 
            message: 'Social links updated',
            social: user.social
        });
    } catch (error) {
        console.error('Error updating social links:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// Update Preferences
app.put('/api/user/preferences', requireAuth, async (req, res) => {
    try {
        const { newsletter, language, theme, notifications } = req.body;
        
        const user = await User.findById(req.session.userId);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        user.preferences = {
            newsletter: newsletter !== undefined ? newsletter : user.preferences.newsletter,
            language: language || user.preferences.language,
            theme: theme || user.preferences.theme,
            notifications: notifications !== undefined ? notifications : user.preferences.notifications
        };

        await user.save();
        
        res.json({ 
            message: 'Preferences updated',
            preferences: user.preferences
        });
    } catch (error) {
        console.error('Error updating preferences:', error);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== START SERVER ====================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
    console.log(`📝 Register at: http://localhost:${PORT}#register`);
    console.log(`🔑 Login at: http://localhost:${PORT}#login`);
});