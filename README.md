# AdventureNearMe
# 🏔️ AdventuresNearMe - New York State Outdoor Adventures Platform

A modern, AI-powered web application for discovering and exploring outdoor adventures across New York State. Features personalized recommendations, secure authentication, and an intuitive interface for adventure enthusiasts.

![Project Status](https://img.shields.io/badge/status-demo-yellow)
![Security](https://img.shields.io/badge/security-enhanced-green)
![License](https://img.shields.io/badge/license-MIT-blue)

---

## 📋 Table of Contents

- [Features](#-features)
- [Demo Screenshots](#-demo-screenshots)
- [Technology Stack](#-technology-stack)
- [Project Structure](#-project-structure)
- [Getting Started](#-getting-started)
- [Security Features](#-security-features)
- [AI Integration](#-ai-integration)
- [Documentation](#-documentation)
- [Limitations](#-limitations)
- [Production Deployment](#-production-deployment)
- [Future Enhancements](#-future-enhancements)
- [Contributing](#-contributing)
- [License](#-license)

---

## ✨ Features

### 🗺️ Adventure Discovery
- **53 Curated Adventures** across 9 NY State regions
- **Multi-Criteria Filtering**: Region, activity type, difficulty, season
- **Smart Sorting**: By popularity or difficulty level
- **Seasonal Activities**: Spring, summer, fall, and winter adventures
- **Detailed Information**: Group size, difficulty ratings, descriptions

### 🤖 AI-Powered Recommendations
- **Personalized Suggestions** using Claude AI
- **Preference-Based Matching**: Fitness level, group type, season, interests
- **Match Scores**: 0-100% compatibility ratings
- **AI Explanations**: Detailed reasons for each recommendation
- **Real-Time Generation**: Dynamic, contextual suggestions

### 🔐 Enhanced Security & Authentication
- **Password Hashing**: SHA-256 encryption
- **Strong Password Requirements**: 8+ characters, mixed case, numbers, special chars
- **Rate Limiting**: 5 login attempts per 15 minutes
- **Account Locking**: Auto-lock after failed attempts
- **Session Management**: JWT-like tokens with auto-logout
- **Password Reset**: Secure token-based recovery
- **Security Logging**: Comprehensive event tracking

### 💾 User Features
- **Save Favorites**: Bookmark adventures for later
- **Persistent Storage**: Cross-session data retention
- **User Profiles**: Personal account management
- **Statistics Dashboard**: Track saved adventures

### 🎨 User Experience
- **Responsive Design**: Mobile, tablet, and desktop optimized
- **Clean Interface**: Modern, intuitive UI
- **Real-Time Feedback**: Password strength indicators, validation
- **Smooth Animations**: Professional transitions and effects
- **Accessibility**: ARIA labels, keyboard navigation

---

## 📸 Demo Screenshots

### Adventure Browsing
Browse through 53 outdoor adventures with advanced filtering options.

### AI Recommendations
Get personalized suggestions based on your preferences and fitness level.

### Saved Adventures
Track and manage your favorite adventures with a beautiful dashboard.

### Security Features
Secure login with password strength validation and comprehensive error handling.

---

## 🛠️ Technology Stack

### Frontend
- **HTML5**: Semantic markup
- **CSS3**: Modern styling with Flexbox/Grid
- **JavaScript (ES6+)**: Async/await, Promises, Classes
- **Web Crypto API**: Password hashing
- **localStorage API**: Client-side data persistence

### AI Integration
- **Anthropic Claude API**: AI-powered recommendations
- **Claude Sonnet 4**: Latest model for personalization
- **JSON Parsing**: Structured data extraction

### Security
- **SHA-256**: Password hashing
- **JWT-like Tokens**: Session management
- **XSS Prevention**: Input sanitization
- **CSRF Protection**: Token-based verification
- **Rate Limiting**: Client-side implementation

---

## 📁 Project Structure

```
AdventuresNearMe/
├── 📄 location.html              # Main adventures browsing page
├── 📄 saved.html                 # Saved adventures dashboard
├── 📄 recommendations.html       # AI recommendations page
├── 📄 signup.html                # User registration
├── 📄 login.html                 # User authentication
├── 📄 reset-password.html        # Password recovery
│
├── 🎨 styles.css                 # Shared stylesheet (28 KB)
│
├── 🔒 security.js                # Core security utilities (11 KB)
│   ├── Password hashing
│   ├── JWT token generation
│   ├── Input sanitization
│   ├── Rate limiting
│   └── Security logging
│
├── 🔐 auth.js                    # Authentication manager (19 KB)
│   ├── User registration
│   ├── Login/logout
│   ├── Session management
│   ├── Password reset
│   └── Account protection
│
└── 📚 Documentation/
    ├── README.md                 # This file
    ├── SECURITY.md               # Complete security docs
    ├── QUICK_START.md            # Getting started guide
    ├── SECURITY_SUMMARY.md       # Security overview
    ├── FILE_STRUCTURE.md         # File organization
    └── SIGNUP_COMPARISON.md      # Version comparison
```

---

## 🚀 Getting Started

### Prerequisites
- Modern web browser (Chrome, Firefox, Safari, Edge)
- No server required (runs entirely client-side)
- No dependencies or build tools needed

### Installation

1. **Download/Clone the Project**
   ```bash
   git clone https://github.com/yourusername/adventures-near-me.git
   cd adventures-near-me
   ```

2. **Open in Browser**
   ```bash
   # Simply open any HTML file in your browser
   open signup.html
   # or
   open location.html
   ```

3. **No Build Process Required!**
   - All files are ready to use
   - No npm install needed
   - No compilation required

### Quick Start Guide

1. **Create an Account**
   - Open `signup.html`
   - Fill in your details
   - Choose a strong password
   - Accept terms and create account

2. **Browse Adventures**
   - Automatically redirected to `location.html`
   - Use filters to find adventures
   - Save your favorites

3. **Get AI Recommendations**
   - Visit `recommendations.html`
   - Fill out preference form
   - Get personalized suggestions from Claude AI

4. **Manage Saved Adventures**
   - Visit `saved.html`
   - View your saved collection
   - Remove or explore more

---

## 🔒 Security Features

### Password Security
```javascript
✓ SHA-256 hashing (client-side demo)
✓ Minimum 8 characters required
✓ Uppercase and lowercase letters
✓ Numbers and special characters
✓ Common password blocking
✓ Real-time strength indicator
```

### Account Protection
```javascript
✓ Rate limiting: 5 attempts per 15 minutes
✓ Account auto-lock after 5 failed logins
✓ 15-minute lockout duration
✓ Failed attempt tracking
✓ Suspicious activity detection
```

### Session Management
```javascript
✓ JWT-like access tokens (24 hours)
✓ Refresh tokens (7 days optional)
✓ Auto-logout after 30 minutes
✓ Activity-based session refresh
✓ Token expiration validation
```

### Security Logging
```javascript
✓ All authentication events logged
✓ LOGIN_SUCCESS / LOGIN_FAILED
✓ ACCOUNT_LOCKED / PASSWORD_RESET
✓ SESSION_TIMEOUT
✓ Last 100 events stored
```

### Input Validation
```javascript
✓ Email format validation
✓ XSS prevention (HTML escaping)
✓ Input sanitization
✓ CSRF token generation
✓ Password confirmation matching
```

---

## 🤖 AI Integration

### Claude API Integration

The application uses the Anthropic Claude API for personalized recommendations.

**Features:**
- Real-time AI analysis of user preferences
- Contextual adventure matching
- Detailed explanation generation
- Match score calculation (0-100%)

**How It Works:**

1. **User Input**: Collects preferences (fitness, interests, season, etc.)
2. **API Call**: Sends preferences + adventure data to Claude
3. **AI Processing**: Claude analyzes and ranks adventures
4. **Response**: Returns top 5 matches with reasons
5. **Display**: Shows personalized recommendations

**Example API Call:**
```javascript
const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
        "Content-Type": "application/json",
    },
    body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 2000,
        messages: [{ 
            role: "user", 
            content: `Recommend adventures for: ${preferences}` 
        }]
    })
});
```

**Note**: API key is handled on the backend (not exposed client-side).

---

## 📚 Documentation

Comprehensive documentation is provided:

### Core Documentation
- **[SECURITY.md](SECURITY.md)** - Complete security reference (12 KB)
  - Authentication flows
  - Security best practices
  - Code examples
  - Production requirements

- **[QUICK_START.md](QUICK_START.md)** - Getting started guide (8.2 KB)
  - Feature overview
  - Usage instructions
  - Testing checklist
  - Common issues

- **[SECURITY_SUMMARY.md](SECURITY_SUMMARY.md)** - Security overview (15 KB)
  - High-level features
  - Data structures
  - Usage examples
  - Metrics

### Additional Resources
- **[FILE_STRUCTURE.md](FILE_STRUCTURE.md)** - Project organization
- **[SIGNUP_COMPARISON.md](SIGNUP_COMPARISON.md)** - Version differences

---

## ⚠️ Limitations

### Critical Limitations

#### ❌ **Client-Side Only**
- All logic runs in browser
- No server validation
- Can be bypassed with dev tools
- Not suitable for production

#### ❌ **Password Hashing**
- Uses SHA-256 (not suitable for passwords)
- Should use bcrypt/Argon2 in production
- No salt (vulnerable to rainbow tables)
- Client-side hashing can be inspected

#### ❌ **Data Storage**
- localStorage is not encrypted
- Data visible in browser dev tools
- No backup or recovery
- Limited storage (5-10 MB)

#### ❌ **No Backend**
- No server-side validation
- No database
- No API endpoints
- No email functionality (simulated)

#### ❌ **Rate Limiting**
- Client-side only
- Can be easily bypassed
- No distributed rate limiting
- No IP-based blocking

#### ❌ **Session Security**
- No server-side sessions
- Can't force logout globally
- No concurrent session control
- Tokens stored in localStorage

### Use Case Suitability

✅ **Good For:**
- Learning and education
- Prototyping and demos
- Understanding auth concepts
- Local development
- Portfolio projects

❌ **Not Good For:**
- Production deployment
- Real user data
- Commercial applications
- Sensitive information
- Compliance requirements (GDPR, HIPAA, etc.)

---

## 🚀 Production Deployment

### Required Changes for Production

To deploy this application to production, you **MUST** implement:

#### 1. Backend Infrastructure
```javascript
// Node.js + Express example
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const app = express();

// Password hashing
const hash = await bcrypt.hash(password, 10);

// JWT tokens
const token = jwt.sign(
    { userId: user.id },
    process.env.JWT_SECRET,
    { expiresIn: '24h' }
);
```

#### 2. Database Setup
```sql
-- PostgreSQL schema example
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_attempts INTEGER DEFAULT 0
);

CREATE TABLE adventures (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    region VARCHAR(100) NOT NULL,
    activity VARCHAR(50) NOT NULL,
    difficulty VARCHAR(50) NOT NULL,
    -- ... other fields
);

CREATE TABLE saved_adventures (
    user_id INTEGER REFERENCES users(id),
    adventure_id INTEGER REFERENCES adventures(id),
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, adventure_id)
);
```

#### 3. Security Implementation
```javascript
// Helmet for security headers
const helmet = require('helmet');
app.use(helmet());

// CORS configuration
const cors = require('cors');
app.use(cors({
    origin: process.env.FRONTEND_URL,
    credentials: true
}));

// Rate limiting
const rateLimit = require('express-rate-limit');
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5
});
app.use('/api/auth/login', limiter);

// HTTPS enforcement
app.use((req, res, next) => {
    if (req.header('x-forwarded-proto') !== 'https') {
        res.redirect(`https://${req.header('host')}${req.url}`);
    } else {
        next();
    }
});
```

#### 4. Environment Variables
```bash
# .env file
DATABASE_URL=postgresql://user:pass@localhost/adventures
JWT_SECRET=your-super-secret-key-here
JWT_EXPIRY=24h
REFRESH_TOKEN_EXPIRY=7d
ANTHROPIC_API_KEY=your-api-key-here
SESSION_SECRET=another-secret-key
REDIS_URL=redis://localhost:6379
FRONTEND_URL=https://yourdomain.com
```

#### 5. Deployment Checklist

- [ ] Set up production server (AWS, Heroku, DigitalOcean)
- [ ] Configure PostgreSQL database
- [ ] Implement Redis for session storage
- [ ] Set up HTTPS with SSL certificate
- [ ] Configure environment variables
- [ ] Implement proper CORS
- [ ] Set up rate limiting on server
- [ ] Add logging and monitoring
- [ ] Configure backup strategy
- [ ] Set up CI/CD pipeline
- [ ] Security audit
- [ ] Penetration testing
- [ ] Load testing
- [ ] Error tracking (Sentry, etc.)

---

## 🔮 Future Enhancements

### Short-term (3-6 months)

#### Backend Implementation
- [ ] Node.js/Express API server
- [ ] PostgreSQL database
- [ ] User authentication API endpoints
- [ ] Adventure CRUD operations
- [ ] Search API with pagination

#### Enhanced Security
- [ ] bcrypt password hashing
- [ ] JWT with proper signing
- [ ] Email verification
- [ ] Two-factor authentication (2FA)
- [ ] OAuth integration (Google, Facebook)

#### User Features
- [ ] User profile management
- [ ] Avatar upload
- [ ] Adventure reviews and ratings
- [ ] Share adventures on social media
- [ ] Trip planning tools

### Medium-term (6-12 months)

#### Content Expansion
- [ ] Expand to all 50 US states
- [ ] Add 10,000+ adventures
- [ ] User-generated content
- [ ] Photo galleries
- [ ] Video previews
- [ ] 360° panoramic views

#### Social Features
- [ ] Follow other users
- [ ] Activity feed
- [ ] Adventure completion badges
- [ ] Leaderboards
- [ ] Comments and discussions
- [ ] Groups and challenges

#### Advanced AI
- [ ] Collaborative filtering
- [ ] Seasonal recommendations
- [ ] Weather-aware suggestions
- [ ] Route optimization
- [ ] Natural language search

### Long-term (12+ months)

#### Mobile Apps
- [ ] iOS native app
- [ ] Android native app
- [ ] Offline functionality
- [ ] GPS tracking
- [ ] Push notifications
- [ ] AR features

#### Monetization
- [ ] Booking integration
- [ ] Premium subscriptions
- [ ] Adventure partnerships
- [ ] Gear affiliate links
- [ ] Sponsored adventures

#### Advanced Features
- [ ] Live trail conditions
- [ ] Real-time weather
- [ ] Emergency SOS features
- [ ] Guided tours booking
- [ ] Equipment rental
- [ ] Travel insurance integration

---

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

### How to Contribute

1. **Fork the Repository**
   ```bash
   git fork https://github.com/yourusername/adventures-near-me.git
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/amazing-feature
   ```

3. **Make Your Changes**
   - Follow existing code style
   - Add comments for complex logic
   - Update documentation

4. **Test Your Changes**
   - Test all affected features
   - Check responsive design
   - Verify security isn't compromised

5. **Commit Your Changes**
   ```bash
   git commit -m "Add amazing feature"
   ```

6. **Push to Branch**
   ```bash
   git push origin feature/amazing-feature
   ```

7. **Open a Pull Request**
   - Describe your changes
   - Reference any issues
   - Add screenshots if UI changes

### Code Style Guidelines

- Use meaningful variable names
- Comment complex logic
- Follow existing patterns
- Keep functions focused and small
- Use async/await for promises
- Handle errors gracefully

### Areas Needing Help

- 🐛 Bug fixes
- 📚 Documentation improvements
- 🎨 UI/UX enhancements
- ♿ Accessibility improvements
- 🌍 Internationalization
- 🧪 Test coverage
- 🚀 Performance optimizations

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

```
Copyright (c) 2024 AdventuresNearMe

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```

---

## 👥 Authors

- **Your Name** - Initial work - [GitHub](https://github.com/yourusername)

---

## 🙏 Acknowledgments

- **Anthropic Claude** - AI recommendations
- **New York State Tourism** - Adventure data inspiration
- **Open Source Community** - Various libraries and tools
- **Contributors** - Everyone who helps improve this project

---

## 📞 Support & Contact

### Getting Help

- 📖 **Documentation**: See [SECURITY.md](SECURITY.md) and [QUICK_START.md](QUICK_START.md)
- 🐛 **Bug Reports**: Open an issue on GitHub
- 💡 **Feature Requests**: Open an issue with [Feature Request] tag
- 💬 **Discussions**: Use GitHub Discussions

### Security Issues

If you discover a security vulnerability, please email security@adventuresnearme.com instead of using the issue tracker.

---

## 📊 Project Stats

![GitHub stars](https://img.shields.io/github/stars/yourusername/adventures-near-me)
![GitHub forks](https://img.shields.io/github/forks/yourusername/adventures-near-me)
![GitHub issues](https://img.shields.io/github/issues/yourusername/adventures-near-me)
![GitHub pull requests](https://img.shields.io/github/issues-pr/yourusername/adventures-near-me)

---

## 🗺️ Roadmap

See our [Project Roadmap](ROADMAP.md) for detailed plans and timelines.

**Current Status:** 🟡 Demo/Prototype Phase

**Next Milestone:** 🎯 Backend Implementation (Q1 2025)

---

## ⭐ Show Your Support

If you like this project, please give it a ⭐ on GitHub!

---

## 📝 Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes.

### Recent Updates

**v1.0.0** (2024-11-23)
- ✅ Initial release
- ✅ 53 NY State adventures
- ✅ AI recommendations
- ✅ Enhanced security
- ✅ Responsive design
- ✅ Complete documentation

---

**Built with ❤️ by outdoor enthusiasts, for outdoor enthusiasts**

🏔️ Get out there and explore! 🏕️
