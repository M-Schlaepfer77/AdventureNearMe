/**
 * Security Utilities Library
 * Provides client-side security functions including password hashing and JWT simulation
 * 
 * IMPORTANT: This is a CLIENT-SIDE ONLY implementation for demonstration purposes.
 * In production, ALL security operations MUST happen on a secure backend server.
 */

class SecurityManager {
    constructor() {
        this.jwtSecret = 'demo-secret-key-change-in-production';
        this.tokenExpiry = 24 * 60 * 60 * 1000; // 24 hours
    }

    /**
     * Hash password using Web Crypto API (SHA-256)
     * NOTE: In production, use bcrypt on the server side
     */
    async hashPassword(password) {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        return hashHex;
    }

    /**
     * Verify password against hash
     */
    async verifyPassword(password, hash) {
        const passwordHash = await this.hashPassword(password);
        return passwordHash === hash;
    }

    /**
     * Generate a JWT-like token (simplified for demo)
     * NOTE: In production, use proper JWT library on backend
     */
    generateToken(payload) {
        const header = {
            alg: 'HS256',
            typ: 'JWT'
        };

        const tokenPayload = {
            ...payload,
            iat: Date.now(),
            exp: Date.now() + this.tokenExpiry
        };

        // Base64 encode (simplified)
        const encodedHeader = btoa(JSON.stringify(header));
        const encodedPayload = btoa(JSON.stringify(tokenPayload));
        
        // Simple signature (in production, use proper HMAC)
        const signature = btoa(encodedHeader + encodedPayload + this.jwtSecret);

        return `${encodedHeader}.${encodedPayload}.${signature}`;
    }

    /**
     * Verify and decode JWT token
     */
    verifyToken(token) {
        try {
            const parts = token.split('.');
            if (parts.length !== 3) {
                return null;
            }

            const [encodedHeader, encodedPayload, signature] = parts;
            
            // Verify signature
            const expectedSignature = btoa(encodedHeader + encodedPayload + this.jwtSecret);
            if (signature !== expectedSignature) {
                return null;
            }

            const payload = JSON.parse(atob(encodedPayload));

            // Check expiration
            if (payload.exp < Date.now()) {
                return null;
            }

            return payload;
        } catch (error) {
            console.error('Token verification failed:', error);
            return null;
        }
    }

    /**
     * Validate email format
     */
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Validate password strength
     * Returns: { valid: boolean, issues: string[], strength: number }
     */
    validatePasswordStrength(password) {
        const issues = [];
        let strength = 0;

        if (password.length < 8) {
            issues.push('Password must be at least 8 characters');
        } else {
            strength += 1;
        }

        if (password.length >= 12) {
            strength += 1;
        }

        if (/[a-z]/.test(password) && /[A-Z]/.test(password)) {
            strength += 1;
        } else {
            issues.push('Password must contain both uppercase and lowercase letters');
        }

        if (/[0-9]/.test(password)) {
            strength += 1;
        } else {
            issues.push('Password must contain at least one number');
        }

        if (/[^a-zA-Z0-9]/.test(password)) {
            strength += 1;
        } else {
            issues.push('Password must contain at least one special character');
        }

        // Check for common weak passwords
        const weakPasswords = ['password', '12345678', 'qwerty', 'abc123', 'password123'];
        if (weakPasswords.includes(password.toLowerCase())) {
            issues.push('This password is too common');
            strength = 0;
        }

        return {
            valid: issues.length === 0,
            issues: issues,
            strength: Math.min(strength, 5) // 0-5 scale
        };
    }

    /**
     * Sanitize user input to prevent XSS
     */
    sanitizeInput(input) {
        const div = document.createElement('div');
        div.textContent = input;
        return div.innerHTML;
    }

    /**
     * Generate secure random string
     */
    generateSecureRandom(length = 32) {
        const array = new Uint8Array(length);
        crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    }

    /**
     * Implement rate limiting (simple client-side version)
     */
    checkRateLimit(action, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
        const key = `rateLimit_${action}`;
        const now = Date.now();
        
        let attempts = JSON.parse(localStorage.getItem(key) || '[]');
        
        // Remove old attempts outside the window
        attempts = attempts.filter(timestamp => now - timestamp < windowMs);
        
        if (attempts.length >= maxAttempts) {
            const oldestAttempt = Math.min(...attempts);
            const waitTime = windowMs - (now - oldestAttempt);
            return {
                allowed: false,
                waitTime: Math.ceil(waitTime / 1000 / 60) // minutes
            };
        }

        attempts.push(now);
        localStorage.setItem(key, JSON.stringify(attempts));
        
        return {
            allowed: true,
            remainingAttempts: maxAttempts - attempts.length
        };
    }

    /**
     * Clear rate limit for an action
     */
    clearRateLimit(action) {
        localStorage.removeItem(`rateLimit_${action}`);
    }

    /**
     * Log security event
     */
    logSecurityEvent(event, details) {
        const logs = JSON.parse(localStorage.getItem('securityLogs') || '[]');
        
        logs.push({
            event: event,
            details: details,
            timestamp: new Date().toISOString(),
            userAgent: navigator.userAgent
        });

        // Keep only last 100 logs
        if (logs.length > 100) {
            logs.shift();
        }

        localStorage.setItem('securityLogs', JSON.stringify(logs));
        
        // In production, send to backend for analysis
        console.log('Security Event:', event, details);
    }

    /**
     * Check if session is valid
     */
    validateSession() {
        const token = localStorage.getItem('authToken');
        if (!token) {
            return false;
        }

        const payload = this.verifyToken(token);
        if (!payload) {
            this.logout();
            return false;
        }

        return true;
    }

    /**
     * Logout and clear all auth data
     */
    logout() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('currentUser');
        localStorage.removeItem('refreshToken');
        this.logSecurityEvent('LOGOUT', { timestamp: Date.now() });
    }

    /**
     * Implement CSRF token (simplified)
     */
    generateCSRFToken() {
        const token = this.generateSecureRandom(32);
        sessionStorage.setItem('csrfToken', token);
        return token;
    }

    /**
     * Verify CSRF token
     */
    verifyCSRFToken(token) {
        const storedToken = sessionStorage.getItem('csrfToken');
        return token === storedToken;
    }

    /**
     * Detect suspicious activity
     */
    detectSuspiciousActivity() {
        const logs = JSON.parse(localStorage.getItem('securityLogs') || '[]');
        
        // Check for multiple failed login attempts
        const recentFailedLogins = logs.filter(log => 
            log.event === 'LOGIN_FAILED' && 
            Date.now() - new Date(log.timestamp).getTime() < 15 * 60 * 1000
        );

        if (recentFailedLogins.length >= 5) {
            return {
                suspicious: true,
                reason: 'Multiple failed login attempts',
                action: 'ACCOUNT_LOCKED'
            };
        }

        return { suspicious: false };
    }

    /**
     * Encrypt sensitive data before storage (simplified)
     * NOTE: In production, never store sensitive data client-side
     */
    async encryptData(data, key) {
        // This is a simplified version - use proper encryption in production
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(JSON.stringify(data));
        const encodedKey = encoder.encode(key);
        
        const hashKey = await crypto.subtle.digest('SHA-256', encodedKey);
        
        const encrypted = new Uint8Array(encodedData.length);
        const keyArray = new Uint8Array(hashKey);
        
        for (let i = 0; i < encodedData.length; i++) {
            encrypted[i] = encodedData[i] ^ keyArray[i % keyArray.length];
        }
        
        return btoa(String.fromCharCode(...encrypted));
    }

    /**
     * Decrypt sensitive data
     */
    async decryptData(encryptedData, key) {
        try {
            const encrypted = Uint8Array.from(atob(encryptedData), c => c.charCodeAt(0));
            const encoder = new TextEncoder();
            const encodedKey = encoder.encode(key);
            
            const hashKey = await crypto.subtle.digest('SHA-256', encodedKey);
            const keyArray = new Uint8Array(hashKey);
            
            const decrypted = new Uint8Array(encrypted.length);
            
            for (let i = 0; i < encrypted.length; i++) {
                decrypted[i] = encrypted[i] ^ keyArray[i % keyArray.length];
            }
            
            const decoder = new TextDecoder();
            return JSON.parse(decoder.decode(decrypted));
        } catch (error) {
            console.error('Decryption failed:', error);
            return null;
        }
    }

    /**
     * Secure session storage with encryption
     */
    async secureSetItem(key, value) {
        const encryptionKey = this.generateSecureRandom(32);
        const encrypted = await this.encryptData(value, encryptionKey);
        sessionStorage.setItem(key, encrypted);
        sessionStorage.setItem(`${key}_key`, encryptionKey);
    }

    /**
     * Retrieve and decrypt from secure session storage
     */
    async secureGetItem(key) {
        const encrypted = sessionStorage.getItem(key);
        const encryptionKey = sessionStorage.getItem(`${key}_key`);
        
        if (!encrypted || !encryptionKey) {
            return null;
        }
        
        return await this.decryptData(encrypted, encryptionKey);
    }
}

// Export singleton instance
const securityManager = new SecurityManager();

// Make available globally
if (typeof window !== 'undefined') {
    window.SecurityManager = securityManager;
}