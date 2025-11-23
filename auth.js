/**
 * Authentication Manager
 * Handles user authentication, session management, and access control
 */

class AuthManager {
    constructor() {
        this.security = window.SecurityManager;
        this.sessionTimeout = 30 * 60 * 1000; // 30 minutes
        this.maxLoginAttempts = 5;
        this.lockoutDuration = 15 * 60 * 1000; // 15 minutes
        
        // Initialize session monitoring
        this.initSessionMonitoring();
    }

    /**
     * Register new user with enhanced security
     */
    async register(userData) {
        try {
            // Validate input
            const validation = this.validateRegistrationData(userData);
            if (!validation.valid) {
                return {
                    success: false,
                    errors: validation.errors
                };
            }

            // Check if email already exists
            const existingUser = await this.getUserByEmail(userData.email);
            if (existingUser) {
                this.security.logSecurityEvent('REGISTRATION_FAILED', {
                    reason: 'Email already exists',
                    email: userData.email
                });
                return {
                    success: false,
                    errors: ['Email address is already registered']
                };
            }

            // Hash password
            const passwordHash = await this.security.hashPassword(userData.password);

            // Generate unique user ID
            const userId = this.security.generateSecureRandom(16);

            // Create user object
            const user = {
                id: userId,
                email: userData.email.toLowerCase().trim(),
                fullName: this.security.sanitizeInput(userData.fullName),
                passwordHash: passwordHash,
                createdAt: new Date().toISOString(),
                lastLogin: null,
                isLocked: false,
                failedLoginAttempts: 0,
                twoFactorEnabled: false,
                emailVerified: false,
                profile: {
                    preferences: {},
                    savedAdventures: []
                }
            };

            // Save user
            await this.saveUser(user);

            // Log event
            this.security.logSecurityEvent('USER_REGISTERED', {
                userId: user.id,
                email: user.email
            });

            // Auto-login after registration
            const loginResult = await this.login(userData.email, userData.password);

            return {
                success: true,
                user: this.sanitizeUserData(user),
                token: loginResult.token
            };

        } catch (error) {
            console.error('Registration error:', error);
            return {
                success: false,
                errors: ['Registration failed. Please try again.']
            };
        }
    }

    /**
     * Login user with security checks
     */
    async login(email, password, rememberMe = false) {
        try {
            email = email.toLowerCase().trim();

            // Check rate limiting
            const rateLimit = this.security.checkRateLimit('login', this.maxLoginAttempts);
            if (!rateLimit.allowed) {
                this.security.logSecurityEvent('LOGIN_RATE_LIMITED', { email });
                return {
                    success: false,
                    errors: [`Too many login attempts. Please try again in ${rateLimit.waitTime} minutes.`]
                };
            }

            // Get user
            const user = await this.getUserByEmail(email);
            if (!user) {
                this.security.logSecurityEvent('LOGIN_FAILED', {
                    reason: 'User not found',
                    email: email
                });
                return {
                    success: false,
                    errors: ['Invalid email or password']
                };
            }

            // Check if account is locked
            if (user.isLocked) {
                const lockExpiry = new Date(user.lockedUntil);
                if (lockExpiry > new Date()) {
                    this.security.logSecurityEvent('LOGIN_BLOCKED', {
                        reason: 'Account locked',
                        userId: user.id
                    });
                    return {
                        success: false,
                        errors: ['Account is temporarily locked. Please try again later or reset your password.']
                    };
                } else {
                    // Unlock account
                    user.isLocked = false;
                    user.failedLoginAttempts = 0;
                    await this.updateUser(user);
                }
            }

            // Verify password
            const passwordValid = await this.security.verifyPassword(password, user.passwordHash);
            if (!passwordValid) {
                // Increment failed attempts
                user.failedLoginAttempts = (user.failedLoginAttempts || 0) + 1;

                // Lock account after max attempts
                if (user.failedLoginAttempts >= this.maxLoginAttempts) {
                    user.isLocked = true;
                    user.lockedUntil = new Date(Date.now() + this.lockoutDuration).toISOString();
                    this.security.logSecurityEvent('ACCOUNT_LOCKED', {
                        userId: user.id,
                        reason: 'Too many failed login attempts'
                    });
                }

                await this.updateUser(user);

                this.security.logSecurityEvent('LOGIN_FAILED', {
                    reason: 'Invalid password',
                    userId: user.id,
                    failedAttempts: user.failedLoginAttempts
                });

                return {
                    success: false,
                    errors: ['Invalid email or password'],
                    remainingAttempts: this.maxLoginAttempts - user.failedLoginAttempts
                };
            }

            // Successful login - reset failed attempts
            user.failedLoginAttempts = 0;
            user.lastLogin = new Date().toISOString();
            await this.updateUser(user);

            // Clear rate limit
            this.security.clearRateLimit('login');

            // Generate tokens
            const accessToken = this.security.generateToken({
                userId: user.id,
                email: user.email,
                type: 'access'
            });

            const refreshToken = this.security.generateToken({
                userId: user.id,
                email: user.email,
                type: 'refresh',
                exp: Date.now() + (7 * 24 * 60 * 60 * 1000) // 7 days
            });

            // Store tokens
            localStorage.setItem('authToken', accessToken);
            if (rememberMe) {
                localStorage.setItem('refreshToken', refreshToken);
            }

            // Store current user session
            const sessionData = {
                userId: user.id,
                email: user.email,
                fullName: user.fullName,
                loggedInAt: new Date().toISOString(),
                rememberMe: rememberMe
            };
            localStorage.setItem('currentUser', JSON.stringify(sessionData));

            // Log successful login
            this.security.logSecurityEvent('LOGIN_SUCCESS', {
                userId: user.id,
                email: user.email
            });

            return {
                success: true,
                user: this.sanitizeUserData(user),
                token: accessToken,
                refreshToken: refreshToken
            };

        } catch (error) {
            console.error('Login error:', error);
            return {
                success: false,
                errors: ['Login failed. Please try again.']
            };
        }
    }

    /**
     * Logout user
     */
    logout() {
        const currentUser = this.getCurrentUser();
        
        if (currentUser) {
            this.security.logSecurityEvent('LOGOUT', {
                userId: currentUser.userId,
                email: currentUser.email
            });
        }

        // Clear all auth data
        localStorage.removeItem('authToken');
        localStorage.removeItem('refreshToken');
        localStorage.removeItem('currentUser');
        sessionStorage.clear();

        return { success: true };
    }

    /**
     * Check if user is authenticated
     */
    isAuthenticated() {
        const token = localStorage.getItem('authToken');
        if (!token) {
            return false;
        }

        const payload = this.security.verifyToken(token);
        return payload !== null;
    }

    /**
     * Get current user
     */
    getCurrentUser() {
        const userJson = localStorage.getItem('currentUser');
        if (!userJson) {
            return null;
        }

        try {
            return JSON.parse(userJson);
        } catch (error) {
            return null;
        }
    }

    /**
     * Refresh access token
     */
    async refreshAccessToken() {
        const refreshToken = localStorage.getItem('refreshToken');
        if (!refreshToken) {
            return { success: false };
        }

        const payload = this.security.verifyToken(refreshToken);
        if (!payload) {
            this.logout();
            return { success: false };
        }

        // Generate new access token
        const newAccessToken = this.security.generateToken({
            userId: payload.userId,
            email: payload.email,
            type: 'access'
        });

        localStorage.setItem('authToken', newAccessToken);

        return {
            success: true,
            token: newAccessToken
        };
    }

    /**
     * Change password
     */
    async changePassword(oldPassword, newPassword) {
        try {
            const currentUser = this.getCurrentUser();
            if (!currentUser) {
                return {
                    success: false,
                    errors: ['You must be logged in to change password']
                };
            }

            const user = await this.getUserById(currentUser.userId);
            if (!user) {
                return {
                    success: false,
                    errors: ['User not found']
                };
            }

            // Verify old password
            const oldPasswordValid = await this.security.verifyPassword(oldPassword, user.passwordHash);
            if (!oldPasswordValid) {
                this.security.logSecurityEvent('PASSWORD_CHANGE_FAILED', {
                    userId: user.id,
                    reason: 'Invalid old password'
                });
                return {
                    success: false,
                    errors: ['Current password is incorrect']
                };
            }

            // Validate new password
            const validation = this.security.validatePasswordStrength(newPassword);
            if (!validation.valid) {
                return {
                    success: false,
                    errors: validation.issues
                };
            }

            // Hash new password
            user.passwordHash = await this.security.hashPassword(newPassword);
            user.passwordChangedAt = new Date().toISOString();

            await this.updateUser(user);

            this.security.logSecurityEvent('PASSWORD_CHANGED', {
                userId: user.id
            });

            return { success: true };

        } catch (error) {
            console.error('Change password error:', error);
            return {
                success: false,
                errors: ['Failed to change password']
            };
        }
    }

    /**
     * Request password reset
     */
    async requestPasswordReset(email) {
        email = email.toLowerCase().trim();

        const user = await this.getUserByEmail(email);
        if (!user) {
            // Don't reveal if email exists
            this.security.logSecurityEvent('PASSWORD_RESET_REQUEST', {
                email: email,
                found: false
            });
            return {
                success: true,
                message: 'If this email is registered, you will receive password reset instructions.'
            };
        }

        // Generate reset token
        const resetToken = this.security.generateSecureRandom(32);
        const resetExpiry = Date.now() + (60 * 60 * 1000); // 1 hour

        user.passwordResetToken = resetToken;
        user.passwordResetExpiry = resetExpiry;

        await this.updateUser(user);

        this.security.logSecurityEvent('PASSWORD_RESET_REQUEST', {
            userId: user.id,
            email: email
        });

        // In production, send email with reset link
        console.log('Password reset token:', resetToken);
        console.log('Reset link: /reset-password?token=' + resetToken);

        return {
            success: true,
            message: 'If this email is registered, you will receive password reset instructions.',
            resetToken: resetToken // Only for demo - remove in production
        };
    }

    /**
     * Reset password with token
     */
    async resetPassword(token, newPassword) {
        try {
            // Find user with valid reset token
            const users = await this.getAllUsers();
            const user = users.find(u => 
                u.passwordResetToken === token && 
                u.passwordResetExpiry > Date.now()
            );

            if (!user) {
                this.security.logSecurityEvent('PASSWORD_RESET_FAILED', {
                    reason: 'Invalid or expired token'
                });
                return {
                    success: false,
                    errors: ['Invalid or expired reset token']
                };
            }

            // Validate new password
            const validation = this.security.validatePasswordStrength(newPassword);
            if (!validation.valid) {
                return {
                    success: false,
                    errors: validation.issues
                };
            }

            // Update password
            user.passwordHash = await this.security.hashPassword(newPassword);
            user.passwordResetToken = null;
            user.passwordResetExpiry = null;
            user.passwordChangedAt = new Date().toISOString();

            // Unlock account if locked
            user.isLocked = false;
            user.failedLoginAttempts = 0;

            await this.updateUser(user);

            this.security.logSecurityEvent('PASSWORD_RESET_SUCCESS', {
                userId: user.id
            });

            return { success: true };

        } catch (error) {
            console.error('Password reset error:', error);
            return {
                success: false,
                errors: ['Failed to reset password']
            };
        }
    }

    /**
     * Validate registration data
     */
    validateRegistrationData(data) {
        const errors = [];

        // Validate full name
        if (!data.fullName || data.fullName.trim().length < 2) {
            errors.push('Full name must be at least 2 characters');
        }

        // Validate email
        if (!this.security.validateEmail(data.email)) {
            errors.push('Please enter a valid email address');
        }

        // Validate password
        const passwordValidation = this.security.validatePasswordStrength(data.password);
        if (!passwordValidation.valid) {
            errors.push(...passwordValidation.issues);
        }

        // Validate password confirmation
        if (data.password !== data.confirmPassword) {
            errors.push('Passwords do not match');
        }

        return {
            valid: errors.length === 0,
            errors: errors
        };
    }

    /**
     * Sanitize user data for client
     */
    sanitizeUserData(user) {
        return {
            id: user.id,
            email: user.email,
            fullName: user.fullName,
            createdAt: user.createdAt,
            lastLogin: user.lastLogin,
            emailVerified: user.emailVerified,
            profile: user.profile
        };
    }

    /**
     * Initialize session monitoring
     */
    initSessionMonitoring() {
        // Check session validity every minute
        setInterval(() => {
            if (this.isAuthenticated()) {
                const currentUser = this.getCurrentUser();
                const loginTime = new Date(currentUser.loggedInAt).getTime();
                const now = Date.now();

                // Auto-logout after session timeout
                if (now - loginTime > this.sessionTimeout) {
                    this.security.logSecurityEvent('SESSION_TIMEOUT', {
                        userId: currentUser.userId
                    });
                    this.logout();
                    window.location.href = '/login.html?reason=timeout';
                }
            }
        }, 60000); // Check every minute

        // Update last activity on user interaction
        ['click', 'keypress', 'scroll', 'mousemove'].forEach(event => {
            document.addEventListener(event, () => {
                if (this.isAuthenticated()) {
                    const currentUser = this.getCurrentUser();
                    if (currentUser) {
                        currentUser.lastActivity = new Date().toISOString();
                        localStorage.setItem('currentUser', JSON.stringify(currentUser));
                    }
                }
            }, { passive: true });
        });
    }

    // ============ Storage Methods ============

    /**
     * Get all users
     */
    async getAllUsers() {
        const usersJson = localStorage.getItem('users');
        if (!usersJson) {
            return [];
        }
        return JSON.parse(usersJson);
    }

    /**
     * Get user by email
     */
    async getUserByEmail(email) {
        const users = await this.getAllUsers();
        return users.find(u => u.email === email.toLowerCase());
    }

    /**
     * Get user by ID
     */
    async getUserById(id) {
        const users = await this.getAllUsers();
        return users.find(u => u.id === id);
    }

    /**
     * Save new user
     */
    async saveUser(user) {
        const users = await this.getAllUsers();
        users.push(user);
        localStorage.setItem('users', JSON.stringify(users));
    }

    /**
     * Update existing user
     */
    async updateUser(updatedUser) {
        const users = await this.getAllUsers();
        const index = users.findIndex(u => u.id === updatedUser.id);
        if (index !== -1) {
            users[index] = updatedUser;
            localStorage.setItem('users', JSON.stringify(users));
        }
    }
}

// Export singleton instance
const authManager = new AuthManager();

// Make available globally
if (typeof window !== 'undefined') {
    window.AuthManager = authManager;
}