# -*- coding: utf-8 -*-

"""
WebShield Scanner - Password Policy
Defines and enforces password security policies.
"""

import re
import hashlib
import secrets
from datetime import datetime
from flask import current_app


class PasswordPolicy:
    """
    Password policy enforcement for security.
    """
    
    # Default policy settings
    MIN_LENGTH = 8
    MAX_LENGTH = 128
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL = True
    
    # Common password blacklist
    COMMON_PASSWORDS = {
        'password', '123456', '12345678', '123456789', 'qwerty',
        'abc123', 'password1', 'admin', 'admin123', 'letmein',
        'welcome', 'monkey', 'dragon', 'master', 'hello',
        'freedom', 'whatever', 'qwertyuiop', '123123', 'iloveyou'
    }
    
    @classmethod
    def validate_password(cls, password):
        """
        Validate a password against the policy.
        
        Args:
            password: Password to validate
            
        Returns:
            tuple: (is_valid, error_message)
        """
        if not password:
            return False, "Password is required"
        
        # Check length
        if len(password) < cls.MIN_LENGTH:
            return False, f"Password must be at least {cls.MIN_LENGTH} characters long"
        
        if len(password) > cls.MAX_LENGTH:
            return False, f"Password must be no more than {cls.MAX_LENGTH} characters long"
        
        # Check for uppercase
        if cls.REQUIRE_UPPERCASE and not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
        
        # Check for lowercase
        if cls.REQUIRE_LOWERCASE and not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
        
        # Check for digits
        if cls.REQUIRE_DIGITS and not re.search(r'\d', password):
            return False, "Password must contain at least one number"
        
        # Check for special characters
        if cls.REQUIRE_SPECIAL and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        
        # Check for common passwords
        if password.lower() in cls.COMMON_PASSWORDS:
            return False, "Password is too common. Please choose a more secure password"
        
        # Check for repeated characters
        if re.search(r'(.)\1{3,}', password):
            return False, "Password contains too many repeated characters"
        
        # Check for sequential characters
        if cls._has_sequential_chars(password):
            return False, "Password contains sequential characters"
        
        return True, None
    
    @classmethod
    def _has_sequential_chars(cls, password):
        """
        Check if password contains sequential characters.
        
        Args:
            password: Password to check
            
        Returns:
            bool: True if sequential characters found
        """
        password_lower = password.lower()
        
        # Check for sequential keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', 'qwertyuiop',
            'asdfghjkl', 'zxcvbnm', '1234567890', 'abcdefghijklmnopqrstuvwxyz'
        ]
        
        for pattern in keyboard_patterns:
            # Check forward and backward
            for i in range(len(pattern) - 3):
                segment = pattern[i:i+4]
                if segment in password_lower:
                    return True
                if segment[::-1] in password_lower:
                    return True
        
        return False
    
    @classmethod
    def generate_strong_password(cls, length=16):
        """
        Generate a strong random password.
        
        Args:
            length: Password length
            
        Returns:
            str: Generated password
        """
        # Define character sets
        uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        lowercase = 'abcdefghijklmnopqrstuvwxyz'
        digits = '0123456789'
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        # Ensure at least one of each type
        password = [
            secrets.choice(uppercase),
            secrets.choice(lowercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest with random characters from all sets
        all_chars = uppercase + lowercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Shuffle the password
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    @classmethod
    def hash_password(cls, password):
        """
        Hash a password (delegates to Flask-Bcrypt).
        
        Args:
            password: Password to hash
            
        Returns:
            str: Hashed password
        """
        from extensions import bcrypt
        return bcrypt.generate_password_hash(password).decode('utf-8')
    
    @classmethod
    def check_password(cls, hashed_password, password):
        """
        Check a password against a hash.
        
        Args:
            hashed_password: Hashed password
            password: Password to check
            
        Returns:
            bool: True if password matches
        """
        from extensions import bcrypt
        return bcrypt.check_password_hash(hashed_password, password)
    
    @classmethod
    def get_password_strength(cls, password):
        """
        Calculate password strength score.
        
        Args:
            password: Password to evaluate
            
        Returns:
            dict: Password strength data
        """
        score = 0
        feedback = []
        
        # Check length
        if len(password) >= 8:
            score += 1
            if len(password) >= 12:
                score += 1
        else:
            feedback.append("Password is too short")
        
        # Check character variety
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        
        variety_count = sum([has_upper, has_lower, has_digit, has_special])
        score += variety_count
        
        if variety_count < 3:
            feedback.append("Use more character types (uppercase, lowercase, numbers, special characters)")
        
        # Check for common passwords
        if password.lower() in cls.COMMON_PASSWORDS:
            score = 0
            feedback.append("Password is too common")
        
        # Determine strength level
        if score >= 7:
            strength = 'strong'
            level = 4
        elif score >= 5:
            strength = 'good'
            level = 3
        elif score >= 3:
            strength = 'fair'
            level = 2
        else:
            strength = 'weak'
            level = 1
        
        return {
            'score': score,
            'max_score': 8,
            'level': level,
            'strength': strength,
            'feedback': feedback,
            'has_upper': has_upper,
            'has_lower': has_lower,
            'has_digit': has_digit,
            'has_special': has_special,
            'length': len(password)
        }
    
    @classmethod
    def get_policy_info(cls):
        """
        Get password policy information for display.
        
        Returns:
            dict: Policy information
        """
        requirements = []
        
        requirements.append(f"Minimum {cls.MIN_LENGTH} characters")
        requirements.append(f"Maximum {cls.MAX_LENGTH} characters")
        
        if cls.REQUIRE_UPPERCASE:
            requirements.append("At least one uppercase letter")
        if cls.REQUIRE_LOWERCASE:
            requirements.append("At least one lowercase letter")
        if cls.REQUIRE_DIGITS:
            requirements.append("At least one number")
        if cls.REQUIRE_SPECIAL:
            requirements.append("At least one special character")
        
        return {
            'min_length': cls.MIN_LENGTH,
            'max_length': cls.MAX_LENGTH,
            'require_uppercase': cls.REQUIRE_UPPERCASE,
            'require_lowercase': cls.REQUIRE_LOWERCASE,
            'require_digits': cls.REQUIRE_DIGITS,
            'require_special': cls.REQUIRE_SPECIAL,
            'requirements': requirements
        }