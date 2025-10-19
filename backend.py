import hashlib
import time
import string
import itertools
import re
import secrets
from typing import Tuple, List, Dict, Optional
import json
from datetime import datetime


# ================== HASH FUNCTIONS ==================

def hash_password(password: str, algorithm: str = 'sha256', salt: str = '') -> str:
    """
    Hash a password using the specified algorithm with optional salt

    Args:
        password: The password to hash
        algorithm: Hash algorithm (md5, sha1, sha256, sha512)
        salt: Optional salt to add before hashing

    Returns:
        Hexadecimal hash string
    """
    algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1,
        'sha256': hashlib.sha256,
        'sha512': hashlib.sha512
    }

    if algorithm not in algorithms:
        algorithm = 'sha256'

    salted_password = salt + password
    hash_obj = algorithms[algorithm](salted_password.encode())
    return hash_obj.hexdigest()


def hash_with_iterations(password: str, iterations: int = 10000,
                         algorithm: str = 'sha256') -> str:
    """
    Hash password multiple times (key stretching simulation)
    Similar to PBKDF2 concept
    """
    result = password
    for _ in range(iterations):
        result = hash_password(result, algorithm)
    return result


def compare_hash_speeds(password: str, iterations: int = 1000) -> Dict[str, float]:
    """
    Compare hashing speeds of different algorithms

    Returns:
        Dictionary with algorithm names and time taken
    """
    algorithms = ['md5', 'sha1', 'sha256', 'sha512']
    results = {}

    for algo in algorithms:
        start = time.time()
        for _ in range(iterations):
            hash_password(password, algo)
        elapsed = time.time() - start
        results[algo] = elapsed

    return results


# ================== PASSWORD STRENGTH ANALYSIS ==================

def calculate_password_strength(password: str) -> Tuple[int, str, str, List[str], Dict]:
    """
    Calculate comprehensive password strength

    Returns:
        (score, strength_label, color, feedback_list, detailed_metrics)
    """
    score = 0
    feedback = []
    metrics = {
        'length': len(password),
        'has_lower': False,
        'has_upper': False,
        'has_digit': False,
        'has_special': False,
        'entropy': 0,
        'unique_chars': 0,
        'repeated_chars': 0,
        'sequential_chars': 0,
        'common_patterns': []
    }

    length = len(password)

    # Length scoring (0-30 points)
    if length >= 8:
        score += 10
    if length >= 12:
        score += 10
    if length >= 16:
        score += 10
    if length < 8:
        feedback.append("❌ Password must be at least 8 characters (16+ recommended)")

    # Character variety checks (0-40 points)
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>/?]', password))

    metrics['has_lower'] = has_lower
    metrics['has_upper'] = has_upper
    metrics['has_digit'] = has_digit
    metrics['has_special'] = has_special

    if has_lower:
        score += 5
    else:
        feedback.append("❌ Add lowercase letters (a-z)")

    if has_upper:
        score += 10
    else:
        feedback.append("❌ Add uppercase letters (A-Z)")

    if has_digit:
        score += 10
    else:
        feedback.append("❌ Add numbers (0-9)")

    if has_special:
        score += 15
    else:
        feedback.append("❌ Add special characters (!@#$%^&*)")

    # Character diversity bonus (0-10 points)
    variety_count = sum([has_lower, has_upper, has_digit, has_special])
    if variety_count >= 3:
        score += 5
    if variety_count == 4:
        score += 5

    # Unique characters analysis (0-10 points)
    unique_chars = len(set(password))
    metrics['unique_chars'] = unique_chars
    if unique_chars >= length * 0.8:
        score += 10
    elif unique_chars < length * 0.5:
        feedback.append("⚠️ Too many repeated characters")
        score -= 5

    # Repeated characters check
    for char in set(password):
        count = password.count(char)
        if count > 2:
            metrics['repeated_chars'] += 1

    if metrics['repeated_chars'] > 0:
        feedback.append(f"⚠️ {metrics['repeated_chars']} character(s) repeated multiple times")

    # Sequential characters check (0 to -10 points)
    sequential_patterns = [
        'abc', 'bcd', 'cde', 'def', 'efg', 'fgh', 'ghi', 'hij',
        '123', '234', '345', '456', '567', '678', '789'
    ]
    for pattern in sequential_patterns:
        if pattern in password.lower():
            metrics['sequential_chars'] += 1
            score -= 5

    if metrics['sequential_chars'] > 0:
        feedback.append("⚠️ Avoid sequential patterns (abc, 123, etc.)")

    # Common patterns and words (0 to -30 points)
    common_patterns = {
        'password': -20, 'pass': -10, '123': -10, 'qwerty': -20,
        'admin': -15, 'login': -10, 'welcome': -10, 'letmein': -15,
        'monkey': -10, 'dragon': -10, 'master': -10, 'shadow': -10,
        'abc': -10, '111': -15, '000': -15
    }

    for pattern, penalty in common_patterns.items():
        if pattern in password.lower():
            score += penalty
            metrics['common_patterns'].append(pattern)

    if metrics['common_patterns']:
        feedback.append(f"⚠️ Avoid common words: {', '.join(metrics['common_patterns'])}")

    # Calculate entropy (bits)
    charset_size = 0
    if has_lower:
        charset_size += 26
    if has_upper:
        charset_size += 26
    if has_digit:
        charset_size += 10
    if has_special:
        charset_size += 32

    if charset_size > 0:
        import math
        metrics['entropy'] = length * math.log2(charset_size)

    # Keyboard pattern detection
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1qaz', '2wsx']
    for pattern in keyboard_patterns:
        if pattern in password.lower():
            score -= 15
            feedback.append("⚠️ Avoid keyboard patterns")
            break

    # Date pattern detection
    if re.search(r'\d{4}', password):  # Year pattern
        feedback.append("⚠️ Avoid using years or dates")
        score -= 10

    # Ensure score is between 0-100
    score = max(0, min(100, score))

    # Determine strength level
    if score >= 90:
        strength = "🔒 Excellent"
        color = "green"
    elif score >= 75:
        strength = "💪 Strong"
        color = "green"
    elif score >= 60:
        strength = "🟡 Moderate"
        color = "orange"
    elif score >= 40:
        strength = "⚠️ Weak"
        color = "orange"
    else:
        strength = "🔴 Very Weak"
        color = "red"

    return score, strength, color, feedback, metrics


# ================== ATTACK SIMULATIONS ==================

def dictionary_attack(target_hash: str, algorithm: str = 'sha256',
                      salt: str = '', max_attempts: int = 10000,
                      custom_wordlist: Optional[List[str]] = None) -> Tuple:
    """
    Simulate a dictionary attack with extensive wordlist

    Returns:
        (success, cracked_password, attempts, elapsed_time, attempts_per_second)
    """
    # Extended common passwords list
    common_passwords = [
        # Top 50 most common
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321',
        'superman', 'qazwsx', 'michael', 'football', 'password1',
        'welcome', 'admin', 'login', 'hello', 'starwars',
        'princess', 'solo', 'whatever', 'freedom', 'ninja',
        'mustang', 'jordan', 'hunter', 'ranger', 'cookie',
        'buster', 'tigger', 'summer', 'Charlie', 'batman',
        'pepper', 'michelle', 'jessica', 'orange', 'blue',
        # Variations
        'Password1', 'Password123', 'Admin123', 'Welcome1',
        '123456789', '12345', '1234', 'password!', 'qwerty123',
        # Common with numbers
        'jordan23', 'soccer10', 'love123', 'money1', 'liverpool1'
    ]

    wordlist = custom_wordlist if custom_wordlist else common_passwords

    attempts = 0
    start_time = time.time()

    for password in wordlist:
        attempts += 1
        hashed = hash_password(password, algorithm, salt)

        if hashed == target_hash:
            elapsed_time = time.time() - start_time
            aps = attempts / elapsed_time if elapsed_time > 0 else attempts
            return True, password, attempts, elapsed_time, aps

        if attempts >= max_attempts:
            break

    elapsed_time = time.time() - start_time
    aps = attempts / elapsed_time if elapsed_time > 0 else attempts
    return False, None, attempts, elapsed_time, aps


def brute_force_attack(target_hash: str, algorithm: str = 'sha256',
                       salt: str = '', max_length: int = 4,
                       max_attempts: int = 10000,
                       charset: str = 'lowercase+digits') -> Tuple:
    """
    Simulate a brute force attack with configurable charset

    Args:
        charset: 'lowercase', 'uppercase', 'digits', 'lowercase+digits', 'all'

    Returns:
        (success, cracked_password, attempts, elapsed_time, attempts_per_second)
    """
    # Define character sets
    charsets = {
        'lowercase': string.ascii_lowercase,
        'uppercase': string.ascii_uppercase,
        'digits': string.digits,
        'lowercase+digits': string.ascii_lowercase + string.digits,
        'lowercase+uppercase': string.ascii_lowercase + string.ascii_uppercase,
        'all': string.ascii_letters + string.digits + string.punctuation
    }

    chars = charsets.get(charset, string.ascii_lowercase + string.digits)

    attempts = 0
    start_time = time.time()

    for length in range(1, max_length + 1):
        for combination in itertools.product(chars, repeat=length):
            password = ''.join(combination)
            attempts += 1
            hashed = hash_password(password, algorithm, salt)

            if hashed == target_hash:
                elapsed_time = time.time() - start_time
                aps = attempts / elapsed_time if elapsed_time > 0 else attempts
                return True, password, attempts, elapsed_time, aps

            if attempts >= max_attempts:
                elapsed_time = time.time() - start_time
                aps = attempts / elapsed_time if elapsed_time > 0 else attempts
                return False, None, attempts, elapsed_time, aps

    elapsed_time = time.time() - start_time
    aps = attempts / elapsed_time if elapsed_time > 0 else attempts
    return False, None, attempts, elapsed_time, aps


def hybrid_attack(target_hash: str, algorithm: str = 'sha256',
                  salt: str = '', max_attempts: int = 10000) -> Tuple:
    """
    Hybrid attack: Dictionary words + common number/symbol suffixes

    Returns:
        (success, cracked_password, attempts, elapsed_time, attempts_per_second)
    """
    base_words = ['password', 'admin', 'welcome', 'hello', 'login']
    suffixes = ['1', '123', '!', '12', '2024', '2025', '@', '1!']

    attempts = 0
    start_time = time.time()

    # Try base words
    for word in base_words:
        attempts += 1
        hashed = hash_password(word, algorithm, salt)
        if hashed == target_hash:
            elapsed_time = time.time() - start_time
            aps = attempts / elapsed_time if elapsed_time > 0 else attempts
            return True, word, attempts, elapsed_time, aps

    # Try combinations
    for word in base_words:
        for suffix in suffixes:
            if attempts >= max_attempts:
                break

            password = word + suffix
            attempts += 1
            hashed = hash_password(password, algorithm, salt)

            if hashed == target_hash:
                elapsed_time = time.time() - start_time
                aps = attempts / elapsed_time if elapsed_time > 0 else attempts
                return True, password, attempts, elapsed_time, aps

    elapsed_time = time.time() - start_time
    aps = attempts / elapsed_time if elapsed_time > 0 else attempts
    return False, None, attempts, elapsed_time, aps


# ================== TIME ESTIMATION ==================

def estimate_crack_time(password: str, attacks_per_second: int = 1_000_000_000) -> Dict:
    """
    Estimate time to crack password using different methods

    Returns:
        Dictionary with estimates for different attack scenarios
    """
    charset_size = 0

    if re.search(r'[a-z]', password):
        charset_size += 26
    if re.search(r'[A-Z]', password):
        charset_size += 26
    if re.search(r'\d', password):
        charset_size += 10
    if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'"\\|,.<>/?]', password):
        charset_size += 32

    length = len(password)

    # Calculate different scenarios
    total_combinations = charset_size ** length

    # Average case (50% of combinations)
    avg_seconds = total_combinations / (2 * attacks_per_second)

    # Worst case (all combinations)
    worst_seconds = total_combinations / attacks_per_second

    # Best case (found in first 1%)
    best_seconds = total_combinations / (100 * attacks_per_second)

    return {
        'charset_size': charset_size,
        'password_length': length,
        'total_combinations': total_combinations,
        'best_case': format_time(best_seconds),
        'average_case': format_time(avg_seconds),
        'worst_case': format_time(worst_seconds),
        'best_case_seconds': best_seconds,
        'average_case_seconds': avg_seconds,
        'worst_case_seconds': worst_seconds
    }


def format_time(seconds: float) -> str:
    """Convert seconds to human-readable format"""
    if seconds < 0.001:
        return "Instant"
    elif seconds < 1:
        return f"{seconds * 1000:.2f} milliseconds"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    elif seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    elif seconds < 31536000:
        return f"{seconds / 86400:.2f} days"
    elif seconds < 3153600000:  # 100 years
        return f"{seconds / 31536000:.2f} years"
    else:
        return f"{seconds / 31536000:.0e} years"


# ================== PASSWORD GENERATION ==================

def generate_secure_password(length: int = 16,
                             include_upper: bool = True,
                             include_lower: bool = True,
                             include_digits: bool = True,
                             include_special: bool = True,
                             exclude_ambiguous: bool = True) -> str:
    """
    Generate a cryptographically secure random password

    Args:
        length: Length of password
        include_*: Include character types
        exclude_ambiguous: Exclude similar-looking characters (0, O, l, 1, etc.)

    Returns:
        Generated password string
    """
    charset = ''

    if include_lower:
        charset += string.ascii_lowercase
    if include_upper:
        charset += string.ascii_uppercase
    if include_digits:
        charset += string.digits
    if include_special:
        charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'

    if exclude_ambiguous:
        ambiguous = 'il1Lo0O'
        charset = ''.join(c for c in charset if c not in ambiguous)

    if not charset:
        raise ValueError("At least one character type must be included")

    # Ensure at least one character from each selected type
    password = []

    if include_lower and not exclude_ambiguous:
        password.append(secrets.choice(string.ascii_lowercase))
    elif include_lower:
        lower = ''.join(c for c in string.ascii_lowercase if c not in 'il')
        password.append(secrets.choice(lower))

    if include_upper and not exclude_ambiguous:
        password.append(secrets.choice(string.ascii_uppercase))
    elif include_upper:
        upper = ''.join(c for c in string.ascii_uppercase if c not in 'LO')
        password.append(secrets.choice(upper))

    if include_digits and not exclude_ambiguous:
        password.append(secrets.choice(string.digits))
    elif include_digits:
        digits = ''.join(c for c in string.digits if c not in '01')
        password.append(secrets.choice(digits))

    if include_special:
        password.append(secrets.choice('!@#$%^&*()'))

    # Fill remaining length
    remaining_length = length - len(password)
    for _ in range(remaining_length):
        password.append(secrets.choice(charset))

    # Shuffle to avoid predictable patterns
    secrets.SystemRandom().shuffle(password)

    return ''.join(password)


def generate_passphrase(word_count: int = 4, separator: str = '-',
                        capitalize: bool = True, add_number: bool = True) -> str:
    """
    Generate a memorable passphrase using random words

    Returns:
        Generated passphrase
    """
    # Sample word list (in production, use a larger list)
    words = [
        'correct', 'horse', 'battery', 'staple', 'mountain', 'river',
        'sunset', 'ocean', 'forest', 'thunder', 'crystal', 'shadow',
        'phoenix', 'dragon', 'wizard', 'castle', 'journey', 'treasure',
        'mystery', 'legend', 'galaxy', 'comet', 'planet', 'nebula',
        'whisper', 'meadow', 'breeze', 'cascade', 'horizon', 'twilight'
    ]

    selected_words = [secrets.choice(words) for _ in range(word_count)]

    if capitalize:
        selected_words = [word.capitalize() for word in selected_words]

    passphrase = separator.join(selected_words)

    if add_number:
        passphrase += separator + str(secrets.randbelow(1000))

    return passphrase


# ================== BREACH CHECK SIMULATION ==================

def check_common_breaches(password: str) -> Dict:
    """
    Simulate checking against common breach databases
    (In production, use Have I Been Pwned API)

    Returns:
        Dictionary with breach information
    """
    # Simulated breached passwords
    known_breached = {
        'password': 'Found in 3,000,000+ breaches',
        '123456': 'Found in 23,000,000+ breaches',
        'password123': 'Found in 1,500,000+ breaches',
        'qwerty': 'Found in 3,800,000+ breaches',
        'admin': 'Found in 2,000,000+ breaches'
    }

    result = {
        'is_breached': password.lower() in known_breached,
        'breach_count': known_breached.get(password.lower(), 'Not found in database'),
        'recommendation': ''
    }

    if result['is_breached']:
        result['recommendation'] = '⚠️ CRITICAL: This password has been found in data breaches. Change it immediately!'
    else:
        result['recommendation'] = '✅ Not found in common breach databases'

    return result


# ================== EXPORT FUNCTIONALITY ==================

def export_analysis_report(password: str, analysis_results: Dict) -> str:
    """
    Generate a comprehensive JSON report of password analysis

    Returns:
        JSON string of the report
    """
    report = {
        'timestamp': datetime.now().isoformat(),
        'password_length': len(password),
        'analysis': analysis_results,
        'recommendations': [
            'Use a unique password for each account',
            'Enable two-factor authentication',
            'Use a password manager',
            'Change passwords regularly',
            'Never share passwords'
        ]
    }

    return json.dumps(report, indent=2)


if __name__ == "__main__":
    # Test the backend
    test_password = "MyP@ssw0rd123"
    print(f"Testing password: {test_password}")
    print("\n--- Strength Analysis ---")
    score, strength, color, feedback, metrics = calculate_password_strength(test_password)
    print(f"Score: {score}/100")
    print(f"Strength: {strength}")
    print(f"Entropy: {metrics['entropy']:.2f} bits")

    print("\n--- Hash Examples ---")
    print(f"SHA-256: {hash_password(test_password, 'sha256')}")

    print("\n--- Crack Time Estimate ---")
    estimates = estimate_crack_time(test_password)
    print(f"Average case: {estimates['average_case']}")

    print("\n--- Generate Secure Password ---")
    secure_pw = generate_secure_password(16)
    print(f"Generated: {secure_pw}")

    print("\n--- Generate Passphrase ---")
    passphrase = generate_passphrase(4)
    print(f"Passphrase: {passphrase}")