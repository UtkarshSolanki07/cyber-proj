# 🔐 Advanced Password Security Suite

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.0+-red.svg)](https://streamlit.io/)


> An interactive, educational tool for analyzing password security, simulating attacks, and learning best practices in cybersecurity.

Website Demo- https://utkarshsolanki07-cyber-proj-password-check-1fnuwa.streamlit.app/

## 🌟 Features

### 🔍 **Advanced Password Strength Analysis**
- Comprehensive strength scoring (0-100)
- Character diversity analysis
- Entropy calculation
- Pattern detection (sequential, keyboard, common words)
- Real-time feedback and recommendations

### 💥 **Attack Simulation Suite**
- **Dictionary Attack**: Tests against 60+ common passwords
- **Brute Force Attack**: Configurable character sets and lengths
- **Hybrid Attack**: Combines dictionary words with variations
- **Speed Comparison**: Benchmark all methods simultaneously

### 🎲 **Secure Password Generation**
- Cryptographically secure random passwords
- Customizable character requirements
- Passphrase generator with memorable words
- Batch generation capabilities

### ⚡ **Hash Algorithm Comparison**
- Performance analysis of MD5, SHA-1, SHA-256, SHA-512
- Key stretching demonstrations
- Speed benchmarks with configurable iterations

### 📚 **Educational Content**
- Interactive learning modules
- Real-world breach case studies
- Defense strategies and best practices
- Comprehensive security guidelines

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/UtkarshSolanki07/cyber-proj.git
   cd cyber-proj
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application**
   ```bash
   streamlit run password_check.py
   ```

4. **Open your browser**
   Navigate to `http://localhost:8501` to access the suite.

## 📖 Usage

### Password Strength Checker
Enter any password to receive:
- Strength score and classification
- Detailed metrics (entropy, character types, patterns)
- Crack time estimates
- Breach database check
- Personalized improvement suggestions

### Attack Simulator
Test passwords against various attack methods:
- Configure attack parameters
- View real-time progress
- Analyze results and vulnerabilities
- Compare attack effectiveness

### Password Generator
Generate secure passwords with custom requirements:
- Adjust length and character types
- Create memorable passphrases
- Batch generate multiple passwords
- Export generated passwords

## 🎯 Key Capabilities

| Feature | Description |
|---------|-------------|
| **Strength Analysis** | Multi-factor scoring with entropy calculation |
| **Attack Simulation** | Educational demonstrations of common attack vectors |
| **Hash Comparison** | Performance benchmarking of cryptographic algorithms |
| **Password Generation** | Secure, customizable password creation |
| **Educational Content** | Comprehensive cybersecurity learning resources |
| **Export Functionality** | JSON reports and password lists |

## 🛡️ Security Features

- **Client-side Processing**: All analysis happens locally
- **No Data Storage**: Passwords are never transmitted or stored
- **Educational Focus**: Designed for learning, not malicious use
- **Best Practices**: Implements industry-standard security recommendations

## 📊 Sample Screenshots


### Strength Analysis
![Strength Checker]<img width="1919" height="972" alt="image" src="https://github.com/user-attachments/assets/5d631d90-61d9-46a9-bbcd-bad346057b96" />

### Attack Simulation
![Attack Simulator]<img width="1875" height="1004" alt="image" src="https://github.com/user-attachments/assets/cc300201-ee66-4065-bd45-2c0b37cbd42c" />


## 🔧 Configuration Options

### Hash Settings
- Algorithm selection (MD5, SHA-1, SHA-256, SHA-512)
- Optional salting
- Custom salt values

### Attack Parameters
- Simulated attack speeds (CPU to supercomputer)
- Maximum attempt limits
- Character set configurations

## 📚 Educational Resources

The suite includes comprehensive educational content covering:
- Hash algorithm fundamentals
- Common attack methodologies
- Defense strategies and countermeasures
- Real-world breach analysis
- Industry best practices

**Educational Purpose Only**
This tool is designed for educational and research purposes to demonstrate password security concepts. It should not be used for unauthorized access attempts or any malicious activities. Always respect privacy and legal boundaries when conducting security research.

## 🙏 Acknowledgments

- Built with [Streamlit](https://streamlit.io/)
- Data visualization powered by [Plotly](https://plotly.com/)
- Inspired by cybersecurity best practices and educational tools

---

**Made with ❤️ for cybersecurity education**

⭐ Star this repo if you find it helpful!
