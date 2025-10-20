import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import time

# Import backend functions
from backend import (
    hash_password, hash_with_iterations, compare_hash_speeds,
    calculate_password_strength, dictionary_attack, brute_force_attack,
    hybrid_attack, estimate_crack_time, generate_secure_password,
    generate_passphrase, check_common_breaches, export_analysis_report
)

# ================== PAGE CONFIG ==================

st.set_page_config(
    page_title="Advanced Password Security Suite",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ================== CUSTOM CSS ==================

def load_custom_css():
    """Load custom CSS styling"""
    st.markdown("""
    <style>
        .stMetric {
            background-color: #f0f2f6;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid rgba(0, 0, 0, 0.08);
        }
        /* Improve metric label/value contrast */
        .stMetric [data-testid="stMetricLabel"] {
            color: #1e293b;
            font-weight: 600;
        }
        .stMetric [data-testid="stMetricValue"] {
            color: #0f172a;
            font-weight: 700;
        }
        @media (prefers-color-scheme: dark) {
            .stMetric {
                background: rgba(255, 255, 255, 0.06) !important;
                border: 1px solid rgba(255, 255, 255, 0.12);
            }
            .stMetric [data-testid="stMetricLabel"] {
                color: rgba(255, 255, 255, 0.9) !important;
            }
            .stMetric [data-testid="stMetricValue"] {
                color: #ffffff !important;
            }
        }
        .success-box {
            padding: 15px;
            border-radius: 5px;
            background-color: #d4edda;
            border-left: 5px solid #28a745;
            margin: 10px 0;
        }
        .warning-box {
            padding: 15px;
            border-radius: 5px;
            background-color: #fff3cd;
            border-left: 5px solid #ffc107;
            margin: 10px 0;
        }
        .danger-box {
            padding: 15px;
            border-radius: 5px;
            background-color: #f8d7da;
            border-left: 5px solid #dc3545;
            margin: 10px 0;
        }
        /* Section titles to ensure visibility in dark mode */
        .section-title {
            font-weight: 700;
            margin: 12px 0 8px;
            padding: 8px 12px;
            border-left: 4px solid #4CAF50;
            border-radius: 4px;
            background: rgba(0, 0, 0, 0.05);
            color: inherit;
        }
        @media (prefers-color-scheme: dark) {
            .section-title {
                background: rgba(255, 255, 255, 0.06);
                color: #ffffff !important;
                text-shadow: 0 1px 2px rgba(0, 0, 0, 0.4);
            }
        }
    </style>
    """, unsafe_allow_html=True)


# ================== SIDEBAR CONFIGURATION ==================

def sidebar_configuration():
    st.sidebar.title("⚙️ Configuration")

    st.sidebar.markdown("---")
    st.sidebar.subheader("Hash Settings")

    hash_algo = st.sidebar.selectbox(
        "Hash Algorithm",
        ['md5', 'sha1', 'sha256', 'sha512'],
        index=2,
        help="Select the hashing algorithm to use"
    )

    use_salt = st.sidebar.checkbox("Enable Salting", value=False)
    salt_value = ""
    if use_salt:
        salt_value = st.sidebar.text_input("Salt Value", value="random_salt_123")

    st.sidebar.markdown("---")
    st.sidebar.subheader("Attack Settings")

    # Use labels for the slider
    attack_speed_labels = [
        'Slow CPU',
        'Fast CPU',
        'GPU',
        'High-end GPU',
        'Super Computer'
    ]
    attack_speed_values = {
        'Slow CPU': 1_000_000,
        'Fast CPU': 10_000_000,
        'GPU': 100_000_000,
        'High-end GPU': 1_000_000_000,
        'Super Computer': 10_000_000_000
    }
    attack_speed_label = st.sidebar.select_slider(
        "Simulated Attack Speed",
        options=attack_speed_labels,
        value='High-end GPU'
    )
    attack_speed = attack_speed_values[attack_speed_label]

    st.sidebar.markdown("---")
    st.sidebar.info(
        "🛡️ **Educational Purpose Only**\n\n"
        "This tool demonstrates password security concepts. "
        "Never use it for unauthorized access attempts."
    )

    st.sidebar.markdown("---")
    st.sidebar.caption(f"© {datetime.now().year} Password Security Suite")

    return hash_algo, salt_value, attack_speed




# ================== UTILITY FUNCTIONS ==================

def create_strength_gauge(score):
    """Create a gauge chart for password strength"""
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={'x': [0, 1], 'y': [0, 1]},
        title={'text': "Strength Score"},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 40], 'color': "lightcoral"},
                {'range': [40, 60], 'color': "lightyellow"},
                {'range': [60, 80], 'color': "lightgreen"},
                {'range': [80, 100], 'color': "darkgreen"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 90
            }
        }
    ))
    fig.update_layout(height=250)
    return fig


def create_entropy_chart(metrics):
    """Create a bar chart for character type distribution"""
    char_types = ['Lowercase', 'Uppercase', 'Digits', 'Special']
    values = [
        metrics['has_lower'],
        metrics['has_upper'],
        metrics['has_digit'],
        metrics['has_special']
    ]

    fig = go.Figure(data=[
        go.Bar(x=char_types, y=values, marker_color=['blue', 'green', 'orange', 'red'])
    ])
    fig.update_layout(
        title="Character Type Distribution",
        yaxis_title="Present (1) / Absent (0)",
        height=300
    )
    return fig


def create_crack_time_comparison(estimates):
    """Create comparison chart for crack times"""
    scenarios = ['Best Case', 'Average Case', 'Worst Case']
    times = [
        estimates['best_case_seconds'],
        estimates['average_case_seconds'],
        estimates['worst_case_seconds']
    ]

    # Convert to log scale for better visualization
    import math
    log_times = [math.log10(t + 1) for t in times]

    fig = go.Figure(data=[
        go.Bar(x=scenarios, y=log_times, marker_color=['green', 'orange', 'red'])
    ])
    fig.update_layout(
        title="Crack Time Scenarios (Log Scale)",
        yaxis_title="Log10(Seconds)",
        height=300
    )
    return fig


# ================== MAIN TABS ==================

def tab_strength_checker(hash_algo, salt_value, attack_speed):
    """Enhanced Strength Checker Tab"""
    st.header("🔍 Advanced Password Strength Analysis")

    col1, col2 = st.columns([2, 1])

    with col1:
        password = st.text_input(
            "Enter password to analyze:",
            type="password",
            key="strength_password",
            help="Your password is never stored or transmitted"
        )

        show_password = st.checkbox("👁️ Show password", key="show_pw_strength")
        if show_password and password:
            st.code(password, language="text")

        if password:
            # Calculate strength
            score, strength, color, feedback, metrics = calculate_password_strength(password)

            # Display results in columns
            st.markdown('<h3 class="section-title">📊 Comprehensive Analysis</h3>', unsafe_allow_html=True)

            col_a, col_b, col_c = st.columns(3)

            with col_a:
                st.metric("Strength Score", f"{score}/100")
                st.metric("Password Length", metrics['length'])

            with col_b:
                st.metric("Unique Characters", metrics['unique_chars'])
                st.metric("Entropy (bits)", f"{metrics['entropy']:.2f}")

            with col_c:
                st.metric("Character Types", sum([
                    metrics['has_lower'],
                    metrics['has_upper'],
                    metrics['has_digit'],
                    metrics['has_special']
                ]))
                st.metric("Repeated Chars", metrics['repeated_chars'])

            # Strength gauge
            st.plotly_chart(create_strength_gauge(score), use_container_width=True)

            # Character distribution
            st.plotly_chart(create_entropy_chart(metrics), use_container_width=True)

            # Feedback section
            if feedback:
                st.markdown("### 💡 Recommendations")
                for item in feedback:
                    st.markdown(f"- {item}")
            else:
                st.markdown('<div class="success-box">✅ Excellent! Your password meets all security criteria.</div>',
                            unsafe_allow_html=True)

            # Hash display
            st.markdown("### 🔐 Password Hashes")
            hash_value = hash_password(password, hash_algo, salt_value)

            hash_col1, hash_col2 = st.columns(2)
            with hash_col1:
                st.code(f"{hash_algo.upper()}: {hash_value}", language="text")
            with hash_col2:
                if salt_value:
                    st.info(f"🧂 Salt applied: `{salt_value}`")

            # Crack time estimates
            st.markdown('<h3 class="section-title">⏱️ Estimated Crack Time</h3>', unsafe_allow_html=True)
            estimates = estimate_crack_time(password, attack_speed)

            est_col1, est_col2, est_col3 = st.columns(3)
            with est_col1:
                st.metric("Best Case", estimates['best_case'])
            with est_col2:
                st.metric("Average Case", estimates['average_case'])
            with est_col3:
                st.metric("Worst Case", estimates['worst_case'])

            st.info(f"📊 Total possible combinations: {estimates['total_combinations']:,}")

            # Visualization
            st.plotly_chart(create_crack_time_comparison(estimates), use_container_width=True)

            # Breach check
            st.markdown("### 🔍 Data Breach Check")
            breach_result = check_common_breaches(password)

            if breach_result['is_breached']:
                st.markdown(
                    f'<div class="danger-box">{breach_result["recommendation"]}<br><strong>{breach_result["breach_count"]}</strong></div>',
                    unsafe_allow_html=True)
            else:
                st.markdown(f'<div class="success-box">{breach_result["recommendation"]}</div>', unsafe_allow_html=True)

            # Export report
            st.markdown("### 📥 Export Analysis")
            if st.button("Generate JSON Report"):
                report_data = {
                    'score': score,
                    'strength': strength,
                    'metrics': metrics,
                    'estimates': estimates,
                    'breach_check': breach_result
                }
                report = export_analysis_report(password, report_data)
                st.download_button(
                    label="Download Report",
                    data=report,
                    file_name=f"password_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )

    with col2:
        st.markdown("### 📋 Security Guidelines")
        st.markdown("""
        **Strong passwords should:**
        - ✅ Be 16+ characters long
        - ✅ Use uppercase & lowercase
        - ✅ Include numbers (0-9)
        - ✅ Include special characters
        - ✅ Avoid dictionary words
        - ✅ Avoid personal information
        - ✅ Be unique per account

        **Avoid:**
        - ❌ Common passwords
        - ❌ Keyboard patterns
        - ❌ Sequential characters
        - ❌ Repeated characters
        - ❌ Personal dates/names

        **Best Practices:**
        - 🔐 Use password managers
        - 🔐 Enable 2FA/MFA
        - 🔐 Change regularly
        - 🔐 Never share passwords
        - 🔐 Use different passwords
        """)


def tab_attack_simulator(hash_algo, salt_value, attack_speed):
    """Enhanced Attack Simulator Tab"""
    st.header("💥 Advanced Attack Simulation Suite")

    st.warning(
        "⚠️ **Educational Demonstration Only** - Results are simulated with limited scope for learning purposes.")

    # Attack type selection
    attack_type = st.radio(
        "Select Attack Method:",
        ["🔍 Dictionary Attack", "🔨 Brute Force Attack", "🎯 Hybrid Attack", "⚡ Speed Comparison"]
    )

    test_password = st.text_input(
        "Enter password to test:",
        type="password",
        key="attack_password",
        help="Test password against simulated attacks"
    )

    show_password_attack = st.checkbox("👁️ Show password", key="show_pw_attack")
    if show_password_attack and test_password:
        st.code(test_password, language="text")

    # Attack-specific settings
    if attack_type == "🔍 Dictionary Attack":
        st.info("📖 Tests password against a dictionary of 60+ common passwords")
        max_attempts = st.slider("Maximum Attempts", 10, 100, 60)

    elif attack_type == "🔨 Brute Force Attack":
        st.info("🔨 Tests all combinations of characters (limited for demonstration)")
        col1, col2 = st.columns(2)
        with col1:
            max_length = st.slider("Maximum Password Length", 1, 6, 4)
        with col2:
            charset_type = st.selectbox(
                "Character Set",
                ["lowercase+digits", "lowercase", "uppercase", "lowercase+uppercase", "all"]
            )
        max_attempts = st.slider("Maximum Attempts", 100, 50000, 5000)

    elif attack_type == "🎯 Hybrid Attack":
        st.info("🎯 Combines dictionary words with common number/symbol variations")
        max_attempts = st.slider("Maximum Attempts", 50, 500, 100)

    else:  # Speed Comparison
        st.info("⚡ Compare all attack methods simultaneously")
        max_attempts = 1000

    # Run attack button
    if st.button("🚀 Launch Attack Simulation", type="primary"):
        if not test_password:
            st.error("❌ Please enter a password to test")
        else:
            # Generate target hash
            target_hash = hash_password(test_password, hash_algo, salt_value)

            st.markdown("### 🎯 Target Information")
            st.code(f"Password Length: {len(test_password)} characters\nHash ({hash_algo.upper()}): {target_hash}",
                    language="text")

            if salt_value:
                st.info(f"🧂 Salt: `{salt_value}`")

            st.markdown("---")

            if attack_type != "⚡ Speed Comparison":
                # Single attack execution
                with st.spinner(f"🔄 Running {attack_type}..."):
                    progress_bar = st.progress(0)

                    # Set default values for brute force parameters
                    max_length = 4  # Default value
                    charset_type = "lowercase+digits"  # Default value
    
                    if attack_type == "🔍 Dictionary Attack":
                        success, cracked_pw, attempts, elapsed, aps = dictionary_attack(
                            target_hash, hash_algo, salt_value, max_attempts
                        )
                    elif attack_type == "🔨 Brute Force Attack":
                        success, cracked_pw, attempts, elapsed, aps = brute_force_attack(
                            target_hash, hash_algo, salt_value, max_length, max_attempts, charset_type
                        )
                    else:  # Hybrid
                        success, cracked_pw, attempts, elapsed, aps = hybrid_attack(
                            target_hash, hash_algo, salt_value, max_attempts
                        )

                    progress_bar.progress(100)
                    time.sleep(0.3)

                # Display results
                st.markdown("### 📈 Attack Results")

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total Attempts", f"{attempts:,}")
                col2.metric("Time Elapsed", f"{elapsed:.4f}s")
                col3.metric("Speed", f"{int(aps):,} attempts/s")
                col4.metric("Status", "✅ Cracked" if success else "❌ Failed")

                if success:
                    st.markdown(
                        f'<div class="danger-box"><strong>🚨 PASSWORD CRACKED!</strong><br>The password was: <code>{cracked_pw}</code><br><br>⚠️ This password is WEAK and easily compromised!</div>',
                        unsafe_allow_html=True)
                else:
                    st.markdown(
                        f'<div class="success-box"><strong>✅ Password Survived</strong><br>Password was not cracked within {attempts:,} attempts.<br><br>This suggests better resistance (within the limited test scope).</div>',
                        unsafe_allow_html=True)

            else:
                # Speed comparison mode
                st.markdown("### 🏁 Running All Attack Methods...")

                results = []

                # Dictionary Attack
                with st.spinner("Running Dictionary Attack..."):
                    success1, pw1, att1, time1, aps1 = dictionary_attack(
                        target_hash, hash_algo, salt_value, max_attempts
                    )
                    results.append({
                        'Method': 'Dictionary',
                        'Success': '✅' if success1 else '❌',
                        'Attempts': att1,
                        'Time (s)': f"{time1:.4f}",
                        'Speed (att/s)': f"{int(aps1):,}"
                    })

                # Brute Force Attack
                with st.spinner("Running Brute Force Attack..."):
                    success2, pw2, att2, time2, aps2 = brute_force_attack(
                        target_hash, hash_algo, salt_value, 4, max_attempts, 'lowercase+digits'
                    )
                    results.append({
                        'Method': 'Brute Force',
                        'Success': '✅' if success2 else '❌',
                        'Attempts': att2,
                        'Time (s)': f"{time2:.4f}",
                        'Speed (att/s)': f"{int(aps2):,}"
                    })

                # Hybrid Attack
                with st.spinner("Running Hybrid Attack..."):
                    success3, pw3, att3, time3, aps3 = hybrid_attack(
                        target_hash, hash_algo, salt_value, max_attempts
                    )
                    results.append({
                        'Method': 'Hybrid',
                        'Success': '✅' if success3 else '❌',
                        'Attempts': att3,
                        'Time (s)': f"{time3:.4f}",
                        'Speed (att/s)': f"{int(aps3):,}"
                    })

                # Display comparison table
                df = pd.DataFrame(results)
                st.dataframe(df, use_container_width=True)

                # Determine which attack succeeded first
                successful_attacks = [
                    ('Dictionary', success1, time1, pw1),
                    ('Brute Force', success2, time2, pw2),
                    ('Hybrid', success3, time3, pw3)
                ]

                successful = [a for a in successful_attacks if a[1]]

                if successful:
                    fastest = min(successful, key=lambda x: x[2])
                    st.markdown(
                        f'<div class="danger-box"><strong>🚨 PASSWORD CRACKED!</strong><br>Fastest method: <strong>{fastest[0]}</strong> in {fastest[2]:.4f}s<br>Password: <code>{fastest[3]}</code></div>',
                        unsafe_allow_html=True)
                else:
                    st.markdown(
                        '<div class="success-box"><strong>✅ All Attacks Failed</strong><br>Password survived all attack methods within the attempt limits.</div>',
                        unsafe_allow_html=True)


def tab_password_generator(hash_algo, salt_value, attack_speed):
    """Password Generator Tab"""
    st.header("🎲 Secure Password Generator")

    col1, col2 = st.columns(2)

    with col1:
        st.markdown("### 🔐 Random Password Generator")

        length = st.slider("Password Length", 8, 32, 16)

        include_upper = st.checkbox("Include Uppercase (A-Z)", value=True)
        include_lower = st.checkbox("Include Lowercase (a-z)", value=True)
        include_digits = st.checkbox("Include Digits (0-9)", value=True)
        include_special = st.checkbox("Include Special (!@#$%^&*)", value=True)
        exclude_ambiguous = st.checkbox("Exclude Ambiguous (0,O,l,1)", value=True)

        if st.button("🎲 Generate Random Password", type="primary"):
            try:
                generated_pw = generate_secure_password(
                    length, include_upper, include_lower,
                    include_digits, include_special, exclude_ambiguous
                )

                st.success("Password Generated Successfully!")
                st.code(generated_pw, language="text")

                # Analyze generated password
                score, strength, color, feedback, metrics = calculate_password_strength(generated_pw)
                st.metric("Strength Score", f"{score}/100")
                st.progress(score / 100)

                # Copy button simulation
                st.info("💡 Copy this password to your password manager")

            except ValueError as e:
                st.error(f"❌ Error: {str(e)}")

    with col2:
        st.markdown("### 📝 Passphrase Generator")
        st.info("Passphrases are easier to remember and can be very secure!")

        word_count = st.slider("Number of Words", 3, 6, 4)
        separator = st.selectbox("Word Separator", ['-', '_', ' ', '.', ''], index=0)
        capitalize_words = st.checkbox("Capitalize Words", value=True)
        add_number = st.checkbox("Add Random Number", value=True)

        if st.button("📝 Generate Passphrase", type="primary"):
            passphrase = generate_passphrase(
                word_count, separator, capitalize_words, add_number
            )

            st.success("Passphrase Generated Successfully!")
            st.code(passphrase, language="text")

            # Analyze passphrase
            score, strength, color, feedback, metrics = calculate_password_strength(passphrase)
            st.metric("Strength Score", f"{score}/100")
            st.progress(score / 100)

            st.info("💡 Passphrases are great for master passwords!")

    # Batch generation
    st.markdown("---")
    st.markdown("### 📦 Batch Password Generation")

    batch_count = st.number_input("How many passwords to generate?", 1, 20, 5)

    if st.button("🎲 Generate Batch"):
        st.markdown("#### Generated Passwords")
        passwords = []
        for i in range(batch_count):
            pw = generate_secure_password(16)
            passwords.append(pw)
            st.code(f"{i + 1}. {pw}", language="text")

        # Option to export
        if st.button("📥 Export as Text File"):
            password_text = "\n".join([f"{i + 1}. {pw}" for i, pw in enumerate(passwords)])
            st.download_button(
                label="Download Passwords",
                data=password_text,
                file_name=f"passwords_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )


def tab_hash_comparison(hash_algo, salt_value, attack_speed):
    """Hash Algorithm Comparison Tab"""
    st.header("⚡ Hash Algorithm Performance Analysis")

    test_input = st.text_input("Enter text to hash:", value="TestPassword123!")
    iterations = st.slider("Number of iterations for speed test", 100, 10000, 1000)

    if st.button("🚀 Run Performance Test"):
        with st.spinner("Running performance tests..."):
            speeds = compare_hash_speeds(test_input, iterations)

        st.markdown("### 📊 Performance Results")

        # Create DataFrame
        df = pd.DataFrame({
            'Algorithm': list(speeds.keys()),
            'Time (seconds)': list(speeds.values()),
            'Hashes per second': [iterations / t for t in speeds.values()]
        })

        st.dataframe(df, use_container_width=True)

        # Visualization
        fig = px.bar(df, x='Algorithm', y='Time (seconds)',
                     title='Hash Algorithm Speed Comparison',
                     color='Algorithm')
        st.plotly_chart(fig, use_container_width=True)

        # Display actual hashes
        st.markdown("### 🔐 Hash Outputs")
        for algo in ['md5', 'sha1', 'sha256', 'sha512']:
            hash_val = hash_password(test_input, algo, salt_value)
            st.code(f"{algo.upper()}: {hash_val}", language="text")

        # Key stretching demo
        st.markdown("### 🔄 Key Stretching Demonstration")
        stretch_iterations = st.slider("Stretching iterations", 1, 10000, 1000, step=1000)

        if st.button("Run Key Stretching"):
            start = time.time()
            stretched = hash_with_iterations(test_input, stretch_iterations, hash_algo)
            elapsed = time.time() - start

            st.success(f"Completed {stretch_iterations:,} iterations in {elapsed:.4f} seconds")
            st.code(f"Final hash: {stretched}", language="text")
            st.info(f"⏱️ This slows down attackers by a factor of {stretch_iterations:,}x")


def tab_education(hash_algo, salt_value, attack_speed):
    """Educational Content Tab"""
    st.header("📚 Password Security Education Center")

    edu_tab = st.radio(
        "Select Topic:",
        ["🔐 Hash Algorithms", "💥 Attack Methods", "🛡️ Defense Strategies",
         "📊 Real-World Examples", "🎯 Best Practices"]
    )

    if edu_tab == "🔐 Hash Algorithms":
        col1, col2 = st.columns(2)

        with col1:
            st.markdown("""
            ### Hash Algorithm Overview

            **MD5 (Message Digest 5)**
            - 🔴 **Security**: Broken
            - ⚡ **Speed**: Very Fast
            - 📏 **Output**: 128 bits
            - ⚠️ **Status**: Deprecated
            - **Use**: Checksums only, NOT passwords

            **SHA-1 (Secure Hash Algorithm 1)**
            - 🟡 **Security**: Weak
            - ⚡ **Speed**: Fast
            - 📏 **Output**: 160 bits
            - ⚠️ **Status**: Deprecated
            - **Use**: Legacy systems only

            **SHA-256**
            - 🟢 **Security**: Strong
            - ⚡ **Speed**: Moderate
            - 📏 **Output**: 256 bits
            - ✅ **Status**: Recommended
            - **Use**: Most applications

            **SHA-512**
            - 🟢 **Security**: Very Strong
            - ⚡ **Speed**: Slower
            - 📏 **Output**: 512 bits
            - ✅ **Status**: Recommended
            - **Use**: High-security applications
            """)

        with col2:
            st.markdown("""
            ### Modern Password Hashing

            **Why Simple Hashing Isn't Enough:**
            - Too fast = Easy to brute force
            - No salt = Rainbow table attacks
            - No key stretching = Vulnerable

            **Modern Solutions:**

            **bcrypt**
            - Built-in salting
            - Adaptive (configurable work factor)
            - Industry standard
            - Resistant to GPU attacks

            **Argon2**
            - Winner of Password Hashing Competition
            - Memory-hard algorithm
            - Resistant to GPUs and ASICs
            - Configurable memory/time costs

            **PBKDF2**
            - Widely supported
            - Configurable iterations
            - NIST recommended
            - Good for compliance needs

            **Key Principles:**
            1. ✅ Always use salt (unique per password)
            2. ✅ Use many iterations (key stretching)
            3. ✅ Use modern algorithms (bcrypt/Argon2)
            4. ✅ Never implement your own crypto
            """)

    elif edu_tab == "💥 Attack Methods":
        st.markdown("""
        ### Common Password Attack Methods

        #### 1. 🔍 Dictionary Attack
        **How it works:**
        - Uses pre-compiled list of common passwords
        - Tests millions of common words and phrases
        - Very fast and effective against weak passwords

        **Defense:**
        - Avoid dictionary words
        - Use random characters
        - Add special characters and numbers

        #### 2. 🔨 Brute Force Attack
        **How it works:**
        - Tries every possible character combination
        - Starts with shortest passwords
        - Guaranteed to work eventually

        **Defense:**
        - Use longer passwords (16+ characters)
        - Increase character variety
        - Makes search space exponentially larger

        #### 3. 🌈 Rainbow Table Attack
        **How it works:**
        - Pre-computed hash tables
        - Instant lookup of hash → password
        - Very fast once table is built

        **Defense:**
        - Always use salting
        - Unique salt per password
        - Makes rainbow tables useless

        #### 4. 🎣 Credential Stuffing
        **How it works:**
        - Uses leaked credentials from other breaches
        - Tests them on multiple services
        - Exploits password reuse

        **Defense:**
        - Unique password per site
        - Use password manager
        - Enable 2FA/MFA

        #### 5. 📱 Social Engineering
        **How it works:**
        - Tricks user into revealing password
        - Phishing, pretexting, baiting
        - Exploits human psychology

        **Defense:**
        - User education
        - Verify requests
        - Never share passwords
        """)

    elif edu_tab == "🛡️ Defense Strategies":
        st.markdown("""
        ### Comprehensive Defense Strategies

        #### Password Policy
        ```
        ✅ Minimum 12 characters (16+ recommended)
        ✅ Require uppercase and lowercase
        ✅ Require numbers and special characters
        ✅ Prevent common passwords
        ✅ Prevent password reuse
        ✅ Regular password changes (for sensitive accounts)
        ✅ Account lockout after failed attempts
        ```

        #### Technical Controls

        **1. Salting**
        - Add random data before hashing
        - Unique salt per password
        - Store salt with hash

        **2. Key Stretching (Iteration)**
        - Hash multiple times
        - Configurable work factor
        - Slows down attacks significantly

        **3. Pepper (Secret Key)**
        - Application-wide secret
        - Stored separately from database
        - Additional layer of security

        **4. Rate Limiting**
        - Limit login attempts
        - Implement delays
        - CAPTCHA after failures

        #### Multi-Factor Authentication (MFA)
        - Something you know (password)
        - Something you have (phone/token)
        - Something you are (biometric)

        #### Password Managers
        - Generate strong passwords
        - Store securely
        - Auto-fill credentials
        - Sync across devices

        **Popular Options:**
        - 1Password
        - Bitwarden
        - LastPass
        - KeePass (offline)
        """)

    elif edu_tab == "📊 Real-World Examples":
        st.markdown("""
        ### Real-World Password Breaches

        #### Case Study 1: LinkedIn (2012)
        - **Breach**: 6.5 million password hashes
        - **Issue**: Unsalted SHA-1 hashes
        - **Result**: Millions cracked within days
        - **Lesson**: Always use salting

        #### Case Study 2: Adobe (2013)
        - **Breach**: 153 million accounts
        - **Issue**: Encrypted (not hashed), weak encryption
        - **Result**: Massive password exposure
        - **Lesson**: Hash, don't encrypt passwords

        #### Case Study 3: Equifax (2017)
        - **Breach**: 147 million records
        - **Issue**: Unpatched vulnerability
        - **Result**: Full identity theft potential
        - **Lesson**: Keep systems updated

        ### Most Common Passwords (2024)

        | Rank | Password | Time to Crack |
        |------|----------|---------------|
        | 1 | 123456 | Instant |
        | 2 | password | Instant |
        | 3 | 123456789 | Instant |
        | 4 | 12345678 | Instant |
        | 5 | 12345 | Instant |
        | 6 | qwerty | Instant |
        | 7 | password1 | Instant |
        | 8 | 111111 | Instant |
        | 9 | welcome | Instant |
        | 10 | admin | Instant |

        **⚠️ Never use these passwords!**

        ### Good vs Bad Examples

        #### 🔴 Weak Passwords:
        - `password` - Dictionary word
        - `123456` - Sequential numbers
        - `qwerty` - Keyboard pattern
        - `John1990` - Name + year
        - `iloveyou` - Common phrase

        #### 🟢 Strong Passwords:
        - `Tr0ub4dor&3` - Mixed, memorable
        - `correct-horse-battery-staple` - Passphrase
        - `mQ9#xL2$pK8!nZ5@` - Random, strong
        - `Purple!Elephant$Dance23` - Creative phrase
        - `K7$nMp2@xQ9#wR5!` - Generated
        """)

    else:  # Best Practices
        st.markdown("""
        ### Password Security Best Practices

        #### For Users

        **DO:**
        - ✅ Use unique passwords for each account
        - ✅ Use a password manager
        - ✅ Enable 2FA/MFA everywhere possible
        - ✅ Use passphrases (easier to remember)
        - ✅ Make passwords at least 16 characters
        - ✅ Check if your email has been breached (haveibeenpwned.com)
        - ✅ Update passwords for breached accounts
        - ✅ Use biometric authentication when available

        **DON'T:**
        - ❌ Reuse passwords across sites
        - ❌ Share passwords with anyone
        - ❌ Write passwords on sticky notes
        - ❌ Use personal information (birthdays, names)
        - ❌ Use common words or patterns
        - ❌ Save passwords in browsers (use password manager instead)
        - ❌ Send passwords via email or text
        - ❌ Use public computers for sensitive accounts

        #### For Developers

        **DO:**
        - ✅ Use bcrypt, Argon2, or PBKDF2
        - ✅ Implement salting (automatic in modern algorithms)
        - ✅ Use appropriate work factors
        - ✅ Implement rate limiting
        - ✅ Use HTTPS everywhere
        - ✅ Implement password strength meters
        - ✅ Check against breach databases
        - ✅ Require 2FA for sensitive operations
        - ✅ Implement secure password reset flows
        - ✅ Log authentication attempts

        **DON'T:**
        - ❌ Store passwords in plain text
        - ❌ Use weak hashing (MD5, SHA-1)
        - ❌ Implement your own crypto
        - ❌ Email passwords to users
        - ❌ Limit password length unreasonably
        - ❌ Enforce frequent password changes (unless compromised)
        - ❌ Store passwords in logs
        - ❌ Use weak password policies

        #### Password Manager Recommendations

        **Cloud-Based:**
        - 1Password (Best UI/UX)
        - Bitwarden (Open source, affordable)
        - Dashlane (Feature-rich)

        **Self-Hosted:**
        - KeePass (Offline, portable)
        - Bitwarden (Self-host option)
        - Pass (Unix password manager)

        #### Two-Factor Authentication Apps
        - Authy
        - Google Authenticator
        - Microsoft Authenticator
        - YubiKey (Hardware key)

        ### Incident Response Plan

        1. **Identify**: Detect and confirm breach quickly (automated alerts)
        2. **Contain**: Limit damage (disable affected accounts)
        3. **Eradicate**: Remove threat (patch vulnerabilities)
        4. **Recover**: Restore systems (force password resets)
        5. **Review**: Analyze incident (improve defenses)
        """)
# ================== MAIN APPLICATION ==================
def main():
    st.set_page_config(
        page_title="Password Security Suite",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Load custom CSS
    load_custom_css()

    # Sidebar configuration
    hash_algo, salt_value, attack_speed = sidebar_configuration()

    # Main tabs
    tabs = st.tabs([
        "🔍 Strength Checker",
        "💥 Attack Simulator",
        "🎲 Password Generator",
        "⚡ Hash Comparison",
        "📚 Education Center"
    ])

    with tabs[0]:
        tab_strength_checker(hash_algo, salt_value, attack_speed)

    with tabs[1]:
        tab_attack_simulator(hash_algo, salt_value, attack_speed)

    with tabs[2]:
        tab_password_generator(hash_algo, salt_value, attack_speed)

    with tabs[3]:
        tab_hash_comparison(hash_algo, salt_value, attack_speed)

    with tabs[4]:
        tab_education(hash_algo, salt_value, attack_speed)
if __name__ == "__main__":
    main()
