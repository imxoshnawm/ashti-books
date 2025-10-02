<?php
require_once 'config.php';

// ئەگەر ئەدمین لە پێشدا چووبێتە ژوورەوە، بیگەڕێنەوە بۆ داشبۆرد
if (isset($_SESSION['admin_id'])) {
    header("Location: admin_dashboard.php");
    exit();
}

$error_message = '';
$success_message = '';

// پرۆسێسی چوونەژوورەوە
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    $phone = clean_input($_POST['phone']);
    $password = $_POST['password'];
    
    if (empty($phone) || empty($password)) {
        $error_message = "تکایە ژمارە مۆبایل و پاسسۆرد بنوسە";
    } else {
        // چەکردنی ئەدمین لە بنکەی داتا
        $stmt = $conn->prepare("SELECT * FROM admins WHERE phone_number = ?");
        $stmt->execute([$phone]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($admin && md5($password) === $admin['password']) {
            // دروستکردنی سیشن
            $_SESSION['admin_id'] = $admin['admin_id'];
            $_SESSION['admin_name'] = $admin['admin_name'];
            $_SESSION['admin_type'] = $admin['admin_type'];
            $_SESSION['phone_number'] = $admin['phone_number'];
            
            header("Location: admin_dashboard.php");
            exit();
        } else {
            $error_message = "ژمارە مۆبایل یان پاسسۆرد هەڵەیە";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>چوونەژوورەوەی ئەدمین - کتێبخانەی ئاشتی</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500&family=Crimson+Text:ital,wght@0,400;0,600;1,400&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Crimson Text', 'Playfair Display', serif;
            background: linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            direction: rtl;
            padding: 20px;
            color: #2a2a2a;
            line-height: 1.7;
        }

        .login-container {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.08);
            border-radius: 8px;
            padding: 3rem;
            width: 100%;
            max-width: 500px;
            position: relative;
            overflow: hidden;
        }

        .login-container::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 3px;
            background: #c0c0c0;
        }

        .logo-section {
            text-align: center;
            margin-bottom: 2.5rem;
        }

        .logo {
            width: 85px;
            height: 85px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 1rem;
            transition: all 0.3s ease;
        }

        .logo:hover {
            transform: scale(1.05);
        }

        .logo img {
            width: 70px;
            height: 70px;
            object-fit: contain;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
        }

        .brand-info h1 {
            font-family: 'Playfair Display', serif;
            font-size: 2rem;
            font-weight: 700;
            color: #2a2a2a;
            margin-bottom: 0.3rem;
            font-style: italic;
        }

        .brand-info p {
            color: #666;
            font-size: 0.95rem;
            font-weight: 500;
        }

        .form-title {
            text-align: center;
            color: #2a2a2a;
            font-family: 'Playfair Display', serif;
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 2rem;
            position: relative;
            display: inline-block;
            width: 100%;
        }

        .form-title::after {
            content: '';
            position: absolute;
            bottom: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 1px;
            background: #c0c0c0;
        }

        .form-group {
            margin-bottom: 1.8rem;
            position: relative;
        }

        .form-label {
            display: block;
            color: #2a2a2a;
            font-weight: 600;
            margin-bottom: 0.5rem;
            font-size: 1rem;
        }

        .form-input {
            width: 100%;
            padding: 1rem 1.2rem;
            border: 1px solid #e5e5e5;
            border-radius: 4px;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.3s ease;
            background: #fafafa;
            direction: rtl;
        }

        .form-input:focus {
            outline: none;
            border-color: #c0c0c0;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(192, 192, 192, 0.1);
        }

        .form-input::placeholder {
            color: #999;
            font-style: italic;
        }

        .phone-input {
            direction: ltr;
            text-align: left;
        }

        .phone-input::placeholder {
            text-align: right;
            direction: rtl;
        }

        .login-btn {
            width: 100%;
            padding: 1rem;
            background: #2a2a2a;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            font-size: 1.1rem;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-top: 1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .login-btn:hover {
            background: #c0c0c0;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(192, 192, 192, 0.3);
        }

        .login-btn:active {
            transform: translateY(0);
        }

        .error-message {
            background: #fff5f5;
            color: #e53e3e;
            padding: 1rem;
            border: 1px solid #fed7d7;
            border-right: 4px solid #e53e3e;
            border-radius: 4px;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }

        .success-message {
            background: #f0fff4;
            color: #38a169;
            padding: 1rem;
            border: 1px solid #c6f6d5;
            border-right: 4px solid #38a169;
            border-radius: 4px;
            margin-bottom: 1.5rem;
            font-weight: 500;
        }

        .back-link {
            text-align: center;
            margin-top: 2rem;
            padding-top: 1.5rem;
            border-top: 1px solid #e5e5e5;
        }

        .back-link a {
            color: #666;
            text-decoration: none;
            font-weight: 500;
            font-size: 0.95rem;
            transition: all 0.3s ease;
            padding: 0.5rem 1rem;
            border: 1px solid transparent;
            border-radius: 4px;
        }

        .back-link a:hover {
            color: #2a2a2a;
            border-color: #e5e5e5;
            background: #f8f8f8;
        }

        .decorative-border {
            width: 80px;
            height: 1px;
            background: #c0c0c0;
            margin: 1.5rem auto;
            position: relative;
        }

        .decorative-border::before,
        .decorative-border::after {
            content: '';
            position: absolute;
            width: 6px;
            height: 6px;
            background: #c0c0c0;
            border-radius: 50%;
            top: -2.5px;
        }

        .decorative-border::before {
            left: -3px;
        }

        .decorative-border::after {
            right: -3px;
        }

        /* Loading state */
        .loading {
            opacity: 0.7;
            pointer-events: none;
        }

        .loading .login-btn {
            background: #999;
            cursor: not-allowed;
        }

        /* Animation */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .login-container {
            animation: fadeInUp 0.6s ease-out;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .login-container {
                padding: 2rem;
                margin: 1rem;
            }
            
            .brand-info h1 {
                font-size: 1.7rem;
            }
            
            .form-title {
                font-size: 1.5rem;
            }
        }

        @media (max-width: 480px) {
            .login-container {
                padding: 1.5rem;
            }
            
            .brand-info h1 {
                font-size: 1.5rem;
            }
            
            .form-title {
                font-size: 1.3rem;
            }
            
            .form-input {
                padding: 0.8rem 1rem;
            }
        }

        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 8px;
        }

        ::-webkit-scrollbar-track {
            background: #f1f1f1;
        }

        ::-webkit-scrollbar-thumb {
            background: #c0c0c0;
            border-radius: 4px;
        }

        ::-webkit-scrollbar-thumb:hover {
            background: #a0a0a0;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo-section">
            <div class="logo">
                <img src="WhatsApp Image 2025-08-03 at 22.34.22_c93e62a6.jpg" alt="کتێبخانەی ئاشتی" onerror="this.style.display='none'">
            </div>
            <div class="brand-info">
                <h1>کتێبخانەی ئاشتی</h1>
                <p>سیستەمی بەڕێوەبردن</p>
            </div>
        </div>

        <div class="decorative-border"></div>

        <h2 class="form-title">چوونەژوورەوەی ئەدمین</h2>

        <?php if($error_message): ?>
            <div class="error-message"><?php echo $error_message; ?></div>
        <?php endif; ?>

        <?php if($success_message): ?>
            <div class="success-message"><?php echo $success_message; ?></div>
        <?php endif; ?>

        <form method="POST" id="loginForm">
            <div class="form-group">
                <label class="form-label">ژمارە مۆبایل</label>
                <input 
                    type="tel" 
                    name="phone" 
                    class="form-input phone-input" 
                    placeholder="نموونە: 07501234567"
                    required
                    value="<?php echo isset($_POST['phone']) ? htmlspecialchars($_POST['phone']) : ''; ?>"
                >
            </div>

            <div class="form-group">
                <label class="form-label">پاسسۆرد</label>
                <input 
                    type="password" 
                    name="password" 
                    class="form-input" 
                    placeholder="پاسسۆردەکەت بنوسە"
                    required
                >
            </div>

            <button type="submit" name="login" class="login-btn">
                چوونەژوورەوە
            </button>
        </form>

        <div class="back-link">
            <a href="index.php">گەڕانەوە بۆ ماڵپەڕ</a>
        </div>
        <style>
        /* Developer Footer with Text Particle Effect */
        .developer-footer {
            margin-top: 2.5rem;
            padding: 2rem 0 1rem;
            border-top: 1px solid #e0e0e0;
            position: relative;
            background: linear-gradient(to bottom, transparent 0%, rgba(248,248,248,0.4) 100%);
            overflow: hidden;
            height: 120px;
        }

        .developer-credit {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 1.2rem;
            font-size: 0.95rem;
            color: #666;
            font-weight: 500;
            flex-wrap: wrap;
            font-family: 'Crimson Text', serif;
            position: relative;
            z-index: 10;
        }

        .developer-link {
            color: #2a2a2a;
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
            position: relative;
            padding: 0.5rem 1rem;
            border: 1px solid #e0e0e0;
            border-radius: 6px;
            background: #ffffff;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            font-family: 'Playfair Display', serif;
            font-style: italic;
            order: -1;
            overflow: hidden;
        }

        .developer-link:hover {
            color: #ffffff;
            background: #2a2a2a;
            border-color: #2a2a2a;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(42,42,42,0.2);
        }

        /* Text Particle Animation for Link */
        .developer-link:hover::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: transparent;
            z-index: -1;
        }

        .dev-text {
            color: #555;
            font-style: italic;
            font-size: 0.9rem;
            order: 1;
            position: relative;
            overflow: hidden;
        }

        .tech-symbol {
            width: 28px;
            height: 28px;
            background: #ffffff;
            border: 2px solid #c0c0c0;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
            transition: all 0.3s ease;
            box-shadow: 0 3px 12px rgba(0,0,0,0.08);
            order: 2;
            cursor: pointer;
            overflow: hidden;
        }

        .tech-symbol::before {
            content: '</>';
            font-size: 11px;
            font-weight: bold;
            color: #555;
            font-family: 'Courier New', monospace;
            transition: all 0.3s ease;
        }

        .tech-symbol:hover {
            transform: scale(1.1) rotate(-5deg);
            border-color: #2a2a2a;
            background: #f8f8f8;
            box-shadow: 0 6px 20px rgba(0,0,0,0.15);
        }

        .tech-symbol:hover::before {
            color: #2a2a2a;
        }

        /* Floating particles from text */
        .particle {
            position: absolute;
            pointer-events: none;
            z-index: 5;
            font-family: 'Playfair Display', serif;
            font-weight: 600;
            opacity: 0;
        }

        /* Decorative elements */
        .developer-footer::before {
            content: '';
            position: absolute;
            top: -1px;
            left: 50%;
            transform: translateX(-50%);
            width: 80px;
            height: 1px;
            background: linear-gradient(to right, transparent, #c0c0c0, transparent);
        }

        .developer-footer::after {
            content: '';
            position: absolute;
            top: -5px;
            left: 50%;
            transform: translateX(-50%);
            width: 10px;
            height: 10px;
            background: #ffffff;
            border: 2px solid #c0c0c0;
            border-radius: 50%;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        /* Mobile responsive */
        @media (max-width: 768px) {
            .developer-footer {
                height: 100px;
            }
            
            .developer-credit {
                font-size: 0.85rem;
                gap: 1rem;
            }
            
            .tech-symbol {
                width: 24px;
                height: 24px;
            }
            
            .tech-symbol::before {
                font-size: 9px;
            }
            
            .developer-link {
                padding: 0.4rem 0.8rem;
                font-size: 0.85rem;
            }
        }

        @media (max-width: 480px) {
            .developer-credit {
                flex-direction: row;
                gap: 0.8rem;
                text-align: center;
                justify-content: center;
            }
            
            .developer-footer {
                padding: 1.5rem 0 1rem;
                margin-top: 2rem;
                height: 80px;
            }
            
            .dev-text {
                font-size: 0.8rem;
            }
        }
    </style>
</head>
<body>
    <!-- Text Particle Effect Footer -->
    <div class="developer-footer" id="developerFooter">
        <div class="developer-credit">
            <a href="https://www.instagram.com/i_xoshnawm/" target="_blank" class="developer-link" id="devLink">@i_xoshnawm</a>
            <span class="dev-text" id="devText">website is developed by</span>
            <div class="tech-symbol" id="techSymbol"></div>
        </div>
    </div>

    <script>
        // Text particle effect
        function createParticle(element, char, x, y) {
            const particle = document.createElement('div');
            particle.className = 'particle';
            particle.textContent = char;
            particle.style.left = x + 'px';
            particle.style.top = y + 'px';
            particle.style.fontSize = (Math.random() * 8 + 10) + 'px';
            particle.style.color = `rgba(${Math.random() > 0.5 ? '192,192,192' : '102,102,102'}, ${Math.random() * 0.8 + 0.2})`;
            
            document.getElementById('developerFooter').appendChild(particle);
            
            // Animate particle
            const animation = particle.animate([
                {
                    opacity: 0,
                    transform: 'translate(0, 0) rotate(0deg) scale(1)'
                },
                {
                    opacity: 1,
                    transform: `translate(${(Math.random() - 0.5) * 30}px, ${-Math.random() * 20}px) rotate(${(Math.random() - 0.5) * 180}deg) scale(1.2)`
                },
                {
                    opacity: 0,
                    transform: `translate(${(Math.random() - 0.5) * 60}px, ${-Math.random() * 40 - 20}px) rotate(${(Math.random() - 0.5) * 360}deg) scale(0.8)`
                }
            ], {
                duration: 2000 + Math.random() * 1000,
                easing: 'ease-out'
            });
            
            animation.onfinish = () => {
                particle.remove();
            };
        }

        // Characters to emit
        const kurdishChars = ['ئ', 'ا', 'ش', 'ت', 'ی', 'ک', 'و', 'ر', 'د', 'ن'];
        const bookWords = ['کتێب', 'ڕۆمان', 'شعر', 'چیرۆک'];
        const techChars = ['<', '>', '/', '{', '}', '(', ')', '*'];

        // Auto-generate particles from each element
        function startAutoParticles() {
            // Kurdish letters from @i_xoshnawm
            setInterval(() => {
                const element = document.getElementById('devLink');
                const rect = element.getBoundingClientRect();
                const footerRect = document.getElementById('developerFooter').getBoundingClientRect();
                
                const char = kurdishChars[Math.floor(Math.random() * kurdishChars.length)];
                const x = rect.left - footerRect.left + Math.random() * rect.width;
                const y = rect.top - footerRect.top + Math.random() * rect.height;
                createParticle(element, char, x, y);
            }, 800);

            // Book words from "website is developed by"
            setInterval(() => {
                const element = document.getElementById('devText');
                const rect = element.getBoundingClientRect();
                const footerRect = document.getElementById('developerFooter').getBoundingClientRect();
                
                const word = bookWords[Math.floor(Math.random() * bookWords.length)];
                const x = rect.left - footerRect.left + Math.random() * rect.width;
                const y = rect.top - footerRect.top + Math.random() * rect.height;
                createParticle(element, word, x, y);
            }, 1200);

            // Tech symbols from the icon
            setInterval(() => {
                const element = document.getElementById('techSymbol');
                const rect = element.getBoundingClientRect();
                const footerRect = document.getElementById('developerFooter').getBoundingClientRect();
                
                const char = techChars[Math.floor(Math.random() * techChars.length)];
                const x = rect.left - footerRect.left + Math.random() * rect.width;
                const y = rect.top - footerRect.top + Math.random() * rect.height;
                createParticle(element, char, x, y);
            }, 600);
        }

        // Start the auto particle generation when page loads
        window.addEventListener('load', startAutoParticles);


    </script>
    </div>

    <script>
        // Form validation and loading animation
        document.getElementById('loginForm').addEventListener('submit', function(e) {
            const phone = this.phone.value.trim();
            const password = this.password.value.trim();
            
            if (!phone || !password) {
                e.preventDefault();
                alert('تکایە ژمارە مۆبایل و پاسسۆرد بنوسە');
                return;
            }
            
            // Phone number validation (Iraqi mobile format)
            const phoneRegex = /^(075|077|078|079)\d{8}$/;
            if (!phoneRegex.test(phone)) {
                e.preventDefault();
                alert('تکایە ژمارەی مۆبایلی دروست بنوسە (نموونە: 07501234567)');
                return;
            }
            
            // Add loading state
            document.body.classList.add('loading');
            this.querySelector('.login-btn').textContent = 'چوونەژوورەوە...';
        });

        // Auto-format phone number
        document.querySelector('.phone-input').addEventListener('input', function(e) {
            let value = e.target.value.replace(/\D/g, ''); // Remove non-digits
            
            // Ensure it starts with 07
            if (value.length > 0 && !value.startsWith('07')) {
                if (value.startsWith('7')) {
                    value = '0' + value;
                } else if (!value.startsWith('0')) {
                    value = '07' + value;
                }
            }
            
            // Limit to 11 digits
            if (value.length > 11) {
                value = value.substring(0, 11);
            }
            
            e.target.value = value;
        });

        // Focus management
        document.addEventListener('DOMContentLoaded', function() {
            const phoneInput = document.querySelector('.phone-input');
            if (phoneInput && !phoneInput.value) {
                phoneInput.focus();
            }
        });

        // Handle enter key
        document.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                document.getElementById('loginForm').submit();
            }
        });

        // Page load animation
        window.addEventListener('load', function() {
            document.body.style.opacity = '0';
            document.body.style.transition = 'opacity 0.5s ease-in-out';
            setTimeout(() => {
                document.body.style.opacity = '1';
            }, 100);
        });
    </script>
</body>
</html>