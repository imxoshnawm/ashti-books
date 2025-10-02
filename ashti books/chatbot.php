<?php
require_once 'config.php';

// Check if user wants to clear history
if(isset($_POST['clear_history'])) {
    session_destroy();
    session_start();
    header("Location: chatbot.php");
    exit();
}

// Initialize chat history in session
if(!isset($_SESSION['chat_history'])) {
    $_SESSION['chat_history'] = [];
}
?>
<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>چات بۆتی کتێبخانەی ئاشتی | یارمەتیدەری کتێب</title>
    <meta name="description" content="چات بۆتی کتێبخانەی ئاشتی - پرسیار بکە دەربارەی کتێب و پێشنیاری باش وەربگرە">
    
    <style>
         @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500&family=Crimson+Text:ital,wght@0,400;0,600;1,400&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        /* Desktop: Use page scrollbar instead of inner pane scrollbar */
        @media (min-width: 769px) {
            .chat-messages {
                overflow-y: visible; /* let page grow and show browser scrollbar */
                max-height: none;
            }
        }

        html { overflow-y: scroll; }

        body {
            font-family: 'Crimson Text', 'Playfair Display', serif;
            background: linear-gradient(135deg, #fafafa 0%, #f5f5f5 100%);
            color: #2a2a2a;
            direction: rtl;
            line-height: 1.7;
            font-size: 16px;
            min-height: 100dvh;
            overflow: auto; /* allow desktop/page scrolling */
            display: flex;
            flex-direction: column;
        }

        /* Header Styles (Unified) */
        .header {
            background: linear-gradient(to bottom, #f8f8f8 0%, #ffffff 100%);
            border-bottom: 3px solid #c0c0c0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            flex-shrink: 0;
            z-index: 100;
            transition: transform 0.25s ease; /* smooth hide/show on mobile */
        }
        .brand-logo {
            width: 64px;
            height: 64px;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            background: #fff;
            display: flex;
            align-items: center;
            justify-content: center;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            transition: transform 0.25s ease;
        }

        .brand-logo:hover { transform: translateY(-2px); }

        .brand-logo img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        .header-wrap {
            max-width: 1200px;
            margin: 0 auto;
            padding: 1rem 2rem;
        }

        .header-top {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 0.5rem 0 0.8rem;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 1rem;
            text-decoration: none;
            color: inherit;
        }
       
        .brand-text { display: flex; flex-direction: column; gap: 0.2rem; }

        .brand-title {
            font-family: 'Playfair Display', serif;
            font-weight: 700;
            font-size: 1.6rem;
            color: #2a2a2a;
            letter-spacing: 0.2px;
        }
        .brand-quote {
            color: #555;
            font-size: 0.95rem;
            font-weight: 500;
            font-style: italic;
            position: relative;
            padding-right: 0.8rem;
        }
        .brand-quote::before {
            content: '';
            position: absolute;
            right: 0;
            top: 0.35rem;
            width: 3px;
            height: 0.9rem;
            background: #c0c0c0;
            border-radius: 2px;
        }
        .brand-slogan {
            color: #666;
            font-size: 0.95rem;
            font-weight: 500;
            margin-top: 0.2rem;
        }
        .header-bottom { padding: 0.4rem 0 0.9rem; border-top: 1px solid #e5e5e5; }
        .nav-menu { display: flex; gap: 1rem; align-items: center; }

        .nav-link {
            color: #555;
            text-decoration: none;
            font-weight: 500;
            padding: 0.7rem 1.2rem;
            border: 1px solid transparent;
            transition: all 0.3s ease;
            font-size: 1rem;
        }

        .nav-link:hover {
            color: #2a2a2a;
            border-color: #c0c0c0;
            background: #f8f8f8;
        }

        .nav-link.active {
            background: #2a2a2a;
            color: #ffffff;
            border-color: #2a2a2a;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }

        /* Chat Layout - Full Screen */
        .chat-wrapper {
            flex: 1;
            display: flex;
            flex-direction: column;
            height: auto; /* allow natural document scroll on desktop */
            min-height: calc(100dvh - 140px); /* fill viewport minus header on larger screens */
            overflow: hidden;
        }

        .chat-header {
            background: #ffffff;
            border-bottom: 1px solid #e5e5e5;
            padding: 1.5rem;
            text-align: center;
            box-shadow: 0 1px 4px rgba(0,0,0,0.05);
            flex-shrink: 0;
        }

        .chat-title {
            font-family: 'Playfair Display', serif;
            font-size: 2rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 0.5rem;
        }

        .chat-subtitle {
            color: #666;
            font-size: 1.1rem;
            font-style: italic;
        }

        .chat-messages {
            flex: 1;
            background: #ffffff;
            padding: 1.5rem;
            overflow-y: auto;
            scroll-behavior: smooth;
        }

        .message {
            margin-bottom: 1.5rem;
            display: flex;
            gap: 1rem;
            animation: fadeInUp 0.3s ease-out;
            max-width: 100%;
        }

        .message.user {
            flex-direction: row-reverse;
        }

        .message-avatar {
            width: 45px;
            height: 45px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            font-size: 1.2rem;
            flex-shrink: 0;
        }

        .message.user .message-avatar {
            background: #2a2a2a;
            color: white;
        }

        .message.bot .message-avatar {
            background: #c0c0c0;
            color: white;
        }

        .message-content {
            flex: 1;
            min-width: 0;
        }

        .message-bubble {
            padding: 1rem 1.5rem;
            border-radius: 18px;
            box-shadow: 0 1px 4px rgba(0,0,0,0.08);
            line-height: 1.6;
            word-wrap: break-word;
            overflow-wrap: break-word;
            font-size: 1rem;
        }

        .message.user .message-bubble {
            background: #2a2a2a;
            color: white;
            border-bottom-right-radius: 4px;
        }

        .message.bot .message-bubble {
            background: #f8f8f8;
            color: #2a2a2a;
            border: 1px solid #e5e5e5;
            border-bottom-left-radius: 4px;
        }

        .message-time {
            font-size: 0.85rem;
            color: #999;
            margin-top: 0.5rem;
            text-align: center;
        }

        .chat-input-container {
            background: #ffffff;
            border-top: 1px solid #e5e5e5;
            padding: 1.5rem;
            box-shadow: 0 -1px 4px rgba(0,0,0,0.05);
            flex-shrink: 0;
            will-change: transform; /* smoother translate on mobile */
        }

        .quick-suggestions {
            display: flex;
            gap: 0.8rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
            justify-content: center;
        }

        .suggestion-btn {
            padding: 0.6rem 1.2rem;
            background: #f0f0f0;
            border: 1px solid #e0e0e0;
            border-radius: 18px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
            color: #555;
            white-space: nowrap;
        }

        .suggestion-btn:hover {
            background: #e0e0e0;
            color: #2a2a2a;
        }

        .clear-chat-btn {
            background: #f8f8f8;
            color: #666;
            border: 1px solid #e0e0e0;
            padding: 0.6rem 1.2rem;
            border-radius: 18px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .clear-chat-btn:hover {
            background: #e0e0e0;
            color: #2a2a2a;
        }

        .chat-input-form {
            display: flex;
            gap: 1rem;
            align-items: flex-end;
        }

        .chat-input {
            flex: 1;
            padding: 1rem 1.2rem;
            border: 1px solid #e0e0e0;
            border-radius: 20px;
            font-size: 1rem;
            resize: none;
            min-height: 50px;
            max-height: 120px;
            font-family: inherit;
            transition: all 0.3s ease;
            background: #fafafa;
        }

        .chat-input:focus {
            outline: none;
            border-color: #c0c0c0;
            background: #ffffff;
            box-shadow: 0 0 0 2px rgba(192,192,192,0.1);
        }

        .send-button {
            padding: 1rem 2rem;
            background: #2a2a2a;
            color: white;
            border: none;
            border-radius: 20px;
            cursor: pointer;
            font-size: 1rem;
            font-weight: 600;
            transition: all 0.3s ease;
            white-space: nowrap;
            min-height: 50px;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-shrink: 0;
            min-width: 120px;
        }

        .send-button:hover:not(:disabled) {
            background: #404040;
        }

        .send-button:disabled {
            background: #ccc;
            cursor: not-allowed;
        }

        .loading {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            color: #666;
            font-style: italic;
        }

        .loading-dots {
            display: inline-flex;
            gap: 2px;
        }

        .loading-dots span {
            width: 4px;
            height: 4px;
            background: #666;
            border-radius: 50%;
            animation: bounce 1.4s ease-in-out infinite both;
        }

        .loading-dots span:nth-child(1) { animation-delay: -0.32s; }
        .loading-dots span:nth-child(2) { animation-delay: -0.16s; }

        @keyframes bounce {
            0%, 80%, 100% {
                transform: scale(0);
            } 40% {
                transform: scale(1);
            }
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .empty-state {
            text-align: center;
            padding: 3rem 1rem;
            color: #666;
        }

        .empty-state-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        .empty-state h3 {
            font-size: 1.5rem;
            margin-bottom: 0.5rem;
        }

        .empty-state p {
            font-size: 1rem;
        }

        .book-recommendation {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }

        .book-title {
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 0.5rem;
            font-size: 1.1rem;
        }

        .book-author {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 0.3rem;
            font-style: italic;
        }

        .book-price {
            color: #2a2a2a;
            font-weight: 600;
            margin-top: 0.5rem;
            font-size: 1rem;
        }

        /* Mobile Optimizations - چارەسەری گرنگ بۆ مۆبایل */
        @media (max-width: 768px) {
            body { overflow: auto; /* allow page to scroll when keyboard opens */ }
            .header { padding: 1.5rem 0; }
            .header-top { flex-direction: column; gap: 1rem; text-align: center; }
            .nav-menu { flex-wrap: wrap; justify-content: center; }

            /* کاتێک نوسین دەکەیت، هێدەر بشارەوە بۆ ئەوەی شوێن بپارێزرێت */
            body.typing .header {
                position: fixed;
                top: 0; left: 0; right: 0;
                transform: translateY(-100%);
            }

            body.typing .chat-wrapper {
                height: 100dvh; /* پڕتر بکە لەسەری دانانی هێدەر */
            }

            .brand-info h1 {
                font-size: 1.8rem;
            }

            .brand-info p {
                font-size: 0.9rem;
            }
            
            .chat-wrapper {
                height: calc(100dvh - 180px);
            }
            
            .chat-header {
                padding: 1rem;
            }
            
            .chat-title {
                font-size: 1.6rem;
            }

            .chat-subtitle {
                font-size: 1rem;
            }
            
            .chat-messages {
                padding: 1rem;
            }

            .message {
                gap: 0.8rem;
                margin-bottom: 1.2rem;
            }

            .message-avatar {
                width: 40px;
                height: 40px;
                font-size: 1rem;
            }
            
            .message-bubble {
                padding: 1rem;
                border-radius: 16px;
                font-size: 1rem;
            }

            .message-time {
                font-size: 0.8rem;
            }
            
            .chat-input-container {
                padding: 1rem;
                /* چارەسەری گرنگ: هاردکۆد کردنی بەرزی */
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                background: #ffffff;
                border-top: 1px solid #e5e5e5;
                z-index: 10;
                box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
            }

            /* بۆ ئەوەی پەیامەکان شوێنی تەواو بگرنەوە */
            .chat-messages {
                padding-bottom: 120px; /* شوێنی container-ی input */
                -webkit-overflow-scrolling: touch;
            }

            .quick-suggestions {
                margin-bottom: 0.8rem;
                gap: 0.6rem;
            }

            .suggestion-btn, .clear-chat-btn {
                padding: 0.6rem 0.8rem;
                font-size: 0.85rem;
                border-radius: 16px;
            }
            
            /* چارەسەری گرنگ بۆ input form */
            .chat-input-form {
                display: flex !important;
                gap: 0.8rem;
                align-items: stretch;
                width: 100%;
            }

            .chat-input {
                flex: 1 !important;
                min-width: 0 !important;
                padding: 0.8rem 1rem;
                font-size: 16px; /* بۆ iOS zoom prevention */
                border-radius: 18px;
                min-height: 44px; /* iOS standard */
                max-height: 88px;
            }

            /* چارەسەری گرنگترین - دووگمەی ناردن */
            .send-button {
                flex-shrink: 0 !important;
                min-width: 80px !important;
                max-width: 80px !important;
                padding: 0.8rem 0.5rem !important;
                font-size: 0.9rem !important;
                border-radius: 18px !important;
                min-height: 44px !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                background: #2a2a2a !important;
                color: white !important;
                border: none !important;
                font-weight: 600 !important;
                white-space: nowrap !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
            }

            .empty-state {
                padding: 2rem 1rem;
            }

            .empty-state-icon {
                font-size: 2.5rem;
            }

            .empty-state h3 {
                font-size: 1.3rem;
            }

            .book-title {
                font-size: 1rem;
            }

            .book-author {
                font-size: 0.85rem;
            }

            .book-price {
                font-size: 0.95rem;
            }
        }

        /* Very small screens - شاشەی زۆر بچووک */
        @media (max-width: 480px) {
            .header-wrap { padding: 1rem; }

            .brand-info h1 {
                font-size: 1.5rem;
            }

            .nav-menu {
                gap: 0.8rem;
            }

            .nav-link {
                padding: 0.5rem 0.8rem;
                font-size: 0.9rem;
            }

            .quick-suggestions {
                flex-direction: row;
                flex-wrap: wrap;
                gap: 0.5rem;
            }

            .suggestion-btn, .clear-chat-btn {
                flex: 1;
                min-width: 120px;
                text-align: center;
                padding: 0.7rem 0.8rem;
                font-size: 0.8rem;
            }

            /* چارەسەری سەرەکی بۆ مۆبایلی بچووک */
            .chat-input-form {
                display: flex !important;
                gap: 0.6rem !important;
                align-items: stretch !important;
                width: 100% !important;
                box-sizing: border-box !important;
            }

            .chat-input {
                flex: 1 !important;
                min-width: 0 !important;
                width: calc(100% - 86px) !important; /* 80px دووگمە + 6px gap */
                min-height: 42px;
                padding: 0.7rem 0.8rem;
                border-radius: 16px;
                font-size: 16px;
            }

            /* دووگمەی ناردن - چارەسەری تەواو */
            .send-button {
                flex-shrink: 0 !important;
                flex-grow: 0 !important;
                width: 80px !important;
                min-width: 80px !important;
                max-width: 80px !important;
                height: 42px !important;
                min-height: 42px !important;
                max-height: 42px !important;
                padding: 0 !important;
                margin: 0 !important;
                border: none !important;
                border-radius: 16px !important;
                background: #2a2a2a !important;
                color: white !important;
                font-size: 0.85rem !important;
                font-weight: 600 !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                white-space: nowrap !important;
                overflow: hidden !important;
                text-overflow: ellipsis !important;
                cursor: pointer !important;
            }

            .send-button:hover:not(:disabled) {
                background: #404040 !important;
            }

            .send-button:disabled {
                background: #ccc !important;
            }

            .chat-input-container {
                padding: 0.8rem;
                position: fixed;
                bottom: 0;
                left: 0;
                right: 0;
                background: #ffffff;
                border-top: 1px solid #e5e5e5;
                z-index: 10;
                box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
            }

            .chat-messages {
                padding-bottom: 130px; /* شوێنی زیاتر بۆ container */
                -webkit-overflow-scrolling: touch;
            }

            /* هەمان چارەسەر لە سکرینی زۆر بچووک */
            body.typing .header {
                position: fixed;
                top: 0; left: 0; right: 0;
                transform: translateY(-100%);
            }

            body.typing .chat-wrapper {
                height: 100dvh;
            }
        }

        /* Extra small screens */
        @media (max-width: 360px) {
            .send-button {
                width: 70px !important;
                min-width: 70px !important;
                max-width: 70px !important;
                font-size: 0.8rem !important;
            }

            .chat-input {
                width: calc(100% - 76px) !important; /* 70px دووگمە + 6px gap */
            }
        }

        /* Scrollbar styling for webkit browsers (messages pane) */
        .chat-messages::-webkit-scrollbar {
            width: 8px;
        }

        .chat-messages::-webkit-scrollbar-track {
            background: #f1f1f1;
        }

        .chat-messages::-webkit-scrollbar-thumb {
            background: #c0c0c0;
            border-radius: 4px;
        }

        .chat-messages::-webkit-scrollbar-thumb:hover {
            background: #a0a0a0;
        }

        /* Page scrollbar styling (webkit) */
        body::-webkit-scrollbar {
            width: 12px;
        }
        body::-webkit-scrollbar-track {
            background: #efefef;
        }
        body::-webkit-scrollbar-thumb {
            background: #b5b5b5;
            border-radius: 6px;
            border: 3px solid #efefef;
        }
        body::-webkit-scrollbar-thumb:hover {
            background: #969696;
        }

        /* Safari iOS specific fixes */
        @supports (-webkit-touch-callout: none) {
            .chat-input-container {
                padding-bottom: calc(0.8rem + env(safe-area-inset-bottom, 0px));
            }
        }
    </style>
</head>
<body>
    <!-- Header (Unified) -->
    <header class="header">
        <div class="header-wrap">
            <div class="header-top">
                <a href="index.php" class="brand" aria-label="گەڕانەوە بۆ سەرەکی">
                    <div class="brand-logo"><img src="WhatsApp Image 2025-10-02 at 13.33.18_2208eaf2.jpg" alt="کتێبخانەی ئاشتی"></div>
                    <div class="brand-text">
                        <h1 class="brand-title">کتێبخانەی ئاشتی</h1>
                        <div class="brand-slogan">حاجی قادری کۆیی: بێ کتێب و زانست نەتەوە لە تاریکیدا دەمێنێتەوە</div>
                        <div class="brand-slogan">کتێبخانەی ئاشتی: لە ئێوە گوڵ چاندن لە ئێمە ئاو پرژێن</div>
                    </div>
                </a>
            </div>
            <div class="header-bottom">
                <nav class="nav-menu">
                    <a href="index.php" class="nav-link">سەرەکی</a>
                    <a href="allbooks.php" class="nav-link">هەموو کتێبەکان</a>
                    <a href="chatbot.php" class="nav-link active">چات بۆت</a>
                </nav>
            </div>
        </div>
    </header>

    <!-- Chat Wrapper - Full Screen -->
    <div class="chat-wrapper">
        <div class="chat-header">
            <h1 class="chat-title">چات بۆتی کتێبخانەی ئاشتی</h1>
        </div>

        <div class="chat-messages" id="chatMessages">
        <?php if(empty($_SESSION['chat_history'])): ?>
            <div class="empty-state">
                <div class="empty-state-icon">💬</div>
                <h3>بەخێربێیت بۆ یارمەتیدەری کتێب!</h3>
                <p>پرسیار بکە دەربارەی کتێب و پێشنیار</p>
            </div>
        <?php else: ?>
                <?php foreach($_SESSION['chat_history'] as $message): ?>
                <div class="message <?php echo $message['type']; ?>">
                    <div class="message-avatar">
                        <?php echo $message['type'] == 'user' ? 'ت' : '🤖'; ?>
                    </div>
                    <div class="message-content">
                        <div class="message-bubble">
                            <?php echo nl2br(htmlspecialchars($message['content'])); ?>
                        </div>
                        <div class="message-time"><?php echo $message['time']; ?></div>
                    </div>
                </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="chat-input-container">
             <div class="quick-suggestions">
                <form method="post" style="display: inline;">
                    <button type="submit" name="clear_history" class="clear-chat-btn">پاککردنەوەی چات</button>
                </form>
            </div>
            <form class="chat-input-form" onsubmit="sendMessage(event)">
                <textarea 
                    class="chat-input" 
                    id="messageInput"
                    placeholder="پرسیارەکەت لێرە بنووسە..."
                    rows="1"></textarea>
                <button type="submit" class="send-button" id="sendButton">
                    ناردن
                </button>
            </form>
            
            
            
        </div>
    </div>

    <script>
        // --- Safe escaping and URL auto-linking helpers ---
        function escapeHtml(str) {
            return String(str)
                .replace(/&/g, '&amp;')
                .replace(/</g, '&lt;')
                .replace(/>/g, '&gt;')
                .replace(/"/g, '&quot;')
                .replace(/'/g, '&#039;');
        }

        function linkifyText(text) {
            // Escape first for safety
            let safe = escapeHtml(text);
            // Convert newlines to <br>
            safe = safe.replace(/\n/g, '<br>');
            // Linkify URLs (http/https and www.)
            const urlRegex = /\b((?:https?:\/\/)[^\s<]+|(?:www\.)[^\s<]+)\b/gi;
            return safe.replace(urlRegex, (match) => {
                let url = match;
                if (/^www\./i.test(url)) {
                    url = 'http://' + url; // add protocol for bare www links
                }
                return `<a href="${url}" target="_blank" rel="noopener noreferrer nofollow">${match}</a>`;
            });
        }

        function linkifyAllBubbles() {
            document.querySelectorAll('.message-bubble').forEach(el => {
                // Use innerText to get plain text, then linkify
                const txt = el.innerText || '';
                el.innerHTML = linkifyText(txt);
            });
        }
        // Auto-resize textarea
        const messageInput = document.getElementById('messageInput');
        messageInput.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 120) + 'px';
        });

        // Send message function
        async function sendMessage(event) {
            event.preventDefault();
            
            const input = document.getElementById('messageInput');
            const sendButton = document.getElementById('sendButton');
            const message = input.value.trim();
            
            if (!message) return;
            
            // Add user message to chat
            addMessageToChat('user', message);
            
            // Clear input and disable button
            input.value = '';
            input.style.height = 'auto';
            sendButton.disabled = true;
            sendButton.textContent = 'ناردن...';
            
            // Show loading indicator
            addLoadingMessage();
            
            try {
                // Send to API
                const response = await fetch('chatbot_api.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ message: message })
                });
                
                const data = await response.json();
                
                // Remove loading message
                removeLoadingMessage();
                
                if (data.success) {
                    addMessageToChat('bot', data.response);
                } else {
                    addMessageToChat('bot', 'ببورە، هەڵەیەک ڕوویدا. دووبارە هەوڵبدەرەوە.');
                }
                
            } catch (error) {
                removeLoadingMessage();
                addMessageToChat('bot', 'ببورە، پەیوەندی بە ئینتەرنێتەوە کێشەی هەیە.');
            }
            
            // Re-enable button
            sendButton.disabled = false;
            sendButton.textContent = 'ناردن';
            input.focus();
        }

        // Add message to chat
        function addMessageToChat(type, message) {
            const chatMessages = document.getElementById('chatMessages');
            const emptyState = chatMessages.querySelector('.empty-state');
            
            if (emptyState) {
                emptyState.remove();
            }
            
            const messageDiv = document.createElement('div');
            messageDiv.className = `message ${type}`;
            
            const currentTime = new Date().toLocaleTimeString('ku', { 
                hour: '2-digit', 
                minute: '2-digit' 
            });
            
            messageDiv.innerHTML = `
                <div class="message-avatar">
                    ${type === 'user' ? 'ت' : '🤖'}
                </div>
                <div class="message-content">
                    <div class="message-bubble">${linkifyText(message)}</div>
                    <div class="message-time">${currentTime}</div>
                </div>
            `;
            
            chatMessages.appendChild(messageDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        // Add loading message
        function addLoadingMessage() {
            const chatMessages = document.getElementById('chatMessages');
            const loadingDiv = document.createElement('div');
            loadingDiv.className = 'message bot loading-message';
            loadingDiv.innerHTML = `
                <div class="message-avatar">🤖</div>
                <div class="message-content">
                    <div class="message-bubble loading">
                        <span>چاوەڕوانبە...</span>
                        <div class="loading-dots">
                            <span></span>
                            <span></span>
                            <span></span>
                        </div>
                    </div>
                </div>
            `;
            
            chatMessages.appendChild(loadingDiv);
            chatMessages.scrollTop = chatMessages.scrollHeight;
        }

        // Remove loading message
        function removeLoadingMessage() {
            const loadingMessage = document.querySelector('.loading-message');
            if (loadingMessage) {
                loadingMessage.remove();
            }
        }

        // Handle Enter key
        messageInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage(e);
            }
        });

        // Auto-scroll to bottom on page load
        window.addEventListener('load', function() {
            const chatMessages = document.getElementById('chatMessages');
            chatMessages.scrollTop = chatMessages.scrollHeight;
            // Make any server-rendered message bubbles clickable
            linkifyAllBubbles();
        });

        // Keep input visible above mobile keyboard using VisualViewport
        (function() {
            const chatInputContainer = document.querySelector('.chat-input-container');
            const chatMessagesEl = document.getElementById('chatMessages');

            function getContainerHeight() {
                const styles = window.getComputedStyle(chatInputContainer);
                const padding = parseFloat(styles.paddingTop) + parseFloat(styles.paddingBottom);
                return chatInputContainer.offsetHeight + padding;
            }

            function updateViewportOffset() {
                if (!chatInputContainer || !chatMessagesEl) return;
                // Default reset
                let keyboardOffset = 0;
                if (window.visualViewport) {
                    const vv = window.visualViewport;
                    // Amount of obscured area at bottom
                    const bottomObscured = (window.innerHeight - (vv.height + vv.offsetTop));
                    keyboardOffset = Math.max(0, Math.round(bottomObscured));
                }
                chatInputContainer.style.transform = keyboardOffset ? `translateY(-${keyboardOffset}px)` : '';
                // Ensure messages area has enough padding so last message not hidden
                const basePad = window.matchMedia('(max-width: 480px)').matches ? 130 : 120;
                chatMessagesEl.style.paddingBottom = (basePad + keyboardOffset) + 'px';
            }

            // iOS/Android: update when viewport changes
            if (window.visualViewport) {
                window.visualViewport.addEventListener('resize', updateViewportOffset);
                window.visualViewport.addEventListener('scroll', updateViewportOffset);
            }
            window.addEventListener('orientationchange', function() {
                setTimeout(updateViewportOffset, 300);
            });

            // Update on input focus/blur
            messageInput.addEventListener('focus', function() {
                setTimeout(function() {
                    document.body.classList.add('typing');
                    updateViewportOffset();
                    // Scroll to bottom so input stays visible
                    chatMessagesEl.scrollTop = chatMessagesEl.scrollHeight;
                }, 100);
            });
            messageInput.addEventListener('blur', function() {
                // Reset on blur
                chatInputContainer.style.transform = '';
                const basePad = window.matchMedia('(max-width: 480px)').matches ? 130 : 120;
                chatMessagesEl.style.paddingBottom = basePad + 'px';
                document.body.classList.remove('typing');
            });

            // Initial call
            updateViewportOffset();
        })();

        // Prevent zoom on input focus for iOS Safari
        if (/iPad|iPhone|iPod/.test(navigator.userAgent)) {
            messageInput.addEventListener('focus', function() {
                this.style.fontSize = '16px';
            });
        }

        // Prevent form submission on mobile keyboard "Done" button double press
        let isSubmitting = false;
        document.querySelector('.chat-input-form').addEventListener('submit', function(e) {
            if (isSubmitting) {
                e.preventDefault();
                return false;
            }
            isSubmitting = true;
            setTimeout(() => {
                isSubmitting = false;
            }, 1000);
        });
    </script>
</body>
</html>