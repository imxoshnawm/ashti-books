<?php
require_once 'config.php';

// پشتڕاستکردنەوەی سیشنی ئەدمین
check_admin_session();

$admin_info = getAdminInfo();

// پاگینەیشن
$page = isset($_GET['page']) ? (int)$_GET['page'] : 1;
$per_page = 20;
$offset = ($page - 1) * $per_page;

// فیلتەرەکان
$search_query = isset($_GET['search']) ? clean_input($_GET['search']) : '';
$date_from = isset($_GET['date_from']) ? clean_input($_GET['date_from']) : '';
$date_to = isset($_GET['date_to']) ? clean_input($_GET['date_to']) : '';

// Query بنەرەتی
$where_conditions = [];
$params = [];

if (!empty($search_query)) {
    $where_conditions[] = "(user_message LIKE ? OR ai_response LIKE ?)";
    $params[] = "%$search_query%";
    $params[] = "%$search_query%";
}

if (!empty($date_from)) {
    $where_conditions[] = "DATE(created_date) >= ?";
    $params[] = $date_from;
}

if (!empty($date_to)) {
    $where_conditions[] = "DATE(created_date) <= ?";
    $params[] = $date_to;
}

$where_clause = !empty($where_conditions) ? "WHERE " . implode(" AND ", $where_conditions) : "";

// گشتی ژمارەی چاتەکان
$count_sql = "SELECT COUNT(*) as total FROM chat_sessions $where_clause";
$count_stmt = $conn->prepare($count_sql);
$count_stmt->execute($params);
$total_records = $count_stmt->fetch()['total'];

// چاتەکان بە پەڕەی ئێستا
$sql = "SELECT * FROM chat_sessions $where_clause ORDER BY created_date DESC LIMIT $per_page OFFSET $offset";
$stmt = $conn->prepare($sql);
$stmt->execute($params);
$chats = $stmt->fetchAll(PDO::FETCH_ASSOC);

// حیسابی پەڕەکان
$total_pages = ceil($total_records / $per_page);

// سڕینەوەی چات (ئەگەر داواکراوە)
if (isset($_POST['delete_chat']) && isset($_POST['chat_id'])) {
    $chat_id = (int)$_POST['chat_id'];
    $delete_sql = "DELETE FROM chat_sessions WHERE chat_id = ?";
    $delete_stmt = $conn->prepare($delete_sql);
    $delete_stmt->execute([$chat_id]);
    
    header("Location: admin_chat_history.php");
    exit();
}

// پاککردنەوەی گشتی
if (isset($_POST['clear_all_chats'])) {
    $clear_sql = "DELETE FROM chat_sessions";
    $clear_stmt = $conn->prepare($clear_sql);
    $clear_stmt->execute();
    
    header("Location: admin_chat_history.php");
    exit();
}
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>هیستۆری چات بۆت - کتێبخانەی ئاشتی</title>
    <meta name="description" content="بەڕێوەبردنی هیستۆری چاتەکانی یارمەتیدەری کتێب">
    
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,500;0,600;0,700;1,400;1,500&family=Crimson+Text:ital,wght@0,400;0,600;1,400&display=swap');

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Crimson Text', 'Playfair Display', serif;
            background: #fafafa;
            color: #2a2a2a;
            direction: rtl;
            line-height: 1.7;
            font-size: 16px;
        }

        /* Header Styles */
        .header {
            background: linear-gradient(to bottom, #f8f8f8 0%, #ffffff 100%);
            border-bottom: 3px solid #c0c0c0;
            padding: 2rem 0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
        }

        .header-content {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header h1 {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-weight: 700;
            color: #2a2a2a;
            font-style: italic;
        }

        .admin-info {
            display: flex;
            align-items: center;
            gap: 1.5rem;
            font-size: 1rem;
            color: #666;
        }

        .logout-btn {
            background: #2a2a2a;
            color: #ffffff;
            padding: 0.7rem 1.2rem;
            border: 1px solid #2a2a2a;
            text-decoration: none;
            font-weight: 500;
            font-family: inherit;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            font-size: 0.9rem;
            border-radius: 4px;
        }

        .logout-btn:hover {
            background: #ffffff;
            color: #2a2a2a;
            border-color: #c0c0c0;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(192, 192, 192, 0.3);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        /* Navigation Links */
        .nav-links {
            display: flex;
            gap: 1rem;
            margin-bottom: 3rem;
            flex-wrap: wrap;
        }

        .nav-link {
            padding: 0.7rem 1.2rem;
            background: #ffffff;
            color: #555;
            text-decoration: none;
            font-weight: 500;
            border: 1px solid #e0e0e0;
            transition: all 0.3s ease;
            font-size: 1rem;
            border-radius: 4px;
        }

        .nav-link:hover, .nav-link.active {
            color: #2a2a2a;
            border-color: #c0c0c0;
            background: #f8f8f8;
            transform: translateY(-2px);
        }

        /* Page Header */
        .page-header {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            text-align: center;
        }

        .page-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 0.5rem;
        }

        .page-subtitle {
            color: #666;
            font-size: 1rem;
            font-style: italic;
        }

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }

        .stat-card {
            background: #ffffff;
            padding: 2rem;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            text-align: center;
            border-top: 3px solid #c0c0c0;
            border-radius: 8px;
        }

        .stat-number {
            font-family: 'Playfair Display', serif;
            font-size: 2.5rem;
            font-weight: 700;
            color: #2a2a2a;
            margin-bottom: 0.5rem;
        }

        .stat-label {
            color: #666;
            font-size: 1.1rem;
            font-weight: 500;
        }

        /* Filters Section */
        .filters-section {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
        }

        .section-title {
            font-family: 'Playfair Display', serif;
            font-size: 1.5rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 1.5rem;
            text-align: center;
            position: relative;
            display: inline-block;
            width: 100%;
        }

        .section-title::after {
            content: '';
            position: absolute;
            bottom: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 1px;
            background: #c0c0c0;
        }

        .filters-form {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            align-items: end;
        }

        .filter-group {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .filter-label {
            font-weight: 600;
            color: #2a2a2a;
            font-size: 1rem;
        }

        .filter-input {
            width: 100%;
            padding: 0.8rem 1rem;
            border: 1px solid #e5e5e5;
            border-radius: 4px;
            font-size: 1rem;
            font-family: inherit;
            transition: all 0.3s ease;
            direction: rtl;
            background: #fafafa;
        }

        .filter-input:focus {
            outline: none;
            border-color: #c0c0c0;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(192, 192, 192, 0.1);
        }

        .filter-btn {
            width: 100%;
            padding: 0.8rem;
            background: #2a2a2a;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            font-size: 1rem;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .filter-btn:hover {
            background: #c0c0c0;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(192, 192, 192, 0.3);
        }

        .clear-btn {
            background: #666;
        }

        .clear-btn:hover {
            background: #888;
        }

        /* Chat List */
        .chat-list {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            margin-bottom: 2rem;
        }

        .chat-item {
            border-bottom: 1px solid #f0f0f0;
            padding: 2rem;
            transition: all 0.3s ease;
        }

        .chat-item:last-child {
            border-bottom: none;
        }

        .chat-item:hover {
            background: #fafafa;
        }

        .chat-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1.5rem;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .chat-date {
            color: #666;
            font-size: 0.9rem;
            background: #f8f8f8;
            padding: 0.5rem 1rem;
            border-radius: 15px;
            border: 1px solid #e5e5e5;
            font-weight: 500;
        }

        .chat-session {
            color: #888;
            font-size: 0.85rem;
            font-family: 'Courier New', monospace;
            background: #f0f0f0;
            padding: 0.3rem 0.8rem;
            border-radius: 12px;
        }

        .delete-btn {
            background: #e53e3e;
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.85rem;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .delete-btn:hover {
            background: #c53030;
            transform: translateY(-1px);
        }

        .chat-messages {
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .message-pair {
            display: flex;
            flex-direction: column;
            gap: 0.8rem;
        }

        .user-message, .bot-message {
            padding: 1.5rem;
            border-radius: 12px;
            max-width: 80%;
            word-wrap: break-word;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }

        .user-message {
            align-self: flex-end;
            background: #2a2a2a;
            color: white;
            border-bottom-right-radius: 4px;
        }

        .bot-message {
            align-self: flex-start;
            background: #f8f8f8;
            border: 1px solid #e5e5e5;
            color: #2a2a2a;
            border-bottom-left-radius: 4px;
        }

        .message-label {
            font-size: 0.85rem;
            color: #888;
            margin-bottom: 0.5rem;
            font-weight: 600;
        }

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 4rem 2rem;
            color: #666;
        }

        .empty-icon {
            font-size: 4rem;
            margin-bottom: 1rem;
            opacity: 0.5;
        }

        /* Pagination */
        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 0.5rem;
            margin: 2rem 0;
        }

        .page-btn {
            padding: 0.8rem 1.2rem;
            border: 1px solid #e0e0e0;
            background: #ffffff;
            color: #2a2a2a;
            text-decoration: none;
            border-radius: 4px;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .page-btn:hover, .page-btn.active {
            background: #2a2a2a;
            color: white;
            border-color: #2a2a2a;
            transform: translateY(-1px);
        }

        .page-btn.disabled {
            opacity: 0.5;
            cursor: not-allowed;
            pointer-events: none;
        }

        /* Action Buttons */
        .action-section {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin: 2rem 0;
        }

        .danger-btn {
            background: #e53e3e;
            color: white;
            padding: 1rem 2rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s ease;
            font-family: inherit;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .danger-btn:hover {
            background: #c53030;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(229, 62, 62, 0.3);
        }

        /* Additional info styles */
        .additional-info {
            margin-top: 1.5rem;
            padding: 1rem;
            background: #f0f8ff;
            border: 1px solid #e0f2fe;
            border-radius: 6px;
            font-size: 0.9rem;
            color: #666;
            border-left: 4px solid #3b82f6;
        }

        .ip-info {
            margin-top: 0.8rem;
            font-size: 0.8rem;
            color: #999;
            font-family: 'Courier New', monospace;
            background: #f5f5f5;
            padding: 0.5rem;
            border-radius: 4px;
            display: inline-block;
        }

        /* Decorative Elements */
        .decorative-border {
            width: 120px;
            height: 2px;
            background: #c0c0c0;
            margin: 2rem auto;
            position: relative;
        }

        .decorative-border::before,
        .decorative-border::after {
            content: '';
            position: absolute;
            width: 8px;
            height: 8px;
            background: #c0c0c0;
            border-radius: 50%;
            top: -3px;
        }

        .decorative-border::before {
            left: -4px;
        }

        .decorative-border::after {
            right: -4px;
        }

        /* Mobile Responsive */
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .admin-info {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            .nav-links {
                justify-content: center;
            }
            
            .container {
                padding: 1rem;
            }
            
            .filters-form {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .chat-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .user-message, .bot-message {
                max-width: 95%;
            }
            
            .page-title {
                font-size: 1.8rem;
            }
            
            .chat-item {
                padding: 1.5rem;
            }
        }

        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .page-header {
                padding: 1.5rem;
            }
            
            .page-title {
                font-size: 1.5rem;
            }
            
            .stat-number {
                font-size: 2rem;
            }
        }

        /* Animation */
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .stat-card,
        .filters-section,
        .chat-list {
            animation: fadeInUp 0.6s ease-out;
        }

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

        /* Decorative elements for footer */
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
    <!-- Header -->
    <div class="header">
        <div class="header-content">
            <h1>هیستۆری چات بۆت</h1>
            <div class="admin-info">
                <span>بەخێرهاتیت، <?php echo htmlspecialchars($admin_info['name']); ?></span>
                <a href="logout.php" class="logout-btn">دەرچوون</a>
            </div>
        </div>
    </div>

    <div class="container">
        <!-- Navigation Links -->
        <div class="nav-links">
            <a href="admin_dashboard.php" class="nav-link">داشبۆرد</a>
            <a href="manage_books.php" class="nav-link">بەڕێوەبردنی کتێبەکان</a>
            <a href="manage_categories.php" class="nav-link">بەڕێوەبردنی بەشەکان</a>
            <a href="admin_chat_history.php" class="nav-link active">هیستۆری چات</a>
            <a href="chatbot.php" class="nav-link">چات بۆت</a>
        </div>

        <!-- Page Header -->
        <div class="page-header">
            <h1 class="page-title">هیستۆری چات بۆت</h1>
            <p class="page-subtitle">بەڕێوەبردن و چاودێری چاتەکانی یارمەتیدەری کتێب</p>
        </div>

        <!-- Stats Section -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><?php echo number_format($total_records); ?></div>
                <div class="stat-label">کۆی گشتی چاتەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $page; ?></div>
                <div class="stat-label">پەڕەی ئێستا</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $total_pages; ?></div>
                <div class="stat-label">کۆی پەڕەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $per_page; ?></div>
                <div class="stat-label">چات بۆ هەر پەڕە</div>
            </div>
        </div>

        <div class="decorative-border"></div>

        <!-- Filters Section -->
        <div class="filters-section">
            <h2 class="section-title">گەڕان و فیلتەرکردن</h2>
            <form method="GET" class="filters-form">
                <div class="filter-group">
                    <button type="submit" class="filter-btn">گەڕان</button>
                </div>
                
                <div class="filter-group">
                    <a href="admin_chat_history.php" class="filter-btn clear-btn">پاککردنەوە</a>
                </div>
            </form>
        </div>

        <!-- Chat List -->
        <div class="chat-list">
            <?php if (empty($chats)): ?>
                <div class="empty-state">
                    <div class="empty-icon">💬</div>
                    <h3>چاتێک نەدۆزراوە</h3>
                    <p>هیچ چاتێک بەپێی ئەم فیلتەرانە نەدۆزراوە</p>
                </div>
            <?php else: ?>
                <?php foreach ($chats as $chat): ?>
                    <div class="chat-item">
                        <div class="chat-header">
                            <div class="chat-date">
                                <?php echo date('Y-m-d H:i', strtotime($chat['created_date'])); ?>
                            </div>
                            <div class="chat-session">
                                Session: <?php echo htmlspecialchars(substr($chat['session_id'], -8)); ?>
                            </div>
                            <form method="POST" style="display: inline;" 
                                  onsubmit="return confirm('دڵنیایی لە سڕینەوەی ئەم چاتە؟')">
                                <input type="hidden" name="chat_id" value="<?php echo $chat['chat_id']; ?>">
                                <button type="submit" name="delete_chat" class="delete-btn">سڕینەوە</button>
                            </form>
                        </div>
                        
                        <div class="chat-messages">
                            <div class="message-pair">
                                <div class="message-label">بەکارهێنەر:</div>
                                <div class="user-message">
                                    <?php echo nl2br(htmlspecialchars($chat['user_message'])); ?>
                                </div>
                            </div>
                            
                            <div class="message-pair">
                                <div class="message-label">چات بۆت:</div>
                                <div class="bot-message">
                                    <?php echo nl2br(htmlspecialchars($chat['ai_response'])); ?>
                                </div>
                            </div>
                        </div>
                        
                        <?php if (!empty($chat['books_mentioned'])): ?>
                            <div class="additional-info">
                                <strong>کتێبە ئامێژکراوەکان:</strong> <?php echo htmlspecialchars($chat['books_mentioned']); ?>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($chat['user_ip'])): ?>
                            <div class="ip-info">
                                IP: <?php echo htmlspecialchars($chat['user_ip']); ?>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- Pagination -->
        <?php if ($total_pages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=<?php echo ($page-1); ?>&search=<?php echo urlencode($search_query); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>" 
                       class="page-btn">پێشوو</a>
                <?php endif; ?>

                <?php
                $start_page = max(1, $page - 2);
                $end_page = min($total_pages, $page + 2);
                
                for ($i = $start_page; $i <= $end_page; $i++):
                ?>
                    <a href="?page=<?php echo $i; ?>&search=<?php echo urlencode($search_query); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>" 
                       class="page-btn <?php echo ($i == $page) ? 'active' : ''; ?>">
                        <?php echo $i; ?>
                    </a>
                <?php endfor; ?>

                <?php if ($page < $total_pages): ?>
                    <a href="?page=<?php echo ($page+1); ?>&search=<?php echo urlencode($search_query); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>" 
                       class="page-btn">دواتر</a>
                <?php endif; ?>
            </div>
        <?php endif; ?>

        <!-- Action Section -->
        <?php if (!empty($chats)): ?>
            <div class="action-section">
                <form method="POST" onsubmit="return confirm('دڵنیایی لە سڕینەوەی هەموو چاتەکان؟ ئەم کردەوەیە ناگەڕێتەوە!')">
                    <button type="submit" name="clear_all_chats" class="danger-btn">
                        سڕینەوەی هەموو چاتەکان
                    </button>
                </form>
            </div>
        <?php endif; ?>

        <div class="decorative-border"></div>
    </div>

    <!-- Developer Footer with Text Particle Effect -->
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

        // Auto-refresh every 5 minutes
        setTimeout(function() {
            window.location.reload();
        }, 300000);

        // Confirm delete actions
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                if (!confirm('دڵنیایی لە سڕینەوەی ئەم چاتە؟')) {
                    e.preventDefault();
                }
            });
        });

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl + F for search
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                document.querySelector('input[name="search"]').focus();
            }
            
            // Arrow keys for pagination
            if (e.key === 'ArrowLeft' && <?php echo $page; ?> < <?php echo $total_pages; ?>) {
                window.location.href = '?page=<?php echo ($page+1); ?>&search=<?php echo urlencode($search_query); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>';
            }
            
            if (e.key === 'ArrowRight' && <?php echo $page; ?> > 1) {
                window.location.href = '?page=<?php echo ($page-1); ?>&search=<?php echo urlencode($search_query); ?>&date_from=<?php echo urlencode($date_from); ?>&date_to=<?php echo urlencode($date_to); ?>';
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

        // Smooth scrolling for pagination
        document.querySelectorAll('.page-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                if (!this.classList.contains('disabled')) {
                    document.body.style.opacity = '0.8';
                }
            });
        });

        // Form validation for search
        document.querySelector('.filters-form').addEventListener('submit', function(e) {
            const searchInput = this.querySelector('input[name="search"]');
            const dateFrom = this.querySelector('input[name="date_from"]');
            const dateTo = this.querySelector('input[name="date_to"]');
            
            if (dateFrom.value && dateTo.value && dateFrom.value > dateTo.value) {
                e.preventDefault();
                alert('بەرواری دەستپێک نابێت گەورەتر بێت لە بەرواری کۆتایی');
                return;
            }
        });
    </script>
</body>
</html>