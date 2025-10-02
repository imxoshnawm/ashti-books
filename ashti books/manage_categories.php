<?php
require_once 'config.php';
check_admin_session();

$success_message = '';
$error_message = '';

// زیادکردنی بەشی نوێ
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_category'])) {
    $category_name = clean_input($_POST['category_name']);
    $category_description = clean_input($_POST['category_description']);
    
    // چەکردنی ئەگەر ناوی بەش دووبارە بووەتەوە
    $stmt = $conn->prepare("SELECT COUNT(*) FROM categories WHERE category_name = ?");
    $stmt->execute([$category_name]);
    $count = $stmt->fetchColumn();
    
    if($count > 0) {
        $error_message = "ئەم ناوە پێشتر بەکارهاتووە";
    } else {
        $stmt = $conn->prepare("INSERT INTO categories (category_name, category_description) VALUES (?, ?)");
        if($stmt->execute([$category_name, $category_description])) {
            $success_message = "بەش بە سەرکەوتوویی زیاد کرا";
        } else {
            $error_message = "هەڵەیەک ڕووی دا لە زیادکردنی بەش";
        }
    }
}

// سڕینەوەی بەش (تەنیا بۆ ئەدمینی گشتی)
if(isset($_GET['delete']) && $_SESSION['admin_type'] == 'گشتی') {
    $category_id = (int)$_GET['delete'];
    
    // چەکردنی ئەگەر کتێب لەم بەشەدا هەیە
    $stmt = $conn->prepare("SELECT COUNT(*) FROM books WHERE category_id = ?");
    $stmt->execute([$category_id]);
    $book_count = $stmt->fetchColumn();
    
    if($book_count > 0) {
        $error_message = "ناتوانرێت ئەم بەشە بسڕێتەوە چونکە $book_count کتێبی تێدایە";
    } elseif($category_id == 1) {
        $error_message = "ناتوانرێت بەشی 'هەموو کتێبەکان' بسڕێتەوە";
    } else {
        $stmt = $conn->prepare("DELETE FROM categories WHERE category_id = ?");
        if($stmt->execute([$category_id])) {
            $success_message = "بەش بە سەرکەوتوویی سڕایەوە";
        } else {
            $error_message = "هەڵەیەک ڕووی دا لە سڕینەوەی بەش";
        }
    }
}

// نوێکردنەوەی بەش
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_category'])) {
    $category_id = (int)$_POST['category_id'];
    $category_name = clean_input($_POST['category_name']);
    $category_description = clean_input($_POST['category_description']);
    
    // چەکردنی ئەگەر ناوی بەش دووبارە بووەتەوە (جگە لە خۆی)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM categories WHERE category_name = ? AND category_id != ?");
    $stmt->execute([$category_name, $category_id]);
    $count = $stmt->fetchColumn();
    
    if($count > 0) {
        $error_message = "ئەم ناوە پێشتر بەکارهاتووە";
    } else {
        $stmt = $conn->prepare("UPDATE categories SET category_name = ?, category_description = ? WHERE category_id = ?");
        if($stmt->execute([$category_name, $category_description, $category_id])) {
            $success_message = "بەش بە سەرکەوتوویی نوێ کرایەوە";
        } else {
            $error_message = "هەڵەیەک ڕووی دا لە نوێکردنەوەی بەش";
        }
    }
}

// وەرگرتنی بەشەکان لەگەڵ ژمارەی کتێبەکان
$stmt = $conn->query("SELECT c.*, COUNT(b.book_id) as book_count 
                     FROM categories c 
                     LEFT JOIN books b ON c.category_id = b.category_id 
                     GROUP BY c.category_id 
                     ORDER BY c.category_name");
$categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

// وەرگرتنی بەش بۆ دەستکاریکردن
$edit_category = null;
if(isset($_GET['edit'])) {
    $edit_id = (int)$_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM categories WHERE category_id = ?");
    $stmt->execute([$edit_id]);
    $edit_category = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>بەڕێوەبردنی بەشەکان - کتێبخانەی ئاشتی</title>
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

        .nav-link {
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

        .nav-link:hover {
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

        /* Messages */
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

        /* Section Styles */
        .section {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            padding: 2rem;
            border-radius: 8px;
            margin-bottom: 2rem;
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

        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
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

        /* Sections Grid */
        .sections-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }

        /* Form Styles */
        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 600;
            color: #2a2a2a;
            font-size: 1rem;
        }

        .form-input, .form-select, .form-textarea {
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

        .form-input:focus, .form-select:focus, .form-textarea:focus {
            outline: none;
            border-color: #c0c0c0;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(192, 192, 192, 0.1);
        }

        .form-textarea {
            resize: vertical;
            min-height: 100px;
        }

        .form-button {
            padding: 1rem 2rem;
            background: #2a2a2a;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            font-size: 1.1rem;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }

        .form-button:hover {
            background: #c0c0c0;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(192, 192, 192, 0.3);
        }

        .cancel-btn {
            background: #95a5a6;
            margin-right: 1rem;
        }

        .cancel-btn:hover {
            background: #7f8c8d;
        }

        /* Edit Form */
        .edit-form {
            background: #f8f9fa;
            border: 3px solid #c0c0c0;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }

        /* Table Styles */
        .table-wrapper {
            overflow-x: auto;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            margin-top: 1rem;
        }

        .categories-table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }

        .categories-table th,
        .categories-table td {
            padding: 1rem;
            text-align: right;
            border-bottom: 1px solid #e5e5e5;
        }

        .categories-table th {
            background: #f8f8f8;
            font-weight: 600;
            color: #2a2a2a;
            border-bottom: 2px solid #e5e5e5;
        }

        .categories-table tr:hover {
            background: #f8f8f8;
        }

        /* Action Buttons */
        .action-btn {
            padding: 0.4rem 0.8rem;
            margin: 0.2rem;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 0.9rem;
            text-decoration: none;
            display: inline-block;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .edit-btn {
            background: #3498db;
            color: white;
        }

        .edit-btn:hover {
            background: #2980b9;
            transform: translateY(-1px);
        }

        .delete-btn {
            background: #e74c3c;
            color: white;
        }

        .delete-btn:hover {
            background: #c0392b;
            transform: translateY(-1px);
        }

        .book-count-badge {
            background: #34495e;
            color: white;
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }

        /* Category Cards */
        .category-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 2rem;
        }

        .category-card {
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            border-right: 4px solid #3498db;
            transition: all 0.3s ease;
        }

        .category-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }

        .category-card h4 {
            color: #2a2a2a;
            margin-bottom: 0.5rem;
            font-family: 'Playfair Display', serif;
        }

        .category-card .book-count {
            color: #7f8c8d;
            font-size: 0.9rem;
        }

        .progress-bar {
            background: #3498db;
            height: 4px;
            border-radius: 2px;
            margin-top: 0.5rem;
            transition: width 0.3s ease;
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

        /* Responsive Design */
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .sections-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .container {
                padding: 1rem;
            }
            
            .section {
                padding: 1.5rem;
            }
            
            .categories-table {
                font-size: 0.9rem;
            }
            
            .categories-table th,
            .categories-table td {
                padding: 0.5rem;
            }
        }

        @media (max-width: 480px) {
            .stats-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 1.8rem;
            }
            
            .stat-number {
                font-size: 2rem;
            }
            
            .action-btn {
                font-size: 0.8rem;
                padding: 0.3rem 0.6rem;
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
        .section {
            animation: fadeInUp 0.6s ease-out;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>بەڕێوەبردنی بەشەکان</h1>
            <a href="admin_dashboard.php" class="nav-link">گەڕانەوە بۆ داشبۆرد</a>
        </div>
    </div>

    <div class="container">
        <?php if($success_message): ?>
            <div class="success-message"><?php echo $success_message; ?></div>
        <?php endif; ?>

        <?php if($error_message): ?>
            <div class="error-message"><?php echo $error_message; ?></div>
        <?php endif; ?>

        <!-- ئاماری بەشەکان -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><?php echo count($categories); ?></div>
                <div class="stat-label">کۆی بەشەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">
                    <?php 
                    $total_books = 0;
                    foreach($categories as $cat) {
                        $total_books += $cat['book_count'];
                    }
                    echo $total_books;
                    ?>
                </div>
                <div class="stat-label">کۆی کتێبەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">
                    <?php 
                    $empty_categories = 0;
                    foreach($categories as $cat) {
                        if($cat['book_count'] == 0 && $cat['category_id'] != 1) {
                            $empty_categories++;
                        }
                    }
                    echo $empty_categories;
                    ?>
                </div>
                <div class="stat-label">بەشی بەتاڵ</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">
                    <?php 
                    $max_books = 0;
                    foreach($categories as $cat) {
                        if($cat['book_count'] > $max_books) {
                            $max_books = $cat['book_count'];
                        }
                    }
                    echo $max_books;
                    ?>
                </div>
                <div class="stat-label">زۆرترین کتێب</div>
            </div>
        </div>

        <div class="decorative-border"></div>

        <!-- فۆرمی دەستکاریکردن -->
        <?php if($edit_category): ?>
        <div class="edit-form">
            <h2 class="section-title">دەستکاریکردنی بەش: <?php echo htmlspecialchars($edit_category['category_name']); ?></h2>
            <form method="POST">
                <input type="hidden" name="category_id" value="<?php echo $edit_category['category_id']; ?>">
                
                <div class="form-group">
                    <label class="form-label">ناوی بەش</label>
                    <input type="text" name="category_name" class="form-input" value="<?php echo htmlspecialchars($edit_category['category_name']); ?>" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">پێناسەی بەش</label>
                    <textarea name="category_description" class="form-textarea" placeholder="پێناسەی بەش بنوسە..."><?php echo htmlspecialchars($edit_category['category_description']); ?></textarea>
                </div>
                
                <div style="margin-top: 2rem;">
                    <button type="submit" name="update_category" class="form-button">نوێکردنەوە</button>
                    <a href="manage_categories.php" class="form-button cancel-btn">هەڵوەشاندنەوە</a>
                </div>
            </form>
        </div>
        <?php endif; ?>

        <div class="sections-grid">
            <!-- زیادکردنی بەشی نوێ -->
            <div class="section">
                <h2 class="section-title">زیادکردنی بەشی نوێ</h2>
                <form method="POST">
                    <div class="form-group">
                        <label class="form-label">ناوی بەش</label>
                        <input type="text" name="category_name" class="form-input" placeholder="ناوی بەش بنوسە..." required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">پێناسەی بەش</label>
                        <textarea name="category_description" class="form-textarea" placeholder="پێناسەی بەش بنوسە..."></textarea>
                    </div>
                    
                    <button type="submit" name="add_category" class="form-button">زیادکردنی بەش</button>
                </form>
            </div>
        </div>

        <!-- لیستی بەشەکان -->
        <div class="section">
            <h2 class="section-title">لیستی بەشەکان</h2>
            
            <div class="table-wrapper">
                <table class="categories-table">
                    <thead>
                        <tr>
                            <th>ناوی بەش</th>
                            <th>پێناسە</th>
                            <th>ژمارەی کتێب</th>
                            <th>بەرواری دروستکردن</th>
                            <th>کردارەکان</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($categories as $category): ?>
                        <tr>
                            <td><strong><?php echo htmlspecialchars($category['category_name']); ?></strong></td>
                            <td>
                                <?php if($category['category_description']): ?>
                                    <?php echo mb_substr(htmlspecialchars($category['category_description']), 0, 50, 'UTF-8'); ?>
                                    <?php if(mb_strlen($category['category_description'], 'UTF-8') > 50): ?>...<?php endif; ?>
                                <?php else: ?>
                                    <span style="color: #7f8c8d;">پێناسە نیە</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <span class="book-count-badge"><?php echo $category['book_count']; ?> کتێب</span>
                            </td>
                            <td><?php echo date('Y/m/d', strtotime($category['created_date'])); ?></td>
                            <td>
                                <?php if($category['category_id'] != 1): ?>
                                <a href="?edit=<?php echo $category['category_id']; ?>" class="action-btn edit-btn">دەستکاری</a>
                                <?php if($_SESSION['admin_type'] == 'گشتی' && $category['book_count'] == 0): ?>
                                <a href="?delete=<?php echo $category['category_id']; ?>" 
                                   class="action-btn delete-btn" 
                                   onclick="return confirm('دڵنیایت لە سڕینەوەی ئەم بەشە؟')">سڕینەوە</a>
                                <?php endif; ?>
                                <?php else: ?>
                                <span style="color: #7f8c8d; font-size: 0.9rem;">بەشی بنەڕەتی</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- بەشەکان بەپێی ژمارەی کتێب -->
        <div class="section">
            <h2 class="section-title">بەشەکان بەپێی ژمارەی کتێب</h2>
            <div class="category-cards">
                <?php 
                // ڕیزکردنی بەشەکان بەپێی ژمارەی کتێب
                usort($categories, function($a, $b) {
                    return $b['book_count'] - $a['book_count'];
                });
                
                foreach(array_slice($categories, 0, 6) as $category): 
                ?>
                <div class="category-card">
                    <h4><?php echo htmlspecialchars($category['category_name']); ?></h4>
                    <div class="book-count"><?php echo $category['book_count']; ?> کتێب</div>
                    <?php if($category['book_count'] > 0 && count($categories) > 0): ?>
                    <div class="progress-bar" style="width: <?php echo min(100, ($category['book_count'] / max(1, $categories[0]['book_count'])) * 100); ?>%;"></div>
                    <?php endif; ?>
                </div>
                <?php endforeach; ?>
            </div>
        </div>
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
    <script>
        // Form validation
        document.querySelector('form[method="POST"]')?.addEventListener('submit', function(e) {
            if (this.category_name) {
                const categoryName = this.category_name.value.trim();
                
                if (!categoryName) {
                    e.preventDefault();
                    alert('تکایە ناوی بەش بنوسە');
                    return;
                }
            }
        });

        // Add loading state for form submission
        document.querySelectorAll('.form-button[type="submit"]').forEach(button => {
            button.addEventListener('click', function() {
                setTimeout(() => {
                    this.textContent = 'پرۆسەکردن...';
                    this.disabled = true;
                }, 100);
            });
        });

        // Page load animation
        window.addEventListener('load', function() {
            document.body.style.opacity = '0';
            document.body.style.transition = 'opacity 0.5s ease-in-out';
            setTimeout(() => {
                document.body.style.opacity = '1';
            }, 100);
        });

        // Auto-hide messages after 5 seconds
        setTimeout(() => {
            const messages = document.querySelectorAll('.success-message, .error-message');
            messages.forEach(message => {
                message.style.transition = 'opacity 0.5s ease-out';
                message.style.opacity = '0';
                setTimeout(() => message.remove(), 500);
            });
        }, 5000);

        // Confirm delete action
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                if (!confirm('دڵنیایت لە سڕینەوەی ئەم بەشە؟')) {
                    e.preventDefault();
                }
            });
        });

        // Enhanced hover effects for action buttons
        document.querySelectorAll('.action-btn').forEach(btn => {
            btn.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-2px)';
            });
            
            btn.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
            });
        });

        // Enhanced hover effects for category cards
        document.querySelectorAll('.category-card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-4px)';
                this.style.boxShadow = '0 8px 25px rgba(0,0,0,0.15)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0)';
                this.style.boxShadow = '0 4px 15px rgba(0,0,0,0.08)';
            });
        });

        // Smooth scroll for form focus
        document.querySelectorAll('.form-input, .form-textarea').forEach(input => {
            input.addEventListener('focus', function() {
                this.scrollIntoView({ 
                    behavior: 'smooth', 
                    block: 'center' 
                });
            });
        });
    </script>
</body>
</html>