<?php
require_once 'config.php';
check_admin_session();

$success_message = '';
$error_message = '';

// وەرگرتنی ئاماری گشتی
$stmt = $conn->query("SELECT COUNT(*) as total_books FROM books");
$total_books = $stmt->fetch(PDO::FETCH_ASSOC)['total_books'];

$stmt = $conn->query("SELECT COUNT(*) as total_categories FROM categories WHERE category_id > 1");
$total_categories = $stmt->fetch(PDO::FETCH_ASSOC)['total_categories'];

$stmt = $conn->query("SELECT COUNT(*) as bestsellers FROM books WHERE is_bestseller = 1");
$bestsellers = $stmt->fetch(PDO::FETCH_ASSOC)['bestsellers'];

$stmt = $conn->query("SELECT COUNT(*) as featured FROM books WHERE is_featured = 1");
$featured = $stmt->fetch(PDO::FETCH_ASSOC)['featured'];

// پرۆسێسی زیادکردنی کتێبی نوێ
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_book'])) {
    $title = clean_input($_POST['title']);
    $author = clean_input($_POST['author']);
    $translator = !empty($_POST['translator']) ? clean_input($_POST['translator']) : null;
    $category_id = (int)$_POST['category_id'];
    $price = clean_input($_POST['price']); // Changed from (float) to allow text
    $description = !empty($_POST['description']) ? clean_input($_POST['description']) : null;
    $is_bestseller = isset($_POST['is_bestseller']) ? 1 : 0;
    $is_featured = isset($_POST['is_featured']) ? 1 : 0;
    
    // مامەڵەکردن لەگەڵ وێنە
    $image_name = 'default_book.jpg';
    if(isset($_FILES['book_image']) && $_FILES['book_image']['error'] == 0) {
        $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
        $file_type = $_FILES['book_image']['type'];
        
        if(in_array($file_type, $allowed_types)) {
            $file_extension = pathinfo($_FILES['book_image']['name'], PATHINFO_EXTENSION);
            $image_name = 'book_' . time() . '.' . $file_extension;
            $upload_path = 'images/' . $image_name;
            
            if(!is_dir('images')) {
                mkdir('images', 0777, true);
            }
            
            if(!move_uploaded_file($_FILES['book_image']['tmp_name'], $upload_path)) {
                $error_message = "هەڵەیەک ڕووی دا لە بارکردنی وێنە";
                $image_name = 'default_book.jpg';
            }
        }
    }
    
    if(empty($error_message)) {
        $stmt = $conn->prepare("INSERT INTO books (book_title, author, translator, category_id, price, book_image, description, is_bestseller, is_featured) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        
        if($stmt->execute([$title, $author, $translator, $category_id, $price, $image_name, $description, $is_bestseller, $is_featured])) {
            $success_message = "کتێب بە سەرکەوتوویی زیاد کرا";
        } else {
            $error_message = "هەڵەیەک ڕووی دا لە زیادکردنی کتێب";
        }
    }
}

// وەرگرتنی بەشەکان
$stmt = $conn->query("SELECT * FROM categories WHERE category_id > 1 ORDER BY category_name");
$categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

// وەرگرتنی کتێبەکان
$stmt = $conn->query("SELECT b.*, c.category_name FROM books b LEFT JOIN categories c ON b.category_id = c.category_id ORDER BY b.created_date DESC LIMIT 10");
$recent_books = $stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>داشبۆردی ئەدمین - کتێبخانەی ئاشتی</title>
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

        .nav-link:hover {
            color: #2a2a2a;
            border-color: #c0c0c0;
            background: #f8f8f8;
            transform: translateY(-2px);
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

        /* Sections Grid */
        .sections-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }

        .section {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            padding: 2rem;
            border-radius: 8px;
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

        .checkbox-group {
            display: flex;
            gap: 2rem;
            margin-top: 1rem;
            flex-wrap: wrap;
        }

        .checkbox-item {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .checkbox-item input[type="checkbox"] {
            width: auto;
            margin: 0;
        }

        .form-button {
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
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .form-button:hover {
            background: #c0c0c0;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(192, 192, 192, 0.3);
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

        /* Table Styles */
        .books-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 1rem;
            background: #ffffff;
        }

        .books-table th,
        .books-table td {
            padding: 1rem;
            text-align: right;
            border-bottom: 1px solid #e5e5e5;
        }

        .books-table th {
            background: #f8f8f8;
            font-weight: 600;
            color: #2a2a2a;
            border-bottom: 2px solid #e5e5e5;
        }

        .books-table tr:hover {
            background: #f8f8f8;
        }

        /* Badges */
        .badge {
            padding: 0.3rem 0.6rem;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: 500;
            margin-left: 0.3rem;
        }

        .badge-bestseller {
            background: #fff5f5;
            color: #e53e3e;
            border: 1px solid #fed7d7;
        }

        .badge-featured {
            background: #fffbeb;
            color: #d69e2e;
            border: 1px solid #faf089;
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
            
            .admin-info {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            .sections-grid {
                grid-template-columns: 1fr;
            }
            
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            
            .nav-links {
                justify-content: center;
            }
            
            .checkbox-group {
                flex-direction: column;
                gap: 1rem;
            }
            
            .container {
                padding: 1rem;
            }
            
            .section {
                padding: 1.5rem;
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

        /* Table responsive wrapper */
        .table-wrapper {
            overflow-x: auto;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>داشبۆردی ئەدمین</h1>
            <div class="admin-info">
                <span>بەخێربێیت، <?php echo $_SESSION['admin_name']; ?> (<?php echo $_SESSION['admin_type']; ?>)</span>
                <a href="logout.php" class="logout-btn">دەرچوون</a>
            </div>
        </div>
    </div>

    <div class="container">
        <div class="nav-links">
            <a href="index.php" class="nav-link">بینینی ماڵپەڕ</a>
            <a href="manage_books.php" class="nav-link">بەڕێوەبردنی کتێبەکان</a>
            <a href="manage_categories.php" class="nav-link">بەڕێوەبردنی بەشەکان</a>
            <?php if($_SESSION['admin_type'] == 'گشتی'): ?>
                    <a href="admin_chat_history.php" class="nav-link">چات بۆت</a>
            <a href="manage_admins.php" class="nav-link">بەڕێوەبردنی ئەدمینەکان</a>
            <?php endif; ?>
        </div>

        <?php if($success_message): ?>
            <div class="success-message"><?php echo $success_message; ?></div>
        <?php endif; ?>

        <?php if($error_message): ?>
            <div class="error-message"><?php echo $error_message; ?></div>
        <?php endif; ?>

        <!-- ئاماری گشتی -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><?php echo $total_books; ?></div>
                <div class="stat-label">کۆی کتێبەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $total_categories; ?></div>
                <div class="stat-label">کۆی بەشەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $bestsellers; ?></div>
                <div class="stat-label">پڕ فرۆشترین</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo $featured; ?></div>
                <div class="stat-label">هەڵبژێردراو</div>
            </div>
        </div>

        <div class="decorative-border"></div>

        <div class="sections-grid">
            <!-- زیادکردنی کتێبی نوێ -->
            <div class="section">
                <h2 class="section-title">زیادکردنی کتێبی نوێ</h2>
                <form method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label class="form-label">ناوی کتێب</label>
                        <input type="text" name="title" class="form-input" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">نوسەر</label>
                        <input type="text" name="author" class="form-input" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">وەرگێڕ (ئیختیاری)</label>
                        <input type="text" name="translator" class="form-input">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">بەش</label>
                        <select name="category_id" class="form-select" required>
                            <option value="">هەڵبژێرە...</option>
                            <?php foreach($categories as $category): ?>
                            <option value="<?php echo $category['category_id']; ?>">
                                <?php echo $category['category_name']; ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">نرخ (دینار)</label>
                        <input type="text" name="price" class="form-input" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">وێنەی کتێب</label>
                        <input type="file" name="book_image" class="form-input" accept="image/*">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">پێشەکی (ئیختیاری)</label>
                        <textarea name="description" class="form-textarea" placeholder="پێشەکی کتێب بنوسە..."></textarea>
                    </div>
                    
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" name="is_bestseller" id="bestseller">
                            <label for="bestseller">پڕ فرۆش</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" name="is_featured" id="featured">
                            <label for="featured">هەڵبژێردراو</label>
                        </div>
                    </div>
                    
                    <button type="submit" name="add_book" class="form-button">زیادکردنی کتێب</button>
                </form>
            </div>
        </div>

        <!-- نوێترین کتێبەکان -->
        <div class="section">
            <h2 class="section-title">نوێترین کتێبەکان</h2>
            <div class="table-wrapper">
                <table class="books-table">
                    <thead>
                        <tr>
                            <th>ناوی کتێب</th>
                            <th>نوسەر</th>
                            <th>بەش</th>
                            <th>نرخ</th>
                            <th>تایبەتمەندی</th>
                            <th>بەروار</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($recent_books as $book): ?>
                        <tr>
                            <td><?php echo $book['book_title']; ?></td>
                            <td><?php echo $book['author']; ?></td>
                            <td><?php echo $book['category_name']; ?></td>
                            <td><?php echo number_format($book['price']); ?> دینار</td>
                            <td>
                                <?php if($book['is_bestseller']): ?>
                                <span class="badge badge-bestseller">پڕ فرۆش</span>
                                <?php endif; ?>
                                <?php if($book['is_featured']): ?>
                                <span class="badge badge-featured">هەڵبژێردراو</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo date('Y/m/d', strtotime($book['created_date'])); ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
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
        document.querySelector('form').addEventListener('submit', function(e) {
            const title = this.title.value.trim();
            const author = this.author.value.trim();
            const price = this.price.value.trim();
            
            if (!title || !author || !price) {
                e.preventDefault();
                alert('تکایە زانیاری پێویست تەواو بکە');
                return;
            }
        });

        // Add loading state for form submission
        document.querySelector('.form-button').addEventListener('click', function() {
            setTimeout(() => {
                this.textContent = 'زیادکردن...';
                this.disabled = true;
            }, 100);
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
    </script>
</body>
</html>