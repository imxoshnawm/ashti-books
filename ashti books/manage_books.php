<?php
require_once 'config.php';
check_admin_session();

$success_message = '';
$error_message = '';

// سڕینەوەی کتێب
if(isset($_GET['delete']) && $_SESSION['admin_type'] == 'گشتی') {
    $book_id = (int)$_GET['delete'];
    
    // وەرگرتنی زانیاری کتێب بۆ سڕینەوەی وێنە
    $stmt = $conn->prepare("SELECT book_image FROM books WHERE book_id = ?");
    $stmt->execute([$book_id]);
    $book = $stmt->fetch(PDO::FETCH_ASSOC);
    
    $stmt = $conn->prepare("DELETE FROM books WHERE book_id = ?");
    if($stmt->execute([$book_id])) {
        // سڕینەوەی وێنە
        if($book && $book['book_image'] != 'default_book.jpg' && file_exists('images/' . $book['book_image'])) {
            unlink('images/' . $book['book_image']);
        }
        $success_message = "کتێب بە سەرکەوتوویی سڕایەوە";
    } else {
        $error_message = "هەڵەیەک ڕووی دا لە سڕینەوەی کتێب";
    }
}

// گۆڕینی حاڵەتی پڕ فرۆش/هەڵبژێردراو
if(isset($_POST['toggle_status'])) {
    $book_id = (int)$_POST['book_id'];
    $field = $_POST['field'];
    $value = (int)$_POST['value'];
    
    if(in_array($field, ['is_bestseller', 'is_featured'])) {
        $stmt = $conn->prepare("UPDATE books SET $field = ? WHERE book_id = ?");
        if($stmt->execute([$value, $book_id])) {
            $success_message = "حاڵەت بە سەرکەوتوویی گۆڕا";
        }
    }
}

// نوێکردنەوەی کتێب
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_book'])) {
    $book_id = (int)$_POST['book_id'];
    $title = clean_input($_POST['title']);
    $author = clean_input($_POST['author']);
    $translator = !empty($_POST['translator']) ? clean_input($_POST['translator']) : null;
    $category_id = (int)$_POST['category_id'];
    $price = clean_input($_POST['price']); // Changed from (float) to allow text like admin_dashboard
    $description = !empty($_POST['description']) ? clean_input($_POST['description']) : null;
    $is_bestseller = isset($_POST['is_bestseller']) ? 1 : 0;
    $is_featured = isset($_POST['is_featured']) ? 1 : 0;
    
    // مامەڵەکردن لەگەڵ وێنەی نوێ
    $image_update = '';
    if(isset($_FILES['book_image']) && $_FILES['book_image']['error'] == 0) {
        $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif'];
        $file_type = $_FILES['book_image']['type'];
        
        if(in_array($file_type, $allowed_types)) {
            // سڕینەوەی وێنەی کۆن
            $stmt = $conn->prepare("SELECT book_image FROM books WHERE book_id = ?");
            $stmt->execute([$book_id]);
            $old_book = $stmt->fetch(PDO::FETCH_ASSOC);
            
            if($old_book && $old_book['book_image'] != 'default_book.jpg' && file_exists('images/' . $old_book['book_image'])) {
                unlink('images/' . $old_book['book_image']);
            }
            
            $file_extension = pathinfo($_FILES['book_image']['name'], PATHINFO_EXTENSION);
            $image_name = 'book_' . time() . '.' . $file_extension;
            $upload_path = 'images/' . $image_name;
            
            if(move_uploaded_file($_FILES['book_image']['tmp_name'], $upload_path)) {
                $image_update = ', book_image = ?';
            }
        }
    }
    
    $sql = "UPDATE books SET book_title = ?, author = ?, translator = ?, category_id = ?, price = ?, description = ?, is_bestseller = ?, is_featured = ?" . $image_update . " WHERE book_id = ?";
    
    $params = [$title, $author, $translator, $category_id, $price, $description, $is_bestseller, $is_featured];
    if($image_update) {
        $params[] = $image_name;
    }
    $params[] = $book_id;
    
    $stmt = $conn->prepare($sql);
    if($stmt->execute($params)) {
        $success_message = "کتێب بە سەرکەوتوویی نوێ کرایەوە";
    } else {
        $error_message = "هەڵەیەک ڕووی دا لە نوێکردنەوەی کتێب";
    }
}

// وەرگرتنی بەشەکان
$stmt = $conn->query("SELECT * FROM categories WHERE category_id > 1 ORDER BY category_name");
$categories = $stmt->fetchAll(PDO::FETCH_ASSOC);

// وەرگرتنی کتێبەکان لەگەڵ پاڵاوتن
$search = isset($_GET['search']) ? clean_input($_GET['search']) : '';
$category_filter = isset($_GET['category']) ? (int)$_GET['category'] : 0;

$where_conditions = [];
$params = [];

if(!empty($search)) {
    $where_conditions[] = "(b.book_title LIKE ? OR b.author LIKE ?)";
    $search_param = "%$search%";
    $params[] = $search_param;
    $params[] = $search_param;
}

if($category_filter > 0) {
    $where_conditions[] = "b.category_id = ?";
    $params[] = $category_filter;
}

$where_clause = count($where_conditions) > 0 ? "WHERE " . implode(" AND ", $where_conditions) : "";

$stmt = $conn->prepare("SELECT b.*, c.category_name FROM books b 
                       LEFT JOIN categories c ON b.category_id = c.category_id 
                       $where_clause 
                       ORDER BY b.created_date DESC");
$stmt->execute($params);
$books = $stmt->fetchAll(PDO::FETCH_ASSOC);

// وەرگرتنی کتێب بۆ دەستکاریکردن
$edit_book = null;
if(isset($_GET['edit'])) {
    $edit_id = (int)$_GET['edit'];
    $stmt = $conn->prepare("SELECT * FROM books WHERE book_id = ?");
    $stmt->execute([$edit_id]);
    $edit_book = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>بەڕێوەبردنی کتێبەکان - کتێبخانەی ئاشتی</title>
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

        /* Search Section */
        .search-grid {
            display: grid;
            grid-template-columns: 2fr 1fr auto;
            gap: 1rem;
            align-items: end;
        }

        .search-btn {
            padding: 0.8rem 1.5rem;
            background: #2a2a2a;
            color: #ffffff;
            border: none;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            height: fit-content;
        }

        .search-btn:hover {
            background: #c0c0c0;
            transform: translateY(-2px);
        }

        /* Edit Form */
        .edit-form {
            background: #f8f9fa;
            border: 3px solid #c0c0c0;
            border-radius: 8px;
            padding: 2rem;
            margin-bottom: 2rem;
        }

        .form-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
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

        /* Table Styles */
        .table-wrapper {
            overflow-x: auto;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            margin-top: 1rem;
        }

        .books-table {
            width: 100%;
            border-collapse: collapse;
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

        .book-image {
            width: 60px;
            height: 80px;
            object-fit: cover;
            border-radius: 5px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }

        .no-image {
            width: 60px;
            height: 80px;
            background: #f0f0f0;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 5px;
            font-size: 0.8rem;
            color: #999;
            border: 1px solid #e5e5e5;
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

        .toggle-btn {
            background: #95a5a6;
            color: white;
            font-size: 0.8rem;
        }

        .toggle-btn:hover {
            background: #7f8c8d;
        }

        .toggle-btn.active {
            background: #27ae60;
        }

        .toggle-btn.active:hover {
            background: #229954;
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

        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 3rem;
            color: #666;
            font-style: italic;
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            .header-content {
                flex-direction: column;
                gap: 1rem;
                text-align: center;
            }
            
            .search-grid {
                grid-template-columns: 1fr;
                gap: 1rem;
            }
            
            .form-grid {
                grid-template-columns: 1fr;
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
            
            .books-table {
                font-size: 0.9rem;
            }
            
            .books-table th,
            .books-table td {
                padding: 0.5rem;
            }
        }

        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.8rem;
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

        .section {
            animation: fadeInUp 0.6s ease-out;
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>بەڕێوەبردنی کتێبەکان</h1>
            <div class="admin-info">
                <span>بەخێربێیت، <?php echo $_SESSION['admin_name']; ?> (<?php echo $_SESSION['admin_type']; ?>)</span>
                <a href="admin_dashboard.php" class="nav-link">گەڕانەوە بۆ داشبۆرد</a>
            </div>
        </div>
    </div>

    <div class="container">
        <?php if($success_message): ?>
            <div class="success-message"><?php echo $success_message; ?></div>
        <?php endif; ?>

        <?php if($error_message): ?>
            <div class="error-message"><?php echo $error_message; ?></div>
        <?php endif; ?>

        <!-- فۆرمی دەستکاریکردن -->
        <?php if($edit_book): ?>
        <div class="edit-form">
            <h2 class="section-title">دەستکاریکردنی کتێب: <?php echo htmlspecialchars($edit_book['book_title']); ?></h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="hidden" name="book_id" value="<?php echo $edit_book['book_id']; ?>">
                
                <div class="form-grid">
                    <div class="form-group">
                        <label class="form-label">ناوی کتێب</label>
                        <input type="text" name="title" class="form-input" value="<?php echo htmlspecialchars($edit_book['book_title']); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">نوسەر</label>
                        <input type="text" name="author" class="form-input" value="<?php echo htmlspecialchars($edit_book['author']); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">وەرگێڕ (ئیختیاری)</label>
                        <input type="text" name="translator" class="form-input" value="<?php echo htmlspecialchars($edit_book['translator']); ?>">
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">بەش</label>
                        <select name="category_id" class="form-select" required>
                            <?php foreach($categories as $category): ?>
                            <option value="<?php echo $category['category_id']; ?>" 
                                    <?php echo ($edit_book['category_id'] == $category['category_id']) ? 'selected' : ''; ?>>
                                <?php echo $category['category_name']; ?>
                            </option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">نرخ (دینار)</label>
                        <input type="text" name="price" class="form-input" value="<?php echo $edit_book['price']; ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">وێنەی نوێ (ئیختیاری)</label>
                        <input type="file" name="book_image" class="form-input" accept="image/*">
                        <?php if($edit_book['book_image'] != 'default_book.jpg'): ?>
                        <small style="color: #7f8c8d; margin-top: 0.5rem; display: block;">وێنەی ئێستا: <?php echo $edit_book['book_image']; ?></small>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">پێشەکی (ئیختیاری)</label>
                    <textarea name="description" class="form-textarea" placeholder="پێشەکی کتێب بنوسە..."><?php echo htmlspecialchars($edit_book['description']); ?></textarea>
                </div>
                
                <div class="checkbox-group">
                    <div class="checkbox-item">
                        <input type="checkbox" name="is_bestseller" id="edit_bestseller" <?php echo $edit_book['is_bestseller'] ? 'checked' : ''; ?>>
                        <label for="edit_bestseller">پڕ فرۆش</label>
                    </div>
                    <div class="checkbox-item">
                        <input type="checkbox" name="is_featured" id="edit_featured" <?php echo $edit_book['is_featured'] ? 'checked' : ''; ?>>
                        <label for="edit_featured">هەڵبژێردراو</label>
                    </div>
                </div>
                
                <div style="margin-top: 2rem;">
                    <button type="submit" name="update_book" class="form-button">نوێکردنەوە</button>
                    <a href="manage_books.php" class="form-button cancel-btn">هەڵوەشاندنەوە</a>
                </div>
            </form>
        </div>
        <?php endif; ?>

        <!-- بەشی گەڕان -->
        <div class="section">
            <h2 class="section-title">گەڕان و پاڵاوتن</h2>
            <form method="GET" class="search-grid">
                <div class="form-group">
                    <label class="form-label">گەڕان لە کتێبەکان</label>
                    <input type="text" name="search" class="form-input" placeholder="ناوی کتێب یان نوسەر..." value="<?php echo htmlspecialchars($search); ?>">
                </div>
                
                <div class="form-group">
                    <label class="form-label">پاڵاوتن بەپێی بەش</label>
                    <select name="category" class="form-select">
                        <option value="0">هەموو بەشەکان</option>
                        <?php foreach($categories as $category): ?>
                        <option value="<?php echo $category['category_id']; ?>" 
                                <?php echo ($category_filter == $category['category_id']) ? 'selected' : ''; ?>>
                            <?php echo $category['category_name']; ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                
                <button type="submit" class="search-btn">گەڕان</button>
            </form>
        </div>

        <div class="decorative-border"></div>

        <!-- بەشی کتێبەکان -->
        <div class="section">
            <h2 class="section-title">لیستی کتێبەکان (<?php echo count($books); ?> کتێب)</h2>
            
            <?php if(count($books) > 0): ?>
            <div class="table-wrapper">
                <table class="books-table">
                    <thead>
                        <tr>
                            <th>وێنە</th>
                            <th>ناوی کتێب</th>
                            <th>نوسەر</th>
                            <th>بەش</th>
                            <th>نرخ</th>
                            <th>حاڵەت</th>
                            <th>بینین</th>
                            <th>کردارەکان</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach($books as $book): ?>
                        <tr>
                            <td>
                                <?php if($book['book_image'] && $book['book_image'] != 'default_book.jpg' && file_exists('images/' . $book['book_image'])): ?>
                                    <img src="images/<?php echo $book['book_image']; ?>" alt="<?php echo htmlspecialchars($book['book_title']); ?>" class="book-image">
                                <?php else: ?>
                                    <div class="no-image">وێنە نیە</div>
                                <?php endif; ?>
                            </td>
                            <td><strong><?php echo htmlspecialchars($book['book_title']); ?></strong></td>
                            <td><?php echo htmlspecialchars($book['author']); ?></td>
                            <td><?php echo htmlspecialchars($book['category_name']); ?></td>
                            <td><?php echo number_format($book['price']); ?> دینار</td>
                            <td>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="book_id" value="<?php echo $book['book_id']; ?>">
                                    <input type="hidden" name="field" value="is_bestseller">
                                    <input type="hidden" name="value" value="<?php echo $book['is_bestseller'] ? 0 : 1; ?>">
                                    <button type="submit" name="toggle_status" class="action-btn toggle-btn <?php echo $book['is_bestseller'] ? 'active' : ''; ?>">
                                        پڕ فرۆش
                                    </button>
                                </form>
                                
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="book_id" value="<?php echo $book['book_id']; ?>">
                                    <input type="hidden" name="field" value="is_featured">
                                    <input type="hidden" name="value" value="<?php echo $book['is_featured'] ? 0 : 1; ?>">
                                    <button type="submit" name="toggle_status" class="action-btn toggle-btn <?php echo $book['is_featured'] ? 'active' : ''; ?>">
                                        هەڵبژێردراو
                                    </button>
                                </form>
                            </td>
                            <td><?php echo number_format($book['view_count']); ?></td>
                            <td>
                                <a href="?edit=<?php echo $book['book_id']; ?>" class="action-btn edit-btn">دەستکاری</a>
                                <?php if($_SESSION['admin_type'] == 'گشتی'): ?>
                                <a href="?delete=<?php echo $book['book_id']; ?>" 
                                   class="action-btn delete-btn" 
                                   onclick="return confirm('دڵنیایت لە سڕینەوەی ئەم کتێبە؟')">سڕینەوە</a>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            <?php else: ?>
            <div class="empty-state">
                هیچ کتێبێک نەدۆزرایەوە
            </div>
            <?php endif; ?>
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
            if (this.title && this.author && this.price) {
                const title = this.title.value.trim();
                const author = this.author.value.trim();
                const price = this.price.value.trim();
                
                if (!title || !author || !price) {
                    e.preventDefault();
                    alert('تکایە زانیاری پێویست تەواو بکە');
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
                if (!confirm('دڵنیایت لە سڕینەوەی ئەم کتێبە؟')) {
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
    </script>
</body>
</html>