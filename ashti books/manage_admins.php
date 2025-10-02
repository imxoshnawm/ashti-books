<?php
require_once 'config.php';
check_admin_session();

// چەکردنی ئەگەر ئەدمین گشتییە
if($_SESSION['admin_type'] != 'گشتی') {
    header("Location: admin_dashboard.php");
    exit();
}

$success_message = '';
$error_message = '';

// سڕینەوەی ئەدمین
if(isset($_GET['delete'])) {
    $admin_id = (int)$_GET['delete'];
    
    // ناتوانرێت خۆی بسڕێتەوە
    if($admin_id == $_SESSION['admin_id']) {
        $error_message = "ناتوانیت خۆت بسڕیتەوە";
    } else {
        $stmt = $conn->prepare("DELETE FROM admins WHERE admin_id = ?");
        if($stmt->execute([$admin_id])) {
            $success_message = "ئەدمین بە سەرکەوتوویی سڕایەوە";
        } else {
            $error_message = "هەڵەیەک ڕووی دا لە سڕینەوەی ئەدمین";
        }
    }
}

// زیادکردنی ئەدمینی نوێ
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['add_admin'])) {
    $name = clean_input($_POST['name']);
    $phone = clean_input($_POST['phone']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];
    $admin_type = clean_input($_POST['admin_type']);
    
    if(empty($name) || empty($phone) || empty($password) || empty($confirm_password)) {
        $error_message = "تکایە هەموو خانەکان پڕبکەرەوە";
    } elseif($password !== $confirm_password) {
        $error_message = "تێپەڕەوشەکان یەکسان نین";
    } elseif(strlen($password) < 6) {
        $error_message = "تێپەڕەوشە دەبێت لانیکەم ٦ پیت بێت";
    } else {
        // چەکردنی ئەگەر ژمارە مۆبایلەکە پێشتر بەکارهاتووە
        $stmt = $conn->prepare("SELECT COUNT(*) FROM admins WHERE phone_number = ?");
        $stmt->execute([$phone]);
        $count = $stmt->fetchColumn();
        
        if($count > 0) {
            $error_message = "ئەم ژمارە مۆبایلە پێشتر بەکارهاتووە";
        } else {
            // چاککردنی query - بەکارهێنانی admin_name لە جیاتی name
            $stmt = $conn->prepare("INSERT INTO admins (admin_name, phone_number, password, admin_type) VALUES (?, ?, MD5(?), ?)");
            if($stmt->execute([$name, $phone, $password, $admin_type])) {
                $success_message = "ئەدمین بە سەرکەوتوویی زیاد کرا";
            } else {
                $error_message = "هەڵەیەک ڕووی دا لە زیادکردنی ئەدمین";
            }
        }
    }
}

// نوێکردنەوەی ئەدمین
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['update_admin'])) {
    $admin_id = (int)$_POST['admin_id'];
    $name = clean_input($_POST['name']);
    $phone = clean_input($_POST['phone']);
    $admin_type = clean_input($_POST['admin_type']);
    $new_password = $_POST['new_password'];
    
    // چەکردنی ئەگەر ژمارە مۆبایلەکە پێشتر بەکارهاتووە (جگە لە خۆی)
    $stmt = $conn->prepare("SELECT COUNT(*) FROM admins WHERE phone_number = ? AND admin_id != ?");
    $stmt->execute([$phone, $admin_id]);
    $count = $stmt->fetchColumn();
    
    if($count > 0) {
        $error_message = "ئەم ژمارە مۆبایلە پێشتر بەکارهاتووە";
    } else {
        $password_update = '';
        $params = [$name, $phone, $admin_type];
        
        // ئەگەر تێپەڕەوشەی نوێ نوسراوە
        if(!empty($new_password)) {
            if(strlen($new_password) < 6) {
                $error_message = "تێپەڕەوشە دەبێت لانیکەم ٦ پیت بێت";
            } else {
                $password_update = ', password = MD5(?)';
                $params[] = $new_password;
            }
        }
        
        if(empty($error_message)) {
            $params[] = $admin_id;
            // چاککردنی query - بەکارهێنانی admin_name
            $sql = "UPDATE admins SET admin_name = ?, phone_number = ?, admin_type = ?" . $password_update . " WHERE admin_id = ?";
            
            $stmt = $conn->prepare($sql);
            if($stmt->execute($params)) {
                $success_message = "ئەدمین بە سەرکەوتوویی نوێ کرایەوە";
            } else {
                $error_message = "هەڵەیەک ڕووی دا لە نوێکردنەوەی ئەدمین";
            }
        }
    }
}

// وەرگرتنی ئەدمینەکان - دڵنیابوونەوە لە هەموو کۆلەمەکان
$stmt = $conn->query("SELECT admin_id, admin_name, phone_number, admin_type, created_date FROM admins ORDER BY created_date DESC");
$admins = $stmt->fetchAll(PDO::FETCH_ASSOC);

// بۆ debug - چاپکردنی یەکەم ئەدمین بۆ بینینی ستوونەکان
if(!empty($admins)) {
    error_log("First admin data: " . print_r($admins[0], true));
}

// وەرگرتنی ئەدمین بۆ دەستکاریکردن
$edit_admin = null;
if(isset($_GET['edit'])) {
    $edit_id = (int)$_GET['edit'];
    $stmt = $conn->prepare("SELECT admin_id, admin_name, phone_number, admin_type, created_date FROM admins WHERE admin_id = ?");
    $stmt->execute([$edit_id]);
    $edit_admin = $stmt->fetch(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>بەڕێوەبردنی ئەدمینەکان - کتێبخانەی ئاشتی</title>
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

        /* Edit Form Special Styling */
        .edit-form {
            background: #ffffff;
            border: 2px solid #c0c0c0;
            box-shadow: 0 6px 20px rgba(0,0,0,0.12);
            padding: 2.5rem;
            border-radius: 12px;
            margin-bottom: 3rem;
            position: relative;
        }

        .edit-form::before {
            content: '';
            position: absolute;
            top: -3px;
            left: -3px;
            right: -3px;
            height: 6px;
            background: linear-gradient(90deg, #c0c0c0, #2a2a2a, #c0c0c0);
            border-radius: 12px 12px 0 0;
        }

        .edit-form h2 {
            font-family: 'Playfair Display', serif;
            font-size: 1.6rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 2rem;
            text-align: center;
            position: relative;
            display: inline-block;
            width: 100%;
        }

        .edit-form h2::after {
            content: '';
            position: absolute;
            bottom: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 80px;
            height: 2px;
            background: #c0c0c0;
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

        .form-input, .form-select {
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

        .form-input:focus, .form-select:focus {
            outline: none;
            border-color: #c0c0c0;
            background: #ffffff;
            box-shadow: 0 0 0 3px rgba(192, 192, 192, 0.1);
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
            margin-left: 1rem;
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
            background: #666;
        }

        .cancel-btn:hover {
            background: #888;
        }

        /* Table Styles */
        .table-wrapper {
            overflow-x: auto;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            margin-top: 1rem;
        }

        .admins-table {
            width: 100%;
            border-collapse: collapse;
            background: #ffffff;
        }

        .admins-table th,
        .admins-table td {
            padding: 1rem;
            text-align: right;
            border-bottom: 1px solid #e5e5e5;
        }

        .admins-table th {
            background: #f8f8f8;
            font-weight: 600;
            color: #2a2a2a;
            border-bottom: 2px solid #e5e5e5;
        }

        .admins-table tr:hover {
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
            background: #2a2a2a;
            color: white;
        }

        .edit-btn:hover {
            background: #c0c0c0;
            transform: translateY(-1px);
        }

        .delete-btn {
            background: #e53e3e;
            color: white;
        }

        .delete-btn:hover {
            background: #c53030;
            transform: translateY(-1px);
        }

        /* Badges */
        .badge {
            padding: 0.3rem 0.6rem;
            border-radius: 3px;
            font-size: 0.8rem;
            font-weight: 500;
            margin-left: 0.3rem;
        }

        .badge-admin {
            background: #f0f8ff;
            color: #2a2a2a;
            border: 1px solid #c0c0c0;
        }

        .badge-super {
            background: #fff5f5;
            color: #e53e3e;
            border: 1px solid #fed7d7;
        }

        .badge-current {
            background: #f0fff4;
            color: #38a169;
            border: 1px solid #c6f6d5;
        }

        /* Info Section Styling */
        .info-box {
            background: #f8f8f8;
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
            border-left: 4px solid #c0c0c0;
        }

        .info-box h4 {
            color: #2a2a2a;
            margin-bottom: 1rem;
            font-family: 'Playfair Display', serif;
        }

        .info-box ul {
            list-style: none;
            padding: 0;
        }

        .info-box li {
            padding: 0.5rem 0;
            border-bottom: 1px solid #e5e5e5;
        }

        .info-box li:last-child {
            border-bottom: none;
        }

        .warning-box {
            background: #fffbeb;
            border-left: 4px solid #f59e0b;
            padding: 1.5rem;
            border-radius: 8px;
        }

        .warning-box h4 {
            color: #92400e;
            margin-bottom: 0.5rem;
        }

        .warning-box p {
            color: #92400e;
            font-size: 0.9rem;
        }

        /* Grid for Edit Form */
        .edit-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }

        /* Distribution Cards */
        .distribution-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .distribution-card {
            background: linear-gradient(135deg, #2a2a2a, #666);
            color: white;
            padding: 2rem;
            border-radius: 15px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .distribution-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: #c0c0c0;
        }

        .distribution-card.super {
            background: linear-gradient(135deg, #e53e3e, #c53030);
        }

        .distribution-card.super::before {
            background: #fff;
        }

        .distribution-card h3 {
            font-family: 'Playfair Display', serif;
            margin-bottom: 1rem;
        }

        .distribution-card .number {
            font-size: 3rem;
            font-weight: bold;
            margin: 1rem 0;
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

        /* Debug Info */
        .debug-info {
            background: #f0f0f0;
            padding: 1rem;
            border: 1px solid #ccc;
            margin-bottom: 1rem;
            font-family: monospace;
            font-size: 0.9rem;
            border-radius: 4px;
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
            
            .edit-grid {
                grid-template-columns: 1fr;
            }
            
            .container {
                padding: 1rem;
            }
            
            .section, .edit-form {
                padding: 1.5rem;
            }
            
            .form-button {
                width: 100%;
                margin: 0.5rem 0;
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
            
            .distribution-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <div class="header-content">
            <h1>بەڕێوەبردنی ئەدمینەکان</h1>
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

        <!-- Debug info - ئەم بەشە دوای چارەسەری کێشەکە بیسڕەوە -->
        <?php if(!empty($admins)): ?>
        <div class="debug-info">
            <strong>Debug - زانیاری یەکەم ئەدمین:</strong><br>
            ID: <?php echo $admins[0]['admin_id'] ?? 'نییە'; ?><br>
            Name: <?php echo $admins[0]['admin_name'] ?? 'نییە'; ?><br>
            Phone: <?php echo $admins[0]['phone_number'] ?? 'نییە'; ?><br>
            Type: <?php echo $admins[0]['admin_type'] ?? 'نییە'; ?><br>
            Date: <?php echo $admins[0]['created_date'] ?? 'نییە'; ?>
        </div>
        <?php endif; ?>

        <!-- ئاماری ئەدمینەکان -->
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number"><?php echo count($admins); ?></div>
                <div class="stat-label">کۆی ئەدمینەکان</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo count(array_filter($admins, function($a) { return $a['admin_type'] == 'گشتی'; })); ?></div>
                <div class="stat-label">ئەدمینی گشتی</div>
            </div>
            <div class="stat-card">
                <div class="stat-number"><?php echo count(array_filter($admins, function($a) { return $a['admin_type'] == 'ئاسایی'; })); ?></div>
                <div class="stat-label">ئەدمینی ئاسایی</div>
            </div>
        </div>

        <div class="decorative-border"></div>

        <!-- فۆرمی دەستکاریکردن -->
        <?php if($edit_admin): ?>
        <div class="edit-form">
            <h2>دەستکاریکردنی ئەدمین: <?php echo htmlspecialchars($edit_admin['admin_name']); ?></h2>
            <form method="POST">
                <input type="hidden" name="admin_id" value="<?php echo $edit_admin['admin_id']; ?>">
                
                <div class="edit-grid">
                    <div class="form-group">
                        <label class="form-label">ناوی تەواو</label>
                        <input type="text" name="name" class="form-input" value="<?php echo htmlspecialchars($edit_admin['admin_name']); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">ژمارە مۆبایل</label>
                        <input type="text" name="phone" class="form-input" value="<?php echo htmlspecialchars($edit_admin['phone_number']); ?>" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">جۆری ئەدمین</label>
                        <select name="admin_type" class="form-select" required>
                            <option value="گشتی" <?php echo ($edit_admin['admin_type'] == 'گشتی') ? 'selected' : ''; ?>>ئەدمینی گشتی</option>
                            <option value="ئاسایی" <?php echo ($edit_admin['admin_type'] == 'ئاسایی') ? 'selected' : ''; ?>>ئەدمینی ئاسایی</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">تێپەڕەوشەی نوێ (ئیختیاری)</label>
                        <input type="password" name="new_password" class="form-input" placeholder="تەنیا ئەگەر دەتەوێت بیگۆڕیت">
                    </div>
                </div>
                
                <div style="margin-top: 2rem; text-align: center;">
                    <button type="submit" name="update_admin" class="form-button">نوێکردنەوە</button>
                    <a href="manage_admins.php" class="form-button cancel-btn">هەڵوەشاندنەوە</a>
                </div>
            </form>
        </div>
        <?php endif; ?>

        <div class="sections-grid">
            <!-- زیادکردنی ئەدمینی نوێ -->
            <div class="section">
                <h2 class="section-title">زیادکردنی ئەدمینی نوێ</h2>
                <form method="POST">
                    <div class="form-group">
                        <label class="form-label">ناوی تەواو</label>
                        <input type="text" name="name" class="form-input" placeholder="ناوی تەواو بنوسە..." required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">ژمارە مۆبایل</label>
                        <input type="text" name="phone" class="form-input" placeholder="07xxxxxxxxx" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">جۆری ئەدمین</label>
                        <select name="admin_type" class="form-select" required>
                            <option value="">هەڵبژێرە...</option>
                            <option value="گشتی">ئەدمینی گشتی</option>
                            <option value="ئاسایی">ئەدمینی ئاسایی</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">تێپەڕەوشە</label>
                        <input type="password" name="password" class="form-input" placeholder="لانیکەم ٦ پیت" required>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">دووبارەکردنەوەی تێپەڕەوشە</label>
                        <input type="password" name="confirm_password" class="form-input" placeholder="تێپەڕەوشەکە دووبارە بکەرەوە" required>
                    </div>
                    
                    <button type="submit" name="add_admin" class="form-button" style="width: 100%;">زیادکردنی ئەدمین</button>
                </form>
            </div>

            <!-- زانیاری سیستەم -->
            <div class="section">
                <h2 class="section-title">زانیاری سیستەم</h2>
                <div class="info-box">
                    <h4>تایبەتمەندیەکانی ئەدمین:</h4>
                    <ul>
                        <li>
                            <strong>ئەدمینی گشتی:</strong>
                            <span style="color: #666;">هەموو دەسەڵاتەکان، سڕینەوەی کتێب و بەش، بەڕێوەبردنی ئەدمینەکان</span>
                        </li>
                        <li>
                            <strong>ئەدمینی ئاسایی:</strong>
                            <span style="color: #666;">زیادکردن و دەستکاریکردنی کتێب و بەش، بەڕێوەبردنی ناوەڕۆک</span>
                        </li>
                    </ul>
                </div>
                
                <div class="warning-box">
                    <h4>⚠️ ئاگاداری:</h4>
                    <p>
                        ناتوانیت خۆت بسڕیتەوە. دڵنیابە لە دروستکردنی ئەدمینی گشتی نوێ پێش سڕینەوەی ئەدمینی گشتی کۆن.
                    </p>
                </div>
            </div>
        </div>

        <!-- لیستی ئەدمینەکان -->
        <div class="section">
            <h2 class="section-title">لیستی ئەدمینەکان</h2>
            
            <div class="table-wrapper">
                <table class="admins-table">
                    <thead>
                        <tr>
                            <th>ناوی تەواو</th>
                            <th>ژمارە مۆبایل</th>
                            <th>جۆری ئەدمین</th>
                            <th>بەرواری دروستکردن</th>
                            <th>کردارەکان</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php if(empty($admins)): ?>
                        <tr>
                            <td colspan="5" style="text-align: center; color: #666; padding: 2rem;">
                                هیچ ئەدمینێک نەدۆزرایەوە
                            </td>
                        </tr>
                        <?php else: ?>
                        <?php foreach($admins as $admin): ?>
                        <tr>
                            <td>
                                <strong><?php echo htmlspecialchars($admin['admin_name'] ?? 'ناو نەگیراوە'); ?></strong>
                                <?php if($admin['admin_id'] == $_SESSION['admin_id']): ?>
                                <span class="badge badge-current">تۆ</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo htmlspecialchars($admin['phone_number'] ?? 'نییە'); ?></td>
                            <td>
                                <?php if(($admin['admin_type'] ?? '') == 'گشتی'): ?>
                                <span class="badge badge-super">ئەدمینی گشتی</span>
                                <?php else: ?>
                                <span class="badge badge-admin">ئەدمینی ئاسایی</span>
                                <?php endif; ?>
                            </td>
                            <td><?php echo date('Y/m/d H:i', strtotime($admin['created_date'] ?? 'now')); ?></td>
                            <td>
                                <a href="?edit=<?php echo $admin['admin_id']; ?>" class="action-btn edit-btn">دەستکاری</a>
                                <?php if($admin['admin_id'] != $_SESSION['admin_id']): ?>
                                <a href="?delete=<?php echo $admin['admin_id']; ?>" 
                                   class="action-btn delete-btn" 
                                   onclick="return confirm('دڵنیایت لە سڕینەوەی ئەم ئەدمینە؟\n\nناو: <?php echo htmlspecialchars($admin['admin_name'] ?? 'نامەلوم'); ?>\nجۆر: <?php echo htmlspecialchars($admin['admin_type'] ?? 'نامەلوم'); ?>')">سڕینەوە</a>
                                <?php else: ?>
                                <span style="color: #888; font-size: 0.9rem;">ناتوانیت خۆت بسڕیتەوە</span>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>

        <!-- دابەشکردنی ئەدمینەکان -->
        <div class="section">
            <h2 class="section-title">دابەشکردنی ئەدمینەکان</h2>
            <div class="distribution-grid">
                <div class="distribution-card super">
                    <h3>ئەدمینی گشتی</h3>
                    <div class="number">
                        <?php echo count(array_filter($admins, function($a) { return ($a['admin_type'] ?? '') == 'گشتی'; })); ?>
                    </div>
                    <p>تەواوی دەسەڵاتەکان</p>
                </div>
                
                <div class="distribution-card">
                    <h3>ئەدمینی ئاسایی</h3>
                    <div class="number">
                        <?php echo count(array_filter($admins, function($a) { return ($a['admin_type'] ?? '') == 'ئاسایی'; })); ?>
                    </div>
                    <p>دەسەڵاتی سنووردار</p>
                </div>
            </div>
        </div>
    </div>

    <!-- Text Particle Effect Footer -->
    <div class="developer-footer" id="developerFooter">
        <div class="developer-credit">
            <a href="https://www.instagram.com/i_xoshnawm/" target="_blank" class="developer-link" id="devLink">@i_xoshnawm</a>
            <span class="dev-text" id="devText">website is developed by</span>
            <div class="tech-symbol" id="techSymbol"></div>
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

        .particle {
            position: absolute;
            pointer-events: none;
            z-index: 5;
            font-family: 'Playfair Display', serif;
            font-weight: 600;
            opacity: 0;
        }

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
    </style>

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

        const kurdishChars = ['ئ', 'ا', 'ش', 'ت', 'ی', 'ک', 'و', 'ر', 'د', 'ن'];
        const bookWords = ['کتێب', 'ڕۆمان', 'شعر', 'چیرۆک'];
        const techChars = ['<', '>', '/', '{', '}', '(', ')', '*'];

        function startAutoParticles() {
            setInterval(() => {
                const element = document.getElementById('devLink');
                const rect = element.getBoundingClientRect();
                const footerRect = document.getElementById('developerFooter').getBoundingClientRect();
                
                const char = kurdishChars[Math.floor(Math.random() * kurdishChars.length)];
                const x = rect.left - footerRect.left + Math.random() * rect.width;
                const y = rect.top - footerRect.top + Math.random() * rect.height;
                createParticle(element, char, x, y);
            }, 800);

            setInterval(() => {
                const element = document.getElementById('devText');
                const rect = element.getBoundingClientRect();
                const footerRect = document.getElementById('developerFooter').getBoundingClientRect();
                
                const word = bookWords[Math.floor(Math.random() * bookWords.length)];
                const x = rect.left - footerRect.left + Math.random() * rect.width;
                const y = rect.top - footerRect.top + Math.random() * rect.height;
                createParticle(element, word, x, y);
            }, 1200);

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

        window.addEventListener('load', startAutoParticles);

        // Form validation
        document.querySelectorAll('form').forEach(form => {
            form.addEventListener('submit', function(e) {
                const password = this.password ? this.password.value : '';
                const confirmPassword = this.confirm_password ? this.confirm_password.value : '';
                
                if (password && confirmPassword && password !== confirmPassword) {
                    e.preventDefault();
                    alert('تێپەڕەوشەکان یەکسان نین');
                    return;
                }
                
                if (password && password.length < 6) {
                    e.preventDefault();
                    alert('تێپەڕەوشە دەبێت لانیکەم ٦ پیت بێت');
                    return;
                }
            });
        });

        // Add loading state for form submission
        document.querySelectorAll('.form-button[type="submit"]').forEach(button => {
            button.addEventListener('click', function() {
                setTimeout(() => {
                    this.textContent = 'چاوەڕوان بە...';
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

        // Confirm delete with more details
        document.querySelectorAll('.delete-btn').forEach(btn => {
            btn.addEventListener('click', function(e) {
                const confirmText = this.getAttribute('onclick');
                if (confirmText && !confirmText.includes('confirm(')) {
                    return true; // Let the onclick handle it
                }
                
                const href = this.getAttribute('href');
                const adminId = href.match(/delete=(\d+)/)?.[1];
                
                if (!confirm('دڵنیایت لە سڕینەوەی ئەم ئەدمینە؟\n\n⚠️ ئەم کردارە ناگەڕێنرێتەوە!')) {
                    e.preventDefault();
                }
            });
        });
    </script>
</body>
</html>