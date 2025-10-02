<?php
require_once 'config.php';

$error_message = '';
$success_message = '';

// چەکردنی ئەگەر ئەدمین چووەتە ژوورەوە
if(isset($_SESSION['admin_id'])) {
    header("Location: admin_dashboard.php");
    exit();
}

// پرۆسێسی چوونەژوورەوە
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['login'])) {
    $phone = isset($_POST['phone']) ? clean_input($_POST['phone']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    
    if(empty($phone) || empty($password)) {
        $error_message = "تکایە هەموو خانەکان پڕبکەرەوە";
    } else {
        $stmt = $conn->prepare("SELECT * FROM admins WHERE phone_number = ? AND password = MD5(?)");
        $stmt->execute([$phone, $password]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if($admin) {
            $_SESSION['admin_id'] = $admin['admin_id'];
            $_SESSION['admin_name'] = $admin['admin_name'];
            $_SESSION['admin_type'] = $admin['admin_type'];
            header("Location: admin_dashboard.php");
            exit();
        } else {
            $error_message = "ژمارە مۆبایل یان تێپەڕەوشە هەڵەیە";
        }
    }
}

// پرۆسێسی دروستکردنی ئەکاونتی نوێ (تەنیا بۆ ئەدمینی گشتی)
if($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['register'])) {
    $name = isset($_POST['name']) ? clean_input($_POST['name']) : '';
    $phone = isset($_POST['phone']) ? clean_input($_POST['phone']) : '';
    $password = isset($_POST['password']) ? $_POST['password'] : '';
    $confirm_password = isset($_POST['confirm_password']) ? $_POST['confirm_password'] : '';
    $admin_type = isset($_POST['admin_type']) ? clean_input($_POST['admin_type']) : '';
    
    if(empty($name) || empty($phone) || empty($password) || empty($confirm_password) || empty($admin_type)) {
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
            $stmt = $conn->prepare("INSERT INTO admins (admin_name, phone_number, password, admin_type) VALUES (?, ?, MD5(?), ?)");
            if($stmt->execute([$name, $phone, $password, $admin_type])) {
                $success_message = "ئەکاونت بە سەرکەوتوویی دروست کرا";
            } else {
                $error_message = "هەڵەیەک ڕووی دا لە دروستکردنی ئەکاونت";
            }
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
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Tahoma', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #2c3e50;
            direction: rtl;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .admin-container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            overflow: hidden;
            width: 100%;
            max-width: 900px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            min-height: 600px;
        }

        .login-side, .register-side {
            padding: 3rem;
            display: flex;
            flex-direction: column;
            justify-content: center;
        }

        .login-side {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        }

        .register-side {
            background: linear-gradient(135deg, #ffecd2 0%, #fcb69f 100%);
        }

        .form-title {
            font-size: 2rem;
            font-weight: bold;
            margin-bottom: 2rem;
            text-align: center;
            color: #2c3e50;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: bold;
            color: #34495e;
        }

        .form-input {
            width: 100%;
            padding: 1rem;
            border: 2px solid #ecf0f1;
            border-radius: 10px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
            direction: rtl;
        }

        .form-input:focus {
            outline: none;
            border-color: #3498db;
        }

        .form-select {
            width: 100%;
            padding: 1rem;
            border: 2px solid #ecf0f1;
            border-radius: 10px;
            font-size: 1rem;
            background: white;
            direction: rtl;
        }

        .form-button {
            width: 100%;
            padding: 1rem;
            background: linear-gradient(45deg, #3498db, #2980b9);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1.1rem;
            font-weight: bold;
            cursor: pointer;
            transition: transform 0.3s ease;
        }

        .form-button:hover {
            transform: translateY(-2px);
        }

        .register-button {
            background: linear-gradient(45deg, #e74c3c, #c0392b);
        }

        .error-message {
            background: #e74c3c;
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            text-align: center;
        }

        .success-message {
            background: #27ae60;
            color: white;
            padding: 1rem;
            border-radius: 10px;
            margin-bottom: 1rem;
            text-align: center;
        }

        .back-link {
            text-align: center;
            margin-top: 2rem;
        }

        .back-link a {
            color: #3498db;
            text-decoration: none;
            font-weight: bold;
        }

        .back-link a:hover {
            text-decoration: underline;
        }

        @media (max-width: 768px) {
            .admin-container {
                grid-template-columns: 1fr;
                margin: 1rem;
            }
            
            .login-side, .register-side {
                padding: 2rem;
            }
        }
    </style>
</head>
<body>
    <div class="admin-container">
        <!-- بەشی چوونەژوورەوە -->
        <div class="login-side">
            <h2 class="form-title">چوونەژوورەوەی ئەدمین</h2>
            
            <?php if($error_message && isset($_POST['login'])): ?>
                <div class="error-message"><?php echo $error_message; ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label class="form-label">ژمارە مۆبایل</label>
                    <input type="text" name="phone" class="form-input" placeholder="07xxxxxxxxx" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">تێپەڕەوشە</label>
                    <input type="password" name="password" class="form-input" placeholder="تێپەڕەوشەکەت بنوسە" required>
                </div>
                
                <button type="submit" name="login" class="form-button">چوونەژوورەوە</button>
            </form>
            
            <div class="back-link">
                <a href="index.php">گەڕانەوە بۆ ماڵپەڕ</a>
            </div>
        </div>

        <!-- بەشی دروستکردنی ئەکاونتی نوێ -->
        <div class="register-side">
            <h2 class="form-title">دروستکردنی ئەکاونتی نوێ</h2>
            
            <?php if($error_message && isset($_POST['register'])): ?>
                <div class="error-message"><?php echo $error_message; ?></div>
            <?php endif; ?>
            
            <?php if($success_message): ?>
                <div class="success-message"><?php echo $success_message; ?></div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label class="form-label">ناوی تەواو</label>
                    <input type="text" name="name" class="form-input" placeholder="ناوی تەواوت بنوسە" required>
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
                
                <button type="submit" name="register" class="form-button register-button">دروستکردنی ئەکاونت</button>
            </form>
        </div>
    </div>
</body>
</html>