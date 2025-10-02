<?php
require_once 'config.php';

if(!isset($_GET['id']) || empty($_GET['id'])) {
    header("Location: index.php");
    exit();
}

$book_id = (int)$_GET['id'];

// زیادکردنی ژمارەی بینین
$stmt = $conn->prepare("UPDATE books SET view_count = view_count + 1 WHERE book_id = ?");
$stmt->execute([$book_id]);

// وەرگرتنی زانیاری کتێب
$stmt = $conn->prepare("SELECT b.*, c.category_name FROM books b 
                       LEFT JOIN categories c ON b.category_id = c.category_id 
                       WHERE b.book_id = ?");
$stmt->execute([$book_id]);
$book = $stmt->fetch(PDO::FETCH_ASSOC);

if(!$book) {
    header("Location: index.php");
    exit();
}

// وەرگرتنی کتێبە هاوتاکان لە هەمان بەش
$related_stmt = $conn->prepare("SELECT b.*, c.category_name FROM books b 
                               LEFT JOIN categories c ON b.category_id = c.category_id 
                               WHERE b.category_id = ? AND b.book_id != ? 
                               ORDER BY b.created_date DESC LIMIT 6");
$related_stmt->execute([$book['category_id'], $book_id]);
$related_books = $related_stmt->fetchAll(PDO::FETCH_ASSOC);
?>

<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $book['book_title']; ?> - کتێبخانەی ئاشتی</title>
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

        /* Header Styles (Unified) */
        .header {
            background: linear-gradient(to bottom, #f8f8f8 0%, #ffffff 100%);
            border-bottom: 3px solid #c0c0c0;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
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
        .brand-text { display: flex; flex-direction: column; gap: 0.2rem; }
        .brand-title { font-family: 'Playfair Display', serif; font-size: 1.8rem; font-weight: 700; color: #2a2a2a; }
        .brand-quote { color: #666; font-size: 0.95rem; }
        .brand-slogan { color: #777; font-size: 0.9rem; }
        .header-bottom { padding: 0.4rem 0 0.9rem; border-top: 1px solid #e5e5e5; }
        .nav-menu { display: flex; gap: 1rem; align-items: center; }
        .nav-link { color: #555; text-decoration: none; font-weight: 500; padding: 0.5rem 1rem; border: 1px solid transparent; transition: all 0.2s ease; border-radius: 4px; }
        .nav-link:hover, .nav-link.active { color: #2a2a2a; border-color: #c0c0c0; background: #f8f8f8; }

        /* Hero Section */
        .hero {
            background: linear-gradient(135deg, #ffffff 0%, #f5f5f5 100%);
            padding: 4rem 0;
            text-align: center;
            border-bottom: 1px solid #e0e0e0;
        }

        .hero-content {
            max-width: 800px;
            margin: 0 auto;
            padding: 0 2rem;
        }

        .hero h2 {
            font-family: 'Playfair Display', serif;
            font-size: 2.8rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 1.5rem;
            line-height: 1.3;
        }

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

        /* Container */
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 2rem;
        }

        /* Book Details Section */
        .book-details-section {
            margin: 4rem 0;
            padding: 3rem 0;
        }

        .book-details {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            padding: 3rem;
            margin: 4rem 0;
            border-radius: 8px;
        }

        .book-main {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 3rem;
            margin-bottom: 3rem;
        }

        .book-image-container {
            text-align: center;
        }

        .book-image {
            width: 70%;
            max-width: 280px;
            height: 420px;
            min-height: 200px; /* زۆرینەی کەمی بەرزی */
            background: linear-gradient(135deg, #f8f8f8 0%, #eeeeee 100%);
            border: 1px solid #e5e5e5;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #999;
            font-size: 1.1rem;
            font-weight: 500;
            position: relative;
            overflow: hidden;
            margin: 0 auto 1.5rem;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
        }

        .book-image::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 70px;
            height: 100px;
            border: 2px solid #c0c0c0;
            border-radius: 4px;
            background: #ffffff;
            z-index: 0;
        }

        .book-image img {
            width: 100%;
            height: 100%;
            object-fit: contain; /* وێنەکە بە تەواوی نیشان دەدرێت */
            position: relative;
            z-index: 1;
            background: #ffffff; /* پاشخانەی سپی */
        }

        .book-info {
            padding: 1rem 0;
        }

        .book-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 2rem;
            color: #2a2a2a;
            line-height: 1.2;
        }

        .book-meta {
            margin-bottom: 3rem;
        }

        .meta-item {
            display: flex;
            margin-bottom: 1.5rem;
            align-items: flex-start;
            padding: 1rem 0;
            border-bottom: 1px solid #f0f0f0;
        }

        .meta-label {
            font-weight: 600;
            color: #2a2a2a;
            width: 140px;
            flex-shrink: 0;
            font-size: 1rem;
        }

        .meta-value {
            font-size: 1.1rem;
            color: #555;
            font-weight: 500;
        }

        .book-genre-badge {
            background: #f0f0f0;
            color: #555;
            padding: 0.5rem 1rem;
            font-size: 0.9rem;
            display: inline-block;
            border: 1px solid #e0e0e0;
            font-weight: 500;
        }

        .book-price {
            font-size: 1.5rem;
            font-weight: 700;
            color: #2a2a2a;
            background: #f8f8f8;
            padding: 1.5rem;
            text-align: center;
            border: 1px solid #e5e5e5;
            border-left: 4px solid #c0c0c0;
            margin-top: 1.5rem;
            border-radius: 8px;
        }

        /* Description */
        .book-description {
            background: #ffffff;
            padding: 2.5rem;
            border: 1px solid #e5e5e5;
            margin-top: 2rem;
            border-left: 4px solid #c0c0c0;
            border-radius: 8px;
        }

        /* Section Styles */
        .section {
            margin: 4rem 0;
            padding: 3rem 0;
        }

        .section-header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .section-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 1rem;
            position: relative;
            display: inline-block;
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

        .section-subtitle {
            color: #666;
            font-size: 1.1rem;
            font-style: italic;
        }

        /* Books Grid */
        .books-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
            margin-top: 2rem;
        }

        .book-card {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            overflow: hidden;
            cursor: pointer;
            border-radius: 8px;
            text-decoration: none;
            color: inherit;
        }

        .book-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
            border-color: #c0c0c0;
        }

        .book-card .book-image {
            width: 100%;
            max-width: none;
            height: 300px;
            margin: 0 0 0 0;
            border-radius: 0;
            box-shadow: none;
        }

        .book-info {
            padding: 1.5rem;
        }

        .book-title {
            font-family: 'Playfair Display', serif;
            font-size: 1.2rem;
            font-weight: 600;
            margin-bottom: 0.8rem;
            color: #2a2a2a;
            line-height: 1.4;
            min-height: 2.8rem;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .book-author {
            color: #666;
            font-size: 0.9rem;
            margin-bottom: 0.8rem;
            font-style: italic;
        }

        .book-genre {
            background: #f0f0f0;
            color: #555;
            padding: 0.3rem 0.6rem;
            font-size: 0.8rem;
            display: inline-block;
            margin-bottom: 1rem;
            border: 1px solid #e0e0e0;
            font-weight: 500;
            border-radius: 3px;
        }

        .book-card .book-price {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2a2a2a;
            text-align: left;
            border-top: 1px solid #e5e5e5;
            padding: 1rem 0 0 0;
            margin: 0;
            background: transparent;
            border-left: none;
            border-radius: 0;
        }

        .description-title {
            font-family: 'Playfair Display', serif;
            font-size: 1.8rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 2rem;
            position: relative;
            display: inline-block;
        }

        .description-title::after {
            content: '';
            position: absolute;
            bottom: -8px;
            left: 0;
            width: 60px;
            height: 1px;
            background: #c0c0c0;
        }

        .description-text {
            font-size: 1.2rem; /* سایزی ئەسڵی بۆ کۆمپیوتەر */
            line-height: 1.8;
            color: #555;
            font-weight: 400;
        }

        /* Stats */
        .book-stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-top: 3rem;
        }

        .stat-card {
            background: #f8f8f8;
            padding: 2rem;
            text-align: center;
            border: 1px solid #e5e5e5;
            border-top: 3px solid #c0c0c0;
        }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: #2a2a2a;
        }

        .stat-label {
            color: #666;
            margin-top: 1rem;
            font-size: 1rem;
            font-weight: 500;
        }

        /* Location Section */
        .location-section {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            margin: 4rem 0;
        }

        .location-content {
            padding: 3rem;
        }

        .section-header {
            text-align: center;
            margin-bottom: 3rem;
        }

        .section-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 1rem;
            position: relative;
            display: inline-block;
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

        .section-subtitle {
            color: #666;
            font-size: 1.1rem;
            font-style: italic;
        }

        .map-container {
            width: 100%;
            height: 400px;
            margin-bottom: 2rem;
            border: 1px solid #e5e5e5;
            overflow: hidden;
        }

        .map-container iframe {
            width: 100%;
            height: 100%;
            border: none;
        }

        .location-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 2rem;
        }

        .info-card {
            background: #f8f8f8;
            padding: 1.5rem;
            border: 1px solid #e5e5e5;
            border-right: 4px solid #c0c0c0;
            border-radius: 8px;
        }

        .info-card h3 {
            color: #2a2a2a;
            margin-bottom: 0.8rem;
            font-size: 1.2rem;
            font-weight: 600;
        }

        .info-card p {
            color: #555;
            font-size: 1rem;
            line-height: 1.5;
        }

        /* Footer */
        .footer {
            background: linear-gradient(to bottom, #f5f5f5 0%, #eeeeee 100%);
            border-top: 2px solid #c0c0c0;
            padding: 3rem 0 2rem;
            text-align: center;
            margin-top: 4rem;
        }

        .footer h3 {
            font-family: 'Playfair Display', serif;
            margin-bottom: 1.5rem;
            font-size: 1.5rem;
            font-weight: 600;
            color: #2a2a2a;
        }

        .social-links {
            display: flex;
            justify-content: center;
            gap: 1rem;
            margin: 1.5rem 0;
            flex-wrap: wrap;
        }

        .social-links a {
            color: #555;
            text-decoration: none;
            padding: 0.8rem 1.5rem;
            background: #ffffff;
            font-weight: 500;
            transition: all 0.3s ease;
            border: 1px solid #e0e0e0;
        }

        .social-links a:hover {
            background: #c0c0c0;
            color: #ffffff;
            border-color: #c0c0c0;
            transform: translateY(-2px);
        }

        .footer p {
            margin-top: 2rem;
            color: #666;
            font-size: 0.9rem;
        }
        /* Responsive Design */
        @media (max-width: 768px) {
            .header-top { flex-direction: column; gap: 1rem; text-align: center; }
            .nav-menu { flex-wrap: wrap; justify-content: center; }
            
            .book-main {
                grid-template-columns: 1fr; /* یەک ستوون بۆ مۆبایل */
                gap: 2rem;
                text-align: center; /* ناوەندی کردن */
            }
            
            .book-image {
                width: 80%; /* زیاتر پان بۆ مۆبایل */
                height: 280px; /* کەمتر بەرزی */
                margin: 0 auto; /* ناوەندی کردن */
            }
            
            .book-details {
                padding: 2rem;
            }
            
            .book-title {
                font-size: 1.4rem; /* فۆنتی بچووکتر بۆ مۆبایل */
            }
            
            .description-text {
                font-size: 0.9rem; /* بچووکتر بۆ مۆبایل */
            }
            
            .books-grid {
                grid-template-columns: repeat(2, 1fr); /* دوو ستوون بۆ مۆبایل */
                gap: 1rem;
            }
            
            .book-card .book-image {
                height: 200px; /* کەمتر بەرزی بۆ مۆبایل */
            }
            
            .book-card .book-info {
                padding: 1rem; /* کەمتر padding */
            }
            
            .book-card .book-title {
                font-size: 0.9rem; /* فۆنتی بچووکتر */
            }
            
            .book-card .book-author {
                font-size: 0.8rem;
            }
            
            .book-card .book-price {
                font-size: 1rem;
            }
            
            .hero h2 {
                font-size: 2.2rem;
            }
            
            .social-links {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            .book-details,
            .location-content {
                padding: 2rem;
            }
        }

        /* Subtle Animations */
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

        .book-details-section {
            animation: fadeInUp 0.6s ease-out;
        }

        .location-section {
            animation: fadeInUp 0.6s ease-out;
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

        /* Add this with the other CSS styles */
        .phone-number {
            direction: ltr;
            display: inline-block;
            unicode-bidi: bidi-override;
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
                    <a href="chatbot.php" class="nav-link">چات بۆت</a>
                </nav>
            </div>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero">
        <div class="hero-content">
            <h2><?php echo htmlspecialchars($book['book_title']); ?></h2>
            <p>نوسەر: <?php echo htmlspecialchars($book['author']); ?> • بەش: <?php echo htmlspecialchars($book['category_name']); ?></p>
            <div class="decorative-border"></div>
        </div>
    </section>

    <div class="container">
        <div class="book-details">
            <div class="book-main">
                <div class="book-image-container">
                    <div class="book-image">
                        <?php if($book['book_image'] && $book['book_image'] != 'default_book.jpg'): ?>
                            <img src="images/<?php echo $book['book_image']; ?>" alt="<?php echo $book['book_title']; ?>">
                        <?php else: ?>
                            <span style="position: relative; z-index: 2;">وێنەی کتێب</span>
                        <?php endif; ?>
                    </div>
                </div>

                <div class="book-info">
                    <h1 class="book-title"><?php echo $book['book_title']; ?></h1>
                    
                    <div class="book-meta">
                        <div class="meta-item">
                            <span class="meta-label">نوسەر:</span>
                            <span class="meta-value"><?php echo $book['author']; ?></span>
                        </div>
                        
                        <?php if($book['translator']): ?>
                        <div class="meta-item">
                            <span class="meta-label">وەرگێڕ:</span>
                            <span class="meta-value"><?php echo $book['translator']; ?></span>
                        </div>
                        <?php endif; ?>
                        
                        <div class="meta-item">
                            <span class="meta-label">بەش:</span>
                            <span class="book-genre-badge"><?php echo $book['category_name']; ?></span>
                        </div>
                    </div>
                    
                    <div class="book-price">
                        نرخ: <?php echo number_format($book['price']); ?> دینار
                    </div>
                    
                    <!-- WhatsApp Order Button -->
                    <div style="margin-top: 1.5rem; text-align: center;">
                        <a href="https://wa.me/9647503866000?text=<?php echo urlencode('سڵاو، سەبارەت بە کتێبی: ' . $book['book_title'] . ' - نرخ: ' . number_format($book['price']) . '  دینار'.'  دەمەوێت داوای بکەم  '); ?>" 
                           target="_blank" 
                           style="display: inline-block; background: #2a2a2a; color: white; padding: 0.8rem 1.5rem; text-decoration: none; border-radius: 8px; font-weight: 600; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(42, 42, 42, 0.3);" 
                           onmouseover="this.style.background='#1f1f1f'; this.style.transform='translateY(-2px)';" 
                           onmouseout="this.style.background='#2a2a2a'; this.style.transform='translateY(0)';">
                            داواکردن لە واتساپ
                        </a>
                    </div>
                </div>
            </div>
            
            <?php if($book['description']): ?>
            <div class="book-description">
                <h3 class="description-title">پێشەکی</h3>
                <div class="description-text">
                    <?php echo nl2br(htmlspecialchars($book['description'])); ?>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="book-stats">
                <div class="stat-card">
                    <div class="stat-number"><?php echo number_format($book['view_count']); ?></div>
                    <div class="stat-label">جار بینراوە</div>
                </div>
            </div>
        </div>
    </div>

    <?php if (!empty($related_books)): ?>
    <!-- Related Books Section -->
    <section class="section">
        <div class="container">
            <div class="section-header">
                <h2 class="section-title">کتێبی هاوتا</h2>
                <p class="section-subtitle">کتێبەکانی تری بەشی <?php echo htmlspecialchars($book['category_name']); ?></p>
            </div>
            <div class="books-grid">
                <?php foreach($related_books as $related_book): ?>
                    <a href="book_details.php?id=<?php echo (int)$related_book['book_id']; ?>" class="book-card">
                        <div class="book-image">
                            <?php if($related_book['book_image'] && $related_book['book_image'] != 'default_book.jpg'): ?>
                                <img src="images/<?php echo htmlspecialchars($related_book['book_image']); ?>" alt="<?php echo htmlspecialchars($related_book['book_title']); ?>">
                            <?php else: ?>
                                وێنەی کتێب
                            <?php endif; ?>
                        </div>
                        <div class="book-info">
                            <div class="book-title"><?php echo htmlspecialchars($related_book['book_title']); ?></div>
                            <div class="book-author"><?php echo htmlspecialchars($related_book['author']); ?></div>
                            <div class="book-genre"><?php echo htmlspecialchars($related_book['category_name']); ?></div>
                            <div class="book-price"><?php echo number_format($related_book['price']); ?> دینار</div>
                        </div>
                    </a>
                <?php endforeach; ?>
            </div>
        </div>
    </section>
    <?php endif; ?>
    
    <!-- Location Section -->
    <section class="location-section">
        <div class="container">
            <div class="location-content">
                <div class="section-header">
                    <h2 class="section-title">شوێنی کتێبخانە</h2>
                    <p class="section-subtitle">سەردانی کتێبخانەکەمان بکەن</p>
                </div>
                <div class="map-container">
                    <iframe 
                        src="https://maps.google.com/maps?q=36.18488173185077,44.012086439214336&hl=en&z=14&output=embed"
                        allowfullscreen 
                        loading="lazy">
                    </iframe>
                </div>
                <div class="location-grid">
                    <div class="info-card">
                        <h3>ناونیشان</h3>
                        <p>هەولێر - داونتاون نهۆمی دووەم </p>
                    </div>
                    <div class="info-card">
                        <h3>کاتژمێرەکانی کارکردن</h3>
                        <p>هەموو ڕۆژێک: ٩:٠٠ بەیانی - ٨:٠٠ ئێوارە</p>
                    </div>
                    <div class="info-card">
                        <h3>پەیوەندی</h3>
                        <p dir="ltr">+964 750 386 6000</p>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <!-- Footer -->
    <footer class="footer">
        <div class="container">
            <h3>پەیوەندیمان پێوە بکەن</h3>
            <div class="social-links">
                <a href="https://maps.app.goo.gl/qwt2qHbjN68D7TTdA" target="_blank" aria-label="Google Maps">
                    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 2C8.134 2 5 5.134 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.866-3.134-7-7-7zm0 10.5a3.5 3.5 0 110-7 3.5 3.5 0 010 7z"/></svg>
                    <span>Google Maps</span>
                </a>
                <a href="https://www.facebook.com/ktebxany.ashti" target="_blank" aria-label="Facebook">
                    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M22 12a10 10 0 10-11.562 9.874v-6.987H7.898V12h2.54V9.797c0-2.506 1.492-3.89 3.777-3.89 1.094 0 2.238.195 2.238.195v2.46h-1.26c-1.243 0-1.63.771-1.63 1.562V12h2.773l-.443 2.887h-2.33v6.987A10.002 10.002 0 0022 12z"/></svg>
                    <span>Facebook</span>
                </a>
                <a href="https://t.me/ktebxanai1ashti" target="_blank" aria-label="Telegram">
                    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21.5 3.5l-19 7a1 1 0 00.05 1.9l5.27 1.7 2.01 6.37a1 1 0 001.74.34l2.9-2.82 5.03 3.7a1 1 0 001.57-.63l3.38-15.1a1 1 0 00-1.95-.46L9 13l10.2-8.1-7.6 9.5"/></svg>
                    <span>Telegram</span>
                </a>
                <a href="https://wa.me/9647503866000" target="_blank" aria-label="WhatsApp">
                    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M20.52 3.48A11.5 11.5 0 003.48 20.52L2 22l1.48-1.48A11.5 11.5 0 1020.52 3.48zM12 5a7 7 0 00-7 7c0 1.27.33 2.46.92 3.49l-.58 2.14 2.2-.58A7 7 0 1012 5zm3.45 9.39c-.18.5-1.05.93-1.5.95-.4.02-.9.03-2.45-.77-2.06-1.06-3.38-3.06-3.48-3.2-.1-.14-.83-1.1-.83-2.1s.53-1.49.72-1.7c.18-.2.47-.3.62-.3h.45c.14 0 .34-.05.53.4.2.5.68 1.73.73 1.85.06.12.1.27.02.43-.08.16-.12.27-.24.41-.12.14-.26.31-.37.42-.12.12-.25.25-.11.49.14.24.63 1.04 1.36 1.68.94.83 1.73 1.09 1.97 1.22.24.12.39.1.53-.05.14-.16.6-.7.76-.95.16-.24.32-.2.53-.12.22.08 1.38.65 1.61.77.24.12.4.18.46.28.07.1.07.58-.11 1.08z"/></svg>
                    <span>WhatsApp</span>
                </a>
                <a href="https://www.instagram.com/ktebxanay.ashti/" target="_blank" aria-label="Instagram">
                    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 2h10a5 5 0 015 5v10a5 5 0 01-5 5H7a5 5 0 01-5-5V7a5 5 0 015-5zm0 2a3 3 0 00-3 3v10a3 3 0 003 3h10a3 3 0 003-3V7a3 3 0 00-3-3H7zm5 3.5a5.5 5.5 0 110 11 5.5 5.5 0 010-11zm6-1.5a1.5 1.5 0 110 3 1.5 1.5 0 010-3z"/></svg>
                    <span>Instagram</span>
                </a>
            </div>
            <style>
                .social-links { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-top: 1rem; }
                .social-links a { display: inline-flex; align-items: center; gap: 0.5rem; color: #2a2a2a; text-decoration: none; padding: 0.5rem 0.8rem; border: 1px solid #e0e0e0; border-radius: 8px; transition: all 0.2s ease; background: #fff; }
                .social-links a:hover { background: #2a2a2a; color: #ffffff; border-color: #2a2a2a; }
                .social-links svg { width: 20px; height: 20px; display: block; }
                @media (max-width: 768px) { .social-links { justify-content: center; } }
            </style>
        </div>
    </footer>
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
            .book-image {
                width: 90%; /* زیاتر پان بۆ مۆبایلی بچووک */
                height: 240px; /* کەمتر بەرزی */
                max-width: 200px; /* زۆرینە پانی */
            }
            
            .book-title {
                font-size: 1.2rem; /* فۆنتی زۆر بچووک بۆ مۆبایلی بچووک */
            }
            
            .description-text {
                font-size: 0.8rem; /* زۆر بچووک بۆ مۆبایلی بچووک */
            }
            
            .books-grid {
                grid-template-columns: repeat(2, 1fr); /* دوو ستوون بۆ مۆبایلی بچووکیش */
                gap: 0.8rem;
            }
            
            .book-card .book-image {
                height: 160px; /* زۆر کەمتر بۆ مۆبایلی بچووک */
            }
            
            .book-card .book-info {
                padding: 0.8rem;
            }
            
            .book-card .book-title {
                font-size: 0.8rem;
            }
            
            .book-card .book-author {
                font-size: 0.7rem;
            }
            
            .book-card .book-price {
                font-size: 0.9rem;
            }
            
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
 <!-- Duplicate body tag removed to keep valid HTML structure -->
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
        // Add smooth scroll behavior
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                document.querySelector(this.getAttribute('href')).scrollIntoView({
                    behavior: 'smooth'
                });
            });
        });

        // Add loading animation
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