<?php
require_once 'config.php';

// Debug: چەکردنی ئەوەی داتا هەیە یان نا
echo "<!-- Debug Info -->";
echo "<!-- Checking bestseller books: -->";
$debug_stmt = $conn->prepare("SELECT COUNT(*) as count FROM books WHERE is_bestseller = 1");
$debug_stmt->execute();
$bestseller_count = $debug_stmt->fetch(PDO::FETCH_ASSOC);
echo "<!-- Bestseller count: " . $bestseller_count['count'] . " -->";

echo "<!-- Checking featured books: -->";
$debug_stmt = $conn->prepare("SELECT COUNT(*) as count FROM books WHERE is_featured = 1");
$debug_stmt->execute();
$featured_count = $debug_stmt->fetch(PDO::FETCH_ASSOC);
echo "<!-- Featured count: " . $featured_count['count'] . " -->";

// وەرگرتنی نوێترین کتێبەکان - گۆڕدرا بۆ ١٣ کتێب
$stmt = $conn->prepare("SELECT b.*, c.category_name 
                       FROM books b 
                       LEFT JOIN categories c ON b.category_id = c.category_id 
                       ORDER BY b.created_date DESC LIMIT 13");
$stmt->execute();
$latest_books = $stmt->fetchAll(PDO::FETCH_ASSOC);

// دروستکردنی لیستێکی کەم دووبارەبووەوە بۆ سکڕۆڵی بێکۆتایی
$scrolling_books = [];
for($i = 0; $i < 5; $i++) { // کەمکردنەوە بۆ 5 جار تەنها
    foreach($latest_books as $book) {
        $scrolling_books[] = $book;
    }
}

// وەرگرتنی پڕ فرۆشترین کتێبەکان - نوێترین کتێبەکانی پڕ فرۆش
$stmt = $conn->prepare("SELECT b.*, c.category_name 
                       FROM books b 
                       LEFT JOIN categories c ON b.category_id = c.category_id 
                       WHERE b.is_bestseller = 1 
                       ORDER BY b.created_date DESC LIMIT 6");
$stmt->execute();
$bestseller_books = $stmt->fetchAll(PDO::FETCH_ASSOC);

// وەرگرتنی کتێبەکانی هەڵبژێردراو - نوێترین کتێبەکانی هەڵبژێردراو
$stmt = $conn->prepare("SELECT b.*, c.category_name 
                       FROM books b 
                       LEFT JOIN categories c ON b.category_id = c.category_id 
                       WHERE b.is_featured = 1 
                       ORDER BY b.created_date DESC LIMIT 6");
$stmt->execute();
$featured_books = $stmt->fetchAll(PDO::FETCH_ASSOC);

?>
<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Primary Meta Tags -->
    <title>کتێبخانەی ئاشتی هەولێر | کتێب، ڕۆمان، شعر، چیرۆک | فرۆشتنی کتێبی کوردی و عەرەبی</title>
    <meta name="title" content="کتێبخانەی ئاشتی هەولێر | کتێب، ڕۆمان، شعر، چیرۆک | فرۆشتنی کتێبی کوردی و عەرەبی">
    <meta name="description" content="کتێبخانەی ئاشتی لە هەولێر - باشترین کۆڵکەی کتێب، ڕۆمان، شعر، چیرۆک، کتێبی ئەدەبی، کتێبی زانستی، کتێبی مێژوویی. فرۆشتنی کتێبی کوردی، عەرەبی، ئینگلیزی. خزمەتگوزاری ناردن بۆ هەموو عێراق.">
    <meta name="keywords" content="کتێبخانە, کتێب, ڕۆمان, شعر, چیرۆک, هەولێر, کوردستان, کتێبی کوردی, کتێبی عەرەبی, کتێبی ئینگلیزی, ئەدەبیات, شاعیر, نوسەر, بەرهەمی ئەدەبی, کولتور, زانست, مێژوو, فەلسەفە, ڕێنمایی, خوێندنەوە, فێربوون, زانیاری, کتێبی قورئان, کتێبی ئاینی, کتێبی ڕێنمایی, کتێبی منداڵان, کتێبی گەنجان, فرۆشتنی کتێب, کڕینی کتێب, ناردنی کتێب, دابەشکردنی کتێب, کتێبخانەی ئۆنلاین, کتێبی ئەلیکترۆنی, PDF, کتێبی نوێ, کتێبی کۆن, کتێبی دەگمەن, بەرهەمی تازە, پەرتووکخانە, لایبرەری, بوک شۆپ, bookstore, books, novels, poetry, stories, literature, Kurdish books, Arabic books, English books, Erbil bookstore, Kurdistan books, Iraqi books, Middle Eastern literature">
    <meta name="author" content="کتێبخانەی ئاشتی">
    <meta name="robots" content="index, follow">
    <meta name="language" content="Kurdish">
    <meta name="revisit-after" content="1 days">
    
    <!-- Open Graph / Facebook -->
    <meta property="og:type" content="website">
    <meta property="og:url" content="https://yourdomain.com/">
    <meta property="og:title" content="کتێبخانەی ئاشتی هەولێر | باشترین کۆڵکەی کتێب لە کوردستان">
    <meta property="og:description" content="کتێبخانەی ئاشتی لە هەولێر - باشترین کۆڵکەی کتێب، ڕۆمان، شعر، چیرۆک، کتێبی ئەدەبی، کتێبی زانستی. فرۆشتنی کتێبی کوردی، عەرەبی، ئینگلیزی.">
    <meta property="og:image" content="https://yourdomain.com/images/og-image.jpg">
    <meta property="og:locale" content="ku_IQ">
    <meta property="og:site_name" content="کتێبخانەی ئاشتی">
    
    <!-- Twitter -->
    <meta property="twitter:card" content="summary_large_image">
    <meta property="twitter:url" content="https://yourdomain.com/">
    <meta property="twitter:title" content="کتێبخانەی ئاشتی هەولێر | باشترین کۆڵکەی کتێب لە کوردستان">
    <meta property="twitter:description" content="کتێبخانەی ئاشتی لە هەولێر - باشترین کۆڵکەی کتێب، ڕۆمان، شعر، چیرۆک، کتێبی ئەدەبی، کتێبی زانستی. فرۆشتنی کتێبی کوردی، عەرەبی، ئینگلیزی.">
    <meta property="twitter:image" content="https://yourdomain.com/images/twitter-image.jpg">
    
     <title>کتێبخانەی ئاشتی | کتێبی کوردی و ڕۆمان و گۆڤار</title>
  <meta name="description" content="کتێبخانەی ئاشتی، شوێنێکی فەرمی بۆ خوێندنی کتێب، فرۆشتن و داگرتنی کتێبی کوردی، رۆمان، فەرهەنگ، فێرکاری، و گۆڤار.">
  <meta name="keywords" content="کتێب, کتێبخانە, کتێبی کوردی, رۆمان, گۆڤار, کتێبی خوێندکار, داگرتنی کتێب, فرۆشتنی کتێب">
    <!-- Geo Tags -->
    <meta name="geo.region" content="IQ-KU">
    <meta name="geo.placename" content="Erbil, Kurdistan Region, Iraq">
    <meta name="geo.position" content="36.18488173185077;44.012086439214336">
    <meta name="ICBM" content="36.18488173185077, 44.012086439214336">
    
    <!-- Canonical URL -->
    <link rel="canonical" href="https://yourdomain.com/">
    
    <!-- Alternate Languages -->
    <link rel="alternate" hreflang="ku" href="https://yourdomain.com/">
    <link rel="alternate" hreflang="ar" href="https://yourdomain.com/ar/">
    <link rel="alternate" hreflang="en" href="https://yourdomain.com/en/">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    <link rel="apple-touch-icon" sizes="180x180" href="/apple-touch-icon.png">
    <link rel="icon" type="image/png" sizes="32x32" href="/favicon-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="/favicon-16x16.png">
    <script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "BookStore", 
  "name": "کتێبخانەی ئاشتی",
  "image": "https://yourdomain.com/images/bookstore.jpg",
  "@id": "https://yourdomain.com",
  "url": "https://yourdomain.com",
  "telephone": "+964-750-386-6000",
  "address": {
    "@type": "PostalAddress",
    "streetAddress": "داونتاون نهۆمی دووەم",
    "addressLocality": "هەولێر", 
    "addressRegion": "هەرێمی کوردستان",
    "postalCode": "44001",
    "addressCountry": "IQ"
  },
  "geo": {
    "@type": "GeoCoordinates",
    "latitude": 36.18488173185077,
    "longitude": 44.012086439214336
  },
  "openingHoursSpecification": {
    "@type": "OpeningHoursSpecification",
    "dayOfWeek": [
      "Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"
    ],
    "opens": "09:00",
    "closes": "17:00"
  },
  "sameAs": [
    "https://www.facebook.com/ktebxany.ashti",
    "https://www.instagram.com/ktebxanay.ashti/",
    "https://t.me/ktebxanai1ashti"
  ]
}
</script>
    <!-- Schema.org structured data -->
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "BookStore",
        "name": "کتێبخانەی ئاشتی",
        "alternateName": "Ashti Books",
        "description": "کتێبخانەی ئاشتی لە هەولێر - باشترین کۆڵکەی کتێب، ڕۆمان، شعر، چیرۆک، کتێبی ئەدەبی، کتێبی زانستی",
        "url": "https://yourdomain.com",
        "logo": "https://yourdomain.com/images/logo.jpg",
        "image": "https://yourdomain.com/images/bookstore.jpg",
        "telephone": "+964-750-386-6000",
        "address": {
            "@type": "PostalAddress",
            "streetAddress": "داونتاون نهۆمی دووەم",
            "addressLocality": "هەولێر",
            "addressRegion": "هەرێمی کوردستان",
            "addressCountry": "IQ"
        },
        "geo": {
            "@type": "GeoCoordinates",
            "latitude": 36.18488173185077,
            "longitude": 44.012086439214336
        },
        "openingHoursSpecification": {
            "@type": "OpeningHoursSpecification",
            "dayOfWeek": [
                "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"
            ],
            "opens": "09:00",
            "closes": "17:00"
        },
        "sameAs": [
            "https://www.facebook.com/ktebxany.ashti",
            "https://t.me/ktebxanai1ashti",
            "https://www.instagram.com/ktebxanay.ashti/"
        ],
        "hasOfferCatalog": {
            "@type": "OfferCatalog",
            "name": "کتێب و ئەدەبیات",
            "itemListElement": [
                {
                    "@type": "Offer",
                    "itemOffered": {
                        "@type": "Book",
                        "name": "کتێبی کوردی"
                    }
                },
                {
                    "@type": "Offer",
                    "itemOffered": {
                        "@type": "Book",
                        "name": "ڕۆمان و چیرۆک"
                    }
                },
                {
                    "@type": "Offer",
                    "itemOffered": {
                        "@type": "Book",
                        "name": "شعر و ئەدەبیات"
                    }
                }
            ]
        }
    }
    </script>
    
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

        .brand-title {
            font-family: 'Playfair Display', serif;
            font-weight: 700;
            font-size: 1.6rem;
            color: #2a2a2a;
            letter-spacing: 0.2px;
        }

   
        .header-bottom { padding: 0.4rem 0 0.9rem; border-top: 1px solid #e5e5e5; }
        .nav-menu { display: flex; gap: 1rem; align-items: center; }
        .nav-link { color: #555; text-decoration: none; font-weight: 500; padding: 0.5rem 1rem; border: 1px solid transparent; transition: all 0.2s ease; border-radius: 4px; }
        .nav-link:hover, .nav-link.active { color: #2a2a2a; border-color: #c0c0c0; background: #f8f8f8; }

       

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

        @media (max-width: 768px) {
            .header-top { flex-direction: column; gap: 1rem; text-align: center; }
            .nav-menu { flex-wrap: wrap; justify-content: center; }
            
            .hero-title {
                font-size: 2rem;
            }
            
            .search-form {
                flex-direction: column;
                gap: 1rem;
            }
            
            .books-grid {
                grid-template-columns: repeat(3, 1fr);
                gap: 1rem;
            }
            
            .book-image {
                height: 280px;
            }
            
            .book-info {
                padding: 1rem;
            }
            
            .book-title {
                font-size: 1rem;
                min-height: 2.4rem;
            }
            
            .book-author {
                font-size: 0.8rem;
            }
            
            .book-genre {
                font-size: 0.7rem;
                padding: 0.2rem 0.4rem;
            }
            
            .book-price {
                font-size: 1.1rem;
            }
            
            .search-filter-content {
                padding: 1.5rem;
            }
            
            .social-links {
                flex-direction: column;
                gap: 0.5rem;
            }

            /* چاککردنی ناوونیشان بۆ مۆبایل */
            .location-content {
                padding: 2rem 1.5rem;
            }

            .location-grid {
                grid-template-columns: 1fr;
                gap: 1.5rem;
            }

            .info-card {
                text-align: center;
                padding: 1.5rem 1rem;
                border-right: none;
                border-top: 4px solid #c0c0c0;
            }

            .info-card p {
                text-align: center;
                direction: rtl;
                /* بۆ ژمارەی تەلەفۆن */
            }

            /* تایبەتمەندی بۆ ژمارەی تەلەفۆن */
            .phone-number {
                direction: ltr !important;
                text-align: center !important;
                display: block !important;
                font-weight: 600;
                color: #2a2a2a;
                font-size: 1.1rem;
            }
        }

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

        .hero p {
            font-size: 1.3rem;
            color: #666;
            margin-bottom: 2.5rem;
            line-height: 1.6;
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

        /* Scrolling Books Section - Updated Styles */
        .scrolling-books-section {
            background: linear-gradient(135deg, #ffffff 0%, #f8f8f8 100%);
            padding: 3rem 0;
            margin: 4rem 0;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }

        .scrolling-books-section::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 1px;
            background: linear-gradient(to right, transparent, #c0c0c0, transparent);
        }

        .scrolling-header {
            text-align: center;
            margin-bottom: 2.5rem;
            padding: 0 2rem;
        }

        .scrolling-title {
            font-family: 'Playfair Display', serif;
            font-size: 2.2rem;
            font-weight: 600;
            color: #2a2a2a;
            margin-bottom: 1rem;
            position: relative;
            display: inline-block;
        }

        .scrolling-title::after {
            content: '';
            position: absolute;
            bottom: -8px;
            left: 50%;
            transform: translateX(-50%);
            width: 60px;
            height: 1px;
            background: #c0c0c0;
        }

        .scrolling-subtitle {
            color: #666;
            font-size: 1.1rem;
            font-style: italic;
        }

        /* Horizontal Scrolling Container */
        .horizontal-scroll-container {
            width: 100%;
            overflow: hidden;
            position: relative;
            padding: 1rem 0;
        }

        .horizontal-scroll-track {
            display: flex;
            animation: infiniteScroll 60s linear infinite; /* خێراتر بۆ ٣ کۆپی */
            gap: 1.5rem;
            padding: 0 1rem;
            width: 300%; /* ٣ جار پانتر بۆ ٣ کۆپی */
        }

        .horizontal-scroll-container:hover .horizontal-scroll-track {
            animation-play-state: paused;
        }

        @keyframes infiniteScroll {
            0% {
                transform: translateX(33.33%); /* لە یەکەم کۆپی دەست پێدەکات */
            }
            100% {
                transform: translateX(-33.33%); /* تا دووەم کۆپی دەڕوات */
            }
        }
/* چاککردنی ناونیشان بۆ مۆبایل */
@media (max-width: 768px) {
    /* Location Content */
    .location-content {
        padding: 2rem 1.5rem;
    }

    /* Location Grid */
    .location-grid {
        grid-template-columns: 1fr;
        gap: 1.5rem;
    }

    /* Info Cards */
    .info-card {
        text-align: center;
        padding: 1.5rem 1rem;
        border-right: none;
        border-top: 4px solid #c0c0c0;
    }

    .info-card p {
        text-align: center;
        direction: rtl;
    }

    /* تایبەتمەندی بۆ ژمارەی تەلەفۆن */
    .phone-number {
        direction: ltr !important;
        text-align: center !important;
        display: block !important;
        font-weight: 600;
        color: #2a2a2a;
        font-size: 1.1rem;
    }
}

@media (max-width: 480px) {
    /* زیاتر چاککردن بۆ مۆبایلی بچووک */
    .location-content {
        padding: 1.5rem 1rem;
    }

    .info-card {
        padding: 1.2rem 0.8rem;
    }

    .info-card h3 {
        font-size: 1.1rem;
        margin-bottom: 0.6rem;
    }

    .info-card p {
        font-size: 0.9rem;
        line-height: 1.6;
    }

    /* ناوونیشانی تەواو */
    .address-full {
        text-align: center !important;
        direction: rtl !important;
        word-break: break-word;
        line-height: 1.6 !important;
    }
}

@media (max-width: 480px) {
    /* زیاتر چاککردن بۆ مۆبایلی بچووک */
    .location-content {
        padding: 1.5rem 1rem;
    }

    .info-card {
        padding: 1.2rem 0.8rem;
    }

    .info-card h3 {
        font-size: 1.1rem;
        margin-bottom: 0.6rem;
    }

    .info-card p {
        font-size: 0.9rem;
        line-height: 1.6;
    }

    /* ناوونیشانی تەواو */
    .address-full {
        text-align: center !important;
        direction: rtl !important;
        word-break: break-word;
        line-height: 1.6 !important;
    }
}
        /* Scrolling Book Card */
        .scroll-book-card {
            flex: 0 0 220px;
            background: #ffffff;
            border: 1px solid #e5e5e5;
            border-radius: 8px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            transition: all 0.3s ease;
            overflow: hidden;
            cursor: pointer;
            min-width: 220px;
        }

        .scroll-book-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
            border-color: #c0c0c0;
        }

        .scroll-book-image {
            width: 100%;
            height: 280px;
            background: linear-gradient(135deg, #f8f8f8 0%, #eeeeee 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #999;
            font-size: 0.9rem;
            font-weight: 500;
            border-bottom: 1px solid #e5e5e5;
            position: relative;
            overflow: hidden;
        }

        .scroll-book-image::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 50px;
            height: 70px;
            border: 2px solid #c0c0c0;
            border-radius: 4px;
            background: #ffffff;
            z-index: 0;
        }

        .scroll-book-image img {
            width: 100%;
            height: 100%;
            object-fit: contain; /* وێنەکە بە تەواوی نیشان دەدرێت */
            position: relative;
            z-index: 1;
            background: #ffffff; /* پاشخانەی سپی */
        }

        .scroll-book-info {
            padding: 1.2rem;
        }

        .scroll-book-title {
            font-family: 'Playfair Display', serif;
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.6rem;
            color: #2a2a2a;
            line-height: 1.4;
            height: 2.8rem;
            display: -webkit-box;
            -webkit-line-clamp: 2;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .scroll-book-author {
            color: #666;
            font-size: 0.85rem;
            margin-bottom: 0.6rem;
            font-style: italic;
        }

        .scroll-book-genre {
            background: #f0f0f0;
            color: #555;
            padding: 0.2rem 0.5rem;
            font-size: 0.75rem;
            display: inline-block;
            margin-bottom: 0.8rem;
            border: 1px solid #e0e0e0;
            font-weight: 500;
            border-radius: 3px;
        }

        .scroll-book-price {
            font-size: 1.1rem;
            font-weight: 600;
            color: #2a2a2a;
            text-align: left;
            border-top: 1px solid #e5e5e5;
            padding-top: 0.8rem;
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

        /* Books Grid - Updated for better mobile display */
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
        }

        .book-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.12);
            border-color: #c0c0c0;
        }

        /* Updated book image dimensions to 1080x1920 ratio */
        .book-image {
            width: 100%;
            height: 400px; /* Increased height for better 1080x1920 ratio */
            background: linear-gradient(135deg, #f8f8f8 0%, #eeeeee 100%);
            display: flex;
            align-items: center;
            justify-content: center;
            color: #999;
            font-size: 1rem;
            font-weight: 500;
            border-bottom: 1px solid #e5e5e5;
            position: relative;
            overflow: hidden;
        }

        .book-image::before {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            width: 60px;
            height: 85px;
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

        .book-price {
            font-size: 1.3rem;
            font-weight: 600;
            color: #2a2a2a;
            text-align: left;
            border-top: 1px solid #e5e5e5;
            padding-top: 1rem;
        }

        /* View All Button */
        .view-all-btn {
            display: inline-block;
            margin: 3rem auto;
            padding: 1rem 2.5rem;
            background: #ffffff;
            color: #2a2a2a;
            text-decoration: none;
            font-size: 1.1rem;
            text-align: center;
            font-weight: 600;
            border: 2px solid #c0c0c0;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-radius: 4px;
        }

        .view-all-btn:hover {
            background: #c0c0c0;
            color: #ffffff;
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(192,192,192,0.3);
        }

        .text-center {
            text-align: center;
        }

        /* Location Section */
        .location-section {
            background: #ffffff;
            border: 1px solid #e5e5e5;
            box-shadow: 0 4px 15px rgba(0,0,0,0.05);
            margin: 4rem 0;
            border-radius: 8px;
            overflow: hidden;
        }

        .location-content {
            padding: 3rem;
        }

        .map-container {
            width: 100%;
            height: 400px;
            margin-bottom: 2rem;
            border: 1px solid #e5e5e5;
            overflow: hidden;
            border-radius: 8px;
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
            border-radius: 4px;
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
            border-radius: 4px;
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

        /* Add this to your existing CSS styles */
        .phone-number {
            direction: ltr;
            display: inline-block;
            unicode-bidi: bidi-override;
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

        /* Optional speed control classes */
        .horizontal-scroll-container.slow .horizontal-scroll-track {
            animation-duration: 240s; /* 4 خولەک بۆ هێواشتر */
        }

        .horizontal-scroll-container.fast .horizontal-scroll-track {
            animation-duration: 120s; /* 1 خولەک بۆ خێراتر */
        }

        /* Responsive Design - چارەسەرکراو بۆ مۆبایل */
        @media (max-width: 768px) {
            .header-top { flex-direction: column; gap: 1rem; text-align: center; }
            .nav-menu { flex-wrap: wrap; justify-content: center; }
            
            .hero-title {
                font-size: 2rem;
            }
            
            .search-form {
                flex-direction: column;
                gap: 1rem;
            }
            
            .books-grid {
                grid-template-columns: repeat(3, 1fr);
                gap: 1rem;
            }
            
            .book-image {
                height: 280px;
            }
            
            .book-info {
                padding: 1rem;
            }
            
            .book-title {
                font-size: 1rem;
                min-height: 2.4rem;
            }
            
            .book-author {
                font-size: 0.8rem;
            }
            
            .book-genre {
                font-size: 0.7rem;
                padding: 0.2rem 0.4rem;
            }
            
            .book-price {
                font-size: 1.1rem;
            }
            
            .search-filter-content {
                padding: 1.5rem;
            }
            
            .social-links {
                flex-direction: column;
                gap: 0.5rem;
            }

            /* چاککردنی ناوونیشان بۆ مۆبایل */
            .location-content {
                padding: 2rem 1.5rem;
            }

            .location-grid {
                grid-template-columns: 1fr;
                gap: 1.5rem;
            }

            .info-card {
                text-align: center;
                padding: 1.5rem 1rem;
                border-right: none;
                border-top: 4px solid #c0c0c0;
            }

            .info-card p {
                text-align: center;
                direction: rtl;
                /* بۆ ژمارەی تەلەفۆن */
            }

            /* تایبەتمەندی بۆ ژمارەی تەلەفۆن */
            .phone-number {
                direction: ltr !important;
                text-align: center !important;
                display: block !important;
                font-weight: 600;
                color: #2a2a2a;
                font-size: 1.1rem;
            }
        }


        /* For very small screens */
        @media (max-width: 480px) {
            .books-grid {
                grid-template-columns: repeat(2, 1fr);
                gap: 0.8rem;
            }
            
            .book-image {
                height: 200px;
            }
            
            .book-info {
                padding: 0.8rem;
            }
            
            .book-title {
                font-size: 0.9rem;
                min-height: 2rem;
            }
            
            .book-price {
                font-size: 1rem;
            }

            /* Smaller scrolling books for very small screens */
            .scroll-book-card {
                flex: 0 0 160px;
                min-width: 160px;
            }
            
            .scroll-book-image {
                height: 180px;
            }
            
            .scroll-book-info {
                padding: 0.8rem;
            }
            
            .scroll-book-title {
                font-size: 0.9rem;
                height: 2rem;
            }
            
            .scroll-book-price {
                font-size: 1rem;
            }

            /* چارەسەری سەرەکی - خێرایی گونجاو بۆ مۆبایل */
            .horizontal-scroll-track {
                animation: infiniteScroll 40s linear infinite; /* خێرایی گونجاو بۆ مۆبایل */
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

        .section {
            animation: fadeInUp 0.6s ease-out;
        }

        .book-card {
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
    </style>
</head>
<body>
    <!-- Header -->
    <header class="header">
        <div class="header-wrap">
            <div class="header-top">
                <a href="index.php" class="brand">
                    <div class="brand-logo">
                        <img src="WhatsApp Image 2025-10-02 at 13.33.18_2208eaf2.jpg" alt="کتێبخانەی ئاشتی">
                    </div>
                    <div class="brand-text">
                        <h1 class="brand-title">کتێبخانەی ئاشتی</h1>
                        <div class="brand-slogan">حاجی قادری کۆیی: بێ کتێب و زانست نەتەوە لە تاریکیدا دەمێنێتەوە</div>
                        <div class="brand-slogan">کتێبخانەی ئاشتی: لە ئێوە گوڵ چاندن لە ئێمە ئاو پرژێن</div>
                    </div>
                </a>
            </div>
            <div class="header-bottom">
                <nav class="nav-menu">
                    <a href="index.php" class="nav-link active">سەرەکی</a>
                    <a href="allbooks.php" class="nav-link">هەموو کتێبەکان</a>
                    <a href="chatbot.php" class="nav-link">چات بۆت</a>
                    
                </nav>
            </div>
        </div>
    </header>

    <!-- Hero Section -->
    <section class="hero">
        <div class="hero-content">
            <h2>بەخێربێن بۆ کتێبخانەی ئاشتی</h2>
            <div class="decorative-border"></div>
        </div>
        <div class="horizontal-scroll-container">
            <div class="horizontal-scroll-track">
                <?php for($i = 0; $i < 3; $i++): ?>
                    <?php foreach($scrolling_books as $book): ?>
                    <div class="scroll-book-card" onclick="showBookDetails(<?php echo $book['book_id']; ?>)">
                        <div class="scroll-book-image">
                            <?php if($book['book_image'] && $book['book_image'] != 'default_book.jpg'): ?>
                                <img src="images/<?php echo $book['book_image']; ?>" alt="<?php echo $book['book_title']; ?>">
                            <?php else: ?>
                                <span>وێنەی کتێب</span>
                            <?php endif; ?>
                        </div>
                       
                    </div>
                    <?php endforeach; ?>
                <?php endfor; ?>
            </div>
        </div>
    </section>

    <!-- Bestseller Books Section -->
    <section class="section">
        <div class="container">
            <div class="section-header">
                <h2 class="section-title">پڕ فرۆشترین کتێبەکان</h2>
                <p class="section-subtitle">بەرهەمە خوازراوەکانی کتێبخانە</p>
            </div>
            <div class="books-grid">
                <?php if(count($bestseller_books) > 0): ?>
                    <?php foreach($bestseller_books as $book): ?>
                    <div class="book-card" onclick="showBookDetails(<?php echo $book['book_id']; ?>)">
                        <div class="book-image">
                            <?php if($book['book_image'] && $book['book_image'] != 'default_book.jpg'): ?>
                                <img src="images/<?php echo $book['book_image']; ?>" alt="<?php echo $book['book_title']; ?>">
                            <?php else: ?>
                                <span>وێنەی کتێب</span>
                            <?php endif; ?>
                        </div>
                        <div class="book-info">
                            <h3 class="book-title"><?php echo $book['book_title']; ?></h3>
                            <div class="book-author">نوسەر: <?php echo isset($book['author']) ? $book['author'] : 'نەناسراو'; ?></div>
                            <span class="book-genre">بەش: <?php echo $book['category_name']; ?></span>
                            <div class="book-price"><?php echo number_format($book['price']); ?> دینار</div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div style="text-align: center; padding: 2rem; color: #666;">
                        <p>هیچ کتێبێکی پڕ فرۆش نەدۆزرایەوە</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </section>

    <!-- Featured Books Section -->
    <section class="section">
        <div class="container">
            <div class="section-header">
                <h2 class="section-title">کتێبەکانی هەڵبژێردراو</h2>
                <p class="section-subtitle">باشترین پێشنیارەکانی کتێبخانە</p>
            </div>
            <div class="books-grid">
                <?php if(count($featured_books) > 0): ?>
                    <?php foreach($featured_books as $book): ?>
                    <div class="book-card" onclick="showBookDetails(<?php echo $book['book_id']; ?>)">
                        <div class="book-image">
                            <?php if($book['book_image'] && $book['book_image'] != 'default_book.jpg'): ?>
                                <img src="images/<?php echo $book['book_image']; ?>" alt="<?php echo $book['book_title']; ?>">
                            <?php else: ?>
                                <span>وێنەی کتێب</span>
                            <?php endif; ?>
                        </div>
                        <div class="book-info">
                            <h3 class="book-title"><?php echo $book['book_title']; ?></h3>
                            <div class="book-author">نوسەر: <?php echo isset($book['author']) ? $book['author'] : 'نەناسراو'; ?></div>
                            <span class="book-genre">بەش: <?php echo $book['category_name']; ?></span>
                            <div class="book-price"><?php echo number_format($book['price']); ?> دینار</div>
                        </div>
                    </div>
                    <?php endforeach; ?>
                <?php else: ?>
                    <div style="text-align: center; padding: 2rem; color: #666;">
                        <p>هیچ کتێبێکی هەڵبژێردراو نەدۆزرایەوە</p>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </section>

    <div class="text-center">
        <a href="allbooks.php" class="view-all-btn">بینینی هەموو کتێبەکان</a>
    </div>

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
                        <p>هەولێر - داونتاون، نهۆمی دووەم دوکانی F78 سەرەوەی ساردەمەنی جیلاتۆ</p>
                    </div>
                    <div class="info-card">
                        <h3>کاتژمێرەکانی کارکردن</h3>
                        <p>هەموو ڕۆژێک: ٩:٠٠ بەیانی - ٨:٠٠ ئێوارە</p>
                    </div>
                    <div class="info-card">
                        <h3>پەیوەندی</h3>
                        <p><span class="phone-number">+964 750 386 6000</span></p>
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
                <a href="https://t.me/ashtibookstore" target="_blank" aria-label="Telegram Channel">
                    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M21.5 3.5l-19 7a1 1 0 00.05 1.9l5.27 1.7 2.01 6.37a1 1 0 001.74.34l2.9-2.82 5.03 3.7a1 1 0 001.57-.63l3.38-15.1a1 1 0 00-1.95-.46L9 13l10.2-8.1-7.6 9.5"/></svg>
                    <span>Telegram Channel</span>
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
        </div>

        <style>
            .social-links { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-top: 1rem; }
            .social-links a { display: inline-flex; align-items: center; gap: 0.5rem; color: #2a2a2a; text-decoration: none; padding: 0.5rem 0.8rem; border: 1px solid #e0e0e0; border-radius: 8px; transition: all 0.2s ease; background: #fff; }
            .social-links a:hover { background: #2a2a2a; color: #ffffff; border-color: #2a2a2a; }
            .social-links svg { width: 20px; height: 20px; display: block; }
            @media (max-width: 768px) { .social-links { justify-content: center; } }
        </style>

        <!-- Text Particle Effect Footer -->
        <div class="developer-footer" id="developerFooter">
            <div class="developer-credit">
                <a href="https://www.instagram.com/i_xoshnawm/" target="_blank" class="developer-link" id="devLink">@i_xoshnawm</a>
                <span class="dev-text" id="devText">website is developed by</span>
                <div class="tech-symbol" id="techSymbol"></div>
            </div>
        </div>
    </footer>

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

        // Function to change scroll speed (optional)
        function changeScrollSpeed(speed) {
            const scrollTrack = document.querySelector('.horizontal-scroll-track');
            const container = document.querySelector('.horizontal-scroll-container');
            
            // Remove existing speed classes
            container.classList.remove('slow', 'fast');
            
            // Add new speed class
            if (speed !== 'normal') {
                container.classList.add(speed);
            }
        }

        // Start the auto particle generation when page loads
        window.addEventListener('load', startAutoParticles);

        // Book card click handler
        function showBookDetails(bookId) {
            window.location.href = 'book_details.php?id=' + bookId;
        }

        // Smooth scroll for anchor links
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
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

        // Add scroll effect for header
        window.addEventListener('scroll', function() {
            const header = document.querySelector('.header');
            if (window.scrollY > 100) {
                header.style.boxShadow = '0 4px 20px rgba(0,0,0,0.1)';
            } else {
                header.style.boxShadow = '0 2px 10px rgba(0,0,0,0.05)';
            }
        });
    </script>
</body>
</html>