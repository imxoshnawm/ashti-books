-- هەڵبژاردن/دروستکردنی بنکەی داتا
CREATE DATABASE IF NOT EXISTS db_ashti CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE db_ashti;

-- ئێستا کۆدەکانی تر بنووسە...
SET NAMES utf8mb4;
SET character_set_client = utf8mb4;
-- ... بەردەوامی کۆدەکە

-- دڵنیابوون لە character set 
SET NAMES utf8mb4;
SET character_set_client = utf8mb4;

DROP TABLE IF EXISTS books;
DROP TABLE IF EXISTS categories;  
DROP TABLE IF EXISTS admins;

-- خشتەی ئەدمینەکان - سادەکراو
CREATE TABLE admins (
    admin_id INT AUTO_INCREMENT,
    admin_name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    password VARCHAR(255) NOT NULL,
    admin_type VARCHAR(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ئاسایی',
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (admin_id),
    UNIQUE KEY phone_unique (phone_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی بەشەکان
CREATE TABLE categories (
    category_id INT AUTO_INCREMENT,
    category_name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    category_description TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی کتێبەکان  
CREATE TABLE books (
    book_id INT AUTO_INCREMENT,
    book_title VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    author VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    translator VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    genre VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    category_id INT,
    price DECIMAL(10,2) NOT NULL,
    book_image VARCHAR(255) DEFAULT 'default_book.jpg',
    description TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    is_featured BOOLEAN DEFAULT FALSE,
    is_bestseller BOOLEAN DEFAULT FALSE,
    view_count INT DEFAULT 0,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (book_id),
    KEY category_key (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Foreign key constraint زیادکردن
ALTER TABLE books 
ADD CONSTRAINT fk_book_category 
FOREIGN KEY (category_id) REFERENCES categories(category_id) 
ON DELETE SET NULL ON UPDATE CASCADE;

-- داتای سەرەتایی بۆ بەشەکان
INSERT INTO categories (category_name, category_description) VALUES
('هەموو کتێبەکان', 'تەواوی کتێبەکانی کتێبخانە'),
('ڕۆمان', 'کتێبەکانی ڕۆمان بە جۆرەکانی جیاواز'),
('ڕۆمانی ڕۆمانسی', 'کتێبەکانی ڕۆمانی ڕۆمانسی'),
('ڕۆمانی ترسناک', 'کتێبەکانی ترسناک و سیناریۆی ترس'),
('کتێبی گەشەپێدان', 'کتێبەکانی گەشەپێدانی کەسایەتی');

-- داتای سەرەتایی بۆ ئەدمینەکان
INSERT INTO admins (admin_name, phone_number, password, admin_type) VALUES
('بەڕێوەبەری سەرەکی', '07501234567', MD5('admin123'), 'گشتی'),
('کارمەندی کتێبخانە', '07509876543', MD5('staff123'), 'ئاسایی');

-- داتای نموونە بۆ کتێبەکان
INSERT INTO books (book_title, author, translator, genre, category_id, price, description, is_featured, is_bestseller) VALUES
('شەمامەی کوردایەتی', 'ئەحمەد موختار جاف', NULL, 'مێژوو', 2, 15000, 'کتێبێکی گرنگ دەربارەی مێژووی گەلی کورد', TRUE, TRUE),
('دلۆڤان', 'ئیبراهیم ئەحمەد', NULL, 'ڕۆمان', 2, 12000, 'یەکێک لە ناوداری ترین ڕۆمانەکانی ئەدەبی کوردی', FALSE, TRUE),
('چرای کوردایەتی', 'جگەرخوێن', NULL, 'شیعر', 2, 8000, 'کۆمەڵە شیعری نیشتمانی', TRUE, FALSE),
('گوڵی سووری غەزەڵ', 'عەبدوڵڵا پەشێو', NULL, 'ڕۆمانی ڕۆمانسی', 3, 10000, 'چیرۆکێکی خۆشەویستی لە سەردەمی کۆندا', FALSE, FALSE);

-- چاودێری ئەنجام
SELECT 'خشتەکان بە سەرکەوتویی دروست کران' AS result;
SELECT COUNT(*) AS admin_count FROM admins;
SELECT COUNT(*) AS category_count FROM categories;
SELECT COUNT(*) AS book_count FROM books;


-- بنکەی داتای کتێبخانەی ئاشتی - وەشانی نوێ لەگەڵ چات بۆت
-- پێش جێبەجێکردن لە phpMyAdmin:
-- 1. لە لیستی database کان 'ashtilib_db_ashti' هەڵبژێرە
-- 2. لە تابی SQL دا ئەم کۆدە paste بکە

-- دڵنیابوون لە character set 
SET NAMES utf8mb4;
SET character_set_client = utf8mb4;
SET character_set_connection = utf8mb4;
SET character_set_results = utf8mb4;

-- سڕینەوەی خشتە کۆنەکان
DROP TABLE IF EXISTS chat_sessions;
DROP TABLE IF EXISTS books;
DROP TABLE IF EXISTS categories;  
DROP TABLE IF EXISTS admins;

-- خشتەی ئەدمینەکان - سادەکراو
CREATE TABLE admins (
    admin_id INT AUTO_INCREMENT,
    admin_name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    password VARCHAR(255) NOT NULL,
    admin_type VARCHAR(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ئاسایی',
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (admin_id),
    UNIQUE KEY phone_unique (phone_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی بەشەکان
CREATE TABLE categories (
    category_id INT AUTO_INCREMENT,
    category_name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    category_description TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی کتێبەکان  
CREATE TABLE books (
    book_id INT AUTO_INCREMENT,
    book_title VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    author VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    translator VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    genre VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    category_id INT,
    price DECIMAL(10,2) NOT NULL,
    book_image VARCHAR(255) DEFAULT 'default_book.jpg',
    description TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    is_featured BOOLEAN DEFAULT FALSE,
    is_bestseller BOOLEAN DEFAULT FALSE,
    view_count INT DEFAULT 0,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (book_id),
    KEY category_key (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی چات سیشنەکان - نوێ
CREATE TABLE chat_sessions (
    chat_id INT AUTO_INCREMENT,
    session_id VARCHAR(100) NOT NULL,
    user_message TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    ai_response TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    books_mentioned TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    user_ip VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chat_id),
    KEY session_idx (session_id),
    KEY date_idx (created_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Foreign key constraint زیادکردن
ALTER TABLE books 
ADD CONSTRAINT fk_book_category 
FOREIGN KEY (category_id) REFERENCES categories(category_id) 
ON DELETE SET NULL ON UPDATE CASCADE;

-- داتای سەرەتایی بۆ بەشەکان
INSERT INTO categories (category_name, category_description) VALUES
('هەموو کتێبەکان', 'تەواوی کتێبەکانی کتێبخانە'),
('ڕۆمان', 'کتێبەکانی ڕۆمان بە جۆرەکانی جیاواز'),
('ڕۆمانی ڕۆمانسی', 'کتێبەکانی ڕۆمانی ڕۆمانسی'),
('ڕۆمانی ترسناک', 'کتێبەکانی ترسناک و سیناریۆی ترس'),
('کتێبی گەشەپێدان', 'کتێبەکانی گەشەپێدانی کەسایەتی'),
('شیعر', 'کتێبەکانی شیعر و ئەدەبیات'),
('مێژوو', 'کتێبەکانی مێژووی گشتی'),
('ئایینی', 'کتێبەکانی ئایینی و ڕۆحی'),
('فەلسەفە', 'کتێبەکانی فەلسەفە و بیرکردنەوە'),
('زانست', 'کتێبەکانی زانستی و تەکنیکی');

-- داتای سەرەتایی بۆ ئەدمینەکان
INSERT INTO admins (admin_name, phone_number, password, admin_type) VALUES
('بەڕێوەبەری سەرەکی', '07501234567', MD5('admin123'), 'گشتی'),
('کارمەندی کتێبخانە', '07509876543', MD5('staff123'), 'ئاسایی');

-- داتای نموونە بۆ کتێبەکان - زیاتر
INSERT INTO books (book_title, author, translator, genre, category_id, price, description, is_featured, is_bestseller) VALUES
('شەمامەی کوردایەتی', 'ئەحمەد موختار جاف', NULL, 'مێژوو', 7, 15000, 'کتێبێکی گرنگ دەربارەی مێژووی گەلی کورد', TRUE, TRUE),
('دلۆڤان', 'ئیبراهیم ئەحمەد', NULL, 'ڕۆمان', 2, 12000, 'یەکێک لە ناوداری ترین ڕۆمانەکانی ئەدەبی کوردی', FALSE, TRUE),
('چرای کوردایەتی', 'جگەرخوێن', NULL, 'شیعر', 6, 8000, 'کۆمەڵە شیعری نیشتمانی', TRUE, FALSE),
('گوڵی سووری غەزەڵ', 'عەبدوڵڵا پەشێو', NULL, 'ڕۆمانی ڕۆمانسی', 3, 10000, 'چیرۆکێکی خۆشەویستی لە سەردەمی کۆندا', FALSE, FALSE),
('ڕێگای خۆناسینەوە', 'کامڵ حسن علی', NULL, 'گەشەپێدان', 5, 18000, 'کتێبی گەشەپێدانی کەسایەتی و خۆناسینەوە', TRUE, TRUE),
('شەوانی ترس', 'سەردار محەمەد', NULL, 'ترسناک', 4, 14000, 'کۆمەڵە چیرۆکی ترسناک کوردی', FALSE, FALSE),
('دراکولا', 'برام ستۆکەر', 'عەلی عەزیز', 'ترسناک', 4, 16000, 'ڕۆمانی ناودار ترسناکی دراکولا', TRUE, TRUE),
('پرنسپلەکانی سەرکەوتن', 'نەپۆلیۆن هیل', 'ئارام رەحیم', 'گەشەپێدان', 5, 22000, 'کتێبی ناودار بۆ سەرکەوتن لە ژیان', FALSE, TRUE),
('قورئانی پیرۆز', 'کتێبی ئاسمانی', NULL, 'ئایینی', 8, 12000, 'قورئانی پیرۆز بە وەرگێڕانی کوردی', TRUE, FALSE),
('فەلسەفەی ژیان', 'ئەفڵاتون', 'د. ئەحمەد عەلی', 'فەلسەفە', 9, 20000, 'بنەماکانی فەلسەفەی ژیان', FALSE, FALSE),
('بنەماکانی کیمیا', 'د. حەسەن محەمەد', NULL, 'زانست', 10, 25000, 'کتێبی خوێندنی زانستی کیمیا', FALSE, FALSE),
('خۆشەویستی لە کاتی کۆلێرا', 'گابریێل گارسیا مارکێز', 'سامان سالم', 'ڕۆمانسی', 3, 19000, 'یەکێک لە ناوداری ترین ڕۆمانە ڕۆمانسیەکان', TRUE, TRUE);

-- چاودێری ئەنجام
SELECT 'خشتەکان بە سەرکەوتویی دروست کران' AS result;
SELECT COUNT(*) AS admin_count FROM admins;
SELECT COUNT(*) AS category_count FROM categories;
SELECT COUNT(*) AS book_count FROM books;
SELECT 'خشتەی چات سیشن ئامادەیە' AS chat_status;







-- بنکەی داتای کتێبخانەی ئاشتی - وەشانی نوێ لەگەڵ چات بۆت
-- پێش جێبەجێکردن لە phpMyAdmin:
-- 1. لە لیستی database کان 'db_ashti' هەڵبژێرە
-- 2. لە تابی SQL دا ئەم کۆدە paste بکە

-- دڵنیابوون لە character set 
SET NAMES utf8mb4;
SET character_set_client = utf8mb4;
SET character_set_connection = utf8mb4;
SET character_set_results = utf8mb4;

-- سڕینەوەی خشتە کۆنەکان
DROP TABLE IF EXISTS chat_sessions;
DROP TABLE IF EXISTS books;
DROP TABLE IF EXISTS categories;  
DROP TABLE IF EXISTS admins;

-- خشتەی ئەدمینەکان - سادەکراو
CREATE TABLE admins (
    admin_id INT AUTO_INCREMENT,
    admin_name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    phone_number VARCHAR(20) NOT NULL,
    password VARCHAR(255) NOT NULL,
    admin_type VARCHAR(20) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT 'ئاسایی',
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (admin_id),
    UNIQUE KEY phone_unique (phone_number)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی بەشەکان
CREATE TABLE categories (
    category_id INT AUTO_INCREMENT,
    category_name VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    category_description TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی کتێبەکان  
CREATE TABLE books (
    book_id INT AUTO_INCREMENT,
    book_title VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    author VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    translator VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    genre VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    category_id INT,
    price DECIMAL(10,2) NOT NULL,
    book_image VARCHAR(255) DEFAULT 'default_book.jpg',
    description TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
    is_featured BOOLEAN DEFAULT FALSE,
    is_bestseller BOOLEAN DEFAULT FALSE,
    view_count INT DEFAULT 0,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (book_id),
    KEY category_key (category_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- خشتەی چات سیشنەکان - نوێ
CREATE TABLE chat_sessions (
    chat_id INT AUTO_INCREMENT,
    session_id VARCHAR(100) NOT NULL,
    user_message TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    ai_response TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    books_mentioned TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    user_ip VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL,
    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (chat_id),
    KEY session_idx (session_id),
    KEY date_idx (created_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Foreign key constraint زیادکردن
ALTER TABLE books 
ADD CONSTRAINT fk_book_category 
FOREIGN KEY (category_id) REFERENCES categories(category_id) 
ON DELETE SET NULL ON UPDATE CASCADE;

-- داتای سەرەتایی بۆ بەشەکان
INSERT INTO categories (category_name, category_description) VALUES
('هەموو کتێبەکان', 'تەواوی کتێبەکانی کتێبخانە'),
('ڕۆمان', 'کتێبەکانی ڕۆمان بە جۆرەکانی جیاواز'),
('ڕۆمانی ڕۆمانسی', 'کتێبەکانی ڕۆمانی ڕۆمانسی'),
('ڕۆمانی ترسناک', 'کتێبەکانی ترسناک و سیناریۆی ترس'),
('کتێبی گەشەپێدان', 'کتێبەکانی گەشەپێدانی کەسایەتی'),
('شیعر', 'کتێبەکانی شیعر و ئەدەبیات'),
('مێژوو', 'کتێبەکانی مێژووی گشتی'),
('ئایینی', 'کتێبەکانی ئایینی و ڕۆحی'),
('فەلسەفە', 'کتێبەکانی فەلسەفە و بیرکردنەوە'),
('زانست', 'کتێبەکانی زانستی و تەکنیکی');

-- داتای سەرەتایی بۆ ئەدمینەکان
INSERT INTO admins (admin_name, phone_number, password, admin_type) VALUES
('بەڕێوەبەری سەرەکی', '07501234567', MD5('admin123'), 'گشتی'),
('کارمەندی کتێبخانە', '07509876543', MD5('staff123'), 'ئاسایی');

-- داتای نموونە بۆ کتێبەکان - زیاتر
INSERT INTO books (book_title, author, translator, genre, category_id, price, description, is_featured, is_bestseller) VALUES
('شەمامەی کوردایەتی', 'ئەحمەد موختار جاف', NULL, 'مێژوو', 7, 15000, 'کتێبێکی گرنگ دەربارەی مێژووی گەلی کورد', TRUE, TRUE),
('دلۆڤان', 'ئیبراهیم ئەحمەد', NULL, 'ڕۆمان', 2, 12000, 'یەکێک لە ناوداری ترین ڕۆمانەکانی ئەدەبی کوردی', FALSE, TRUE),
('چرای کوردایەتی', 'جگەرخوێن', NULL, 'شیعر', 6, 8000, 'کۆمەڵە شیعری نیشتمانی', TRUE, FALSE),
('گوڵی سووری غەزەڵ', 'عەبدوڵڵا پەشێو', NULL, 'ڕۆمانی ڕۆمانسی', 3, 10000, 'چیرۆکێکی خۆشەویستی لە سەردەمی کۆندا', FALSE, FALSE),
('ڕێگای خۆناسینەوە', 'کامڵ حسن علی', NULL, 'گەشەپێدان', 5, 18000, 'کتێبی گەشەپێدانی کەسایەتی و خۆناسینەوە', TRUE, TRUE),
('شەوانی ترس', 'سەردار محەمەد', NULL, 'ترسناک', 4, 14000, 'کۆمەڵە چیرۆکی ترسناک کوردی', FALSE, FALSE),
('دراکولا', 'برام ستۆکەر', 'عەلی عەزیز', 'ترسناک', 4, 16000, 'ڕۆمانی ناودار ترسناکی دراکولا', TRUE, TRUE),
('پرنسپلەکانی سەرکەوتن', 'نەپۆلیۆن هیل', 'ئارام رەحیم', 'گەشەپێدان', 5, 22000, 'کتێبی ناودار بۆ سەرکەوتن لە ژیان', FALSE, TRUE),
('قورئانی پیرۆز', 'کتێبی ئاسمانی', NULL, 'ئایینی', 8, 12000, 'قورئانی پیرۆز بە وەرگێڕانی کوردی', TRUE, FALSE),
('فەلسەفەی ژیان', 'ئەفڵاتون', 'د. ئەحمەد عەلی', 'فەلسەفە', 9, 20000, 'بنەماکانی فەلسەفەی ژیان', FALSE, FALSE),
('بنەماکانی کیمیا', 'د. حەسەن محەمەد', NULL, 'زانست', 10, 25000, 'کتێبی خوێندنی زانستی کیمیا', FALSE, FALSE),
('خۆشەویستی لە کاتی کۆلێرا', 'گابریێل گارسیا مارکێز', 'سامان سالم', 'ڕۆمانسی', 3, 19000, 'یەکێک لە ناوداری ترین ڕۆمانە ڕۆمانسیەکان', TRUE, TRUE),
('ناسکی گشتی', 'ستیڤن هاوکینگ', 'محەمەد ئەمین', 'زانست', 10, 28000, 'گەیاندنی زانستی ئاسان بۆ ناسکی گەردوون', TRUE, TRUE),
('نهێنی خۆشەویستی', 'پاولۆ کۆێلۆ', 'ژیان ئەحمەد', 'ڕۆمانسی', 3, 17000, 'کتێبی ناودار دەربارەی خۆشەویستی ڕاستەقینە', FALSE, TRUE),
('مێژووی کوردستان', 'د. کەمال مەزهەر', NULL, 'مێژوو', 7, 24000, 'مێژووی تەواوی گەلی کورد', TRUE, FALSE);

-- چاودێری ئەنجام
SELECT 'خشتەکان بە سەرکەوتویی دروست کران' AS result;
SELECT COUNT(*) AS admin_count FROM admins;
SELECT COUNT(*) AS category_count FROM categories;
SELECT COUNT(*) AS book_count FROM books;
SELECT 'خشتەی چات سیشن ئامادەیە' AS chat_status;