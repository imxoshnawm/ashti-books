<?php
require_once 'config.php';
?>
<!DOCTYPE html>
<html lang="ku" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    
    <!-- Primary Meta Tags -->
    <title>دەربارە | کتێبخانەی ئاشتی هەولێر</title>
    <meta name="title" content="دەربارە | کتێبخانەی ئاشتی هەولێر">
    <meta name="description" content="دەربارەی کتێبخانەی ئاشتی لە هەولێر - شوێن و پەیوەندی و سۆشیاڵ میدیاکانمان">
    <meta name="keywords" content="دەربارە, کتێبخانەی ئاشتی, پەیوەندی, شوێن, هەولێر">
    <meta name="author" content="کتێبخانەی ئاشتی">
    <meta name="robots" content="index, follow">
    
    <!-- Open Graph -->
    <meta property="og:type" content="website">
    <meta property="og:title" content="دەربارە | کتێبخانەی ئاشتی هەولێر">
    <meta property="og:description" content="دەربارەی کتێبخانەی ئاشتی لە هەولێر - شوێن و پەیوەندی و سۆشیاڵ میدیاکانمان">
    
    <!-- Canonical URL -->
    <link rel="canonical" href="https://yourdomain.com/about.php">
    
    <!-- Favicon -->
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    
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

/* Header Styles (Unified like index.php) */
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

.brand-logo img { width: 100%; height: 100%; object-fit: cover; }

.brand-text { display: flex; flex-direction: column; gap: 0.2rem; }

.brand-title {
    font-family: 'Playfair Display', serif;
    font-weight: 700;
    font-size: 1.6rem;
    color: #2a2a2a;
    letter-spacing: 0.2px;
}

.brand-slogan { color: #666; font-size: 0.95rem; font-weight: 500; margin-top: 0.2rem; }

.header-bottom { padding: 0.4rem 0 0.9rem; border-top: 1px solid #e5e5e5; }
.nav-menu { display: flex; gap: 1rem; align-items: center; }
.nav-link { color: #555; text-decoration: none; font-weight: 500; padding: 0.7rem 1.2rem; border: 1px solid transparent; transition: all 0.3s ease; font-size: 1rem; }
.nav-link:hover { color: #2a2a2a; border-color: #c0c0c0; background: #f8f8f8; }
.nav-link.active { background: #2a2a2a; color: #ffffff; border-color: #2a2a2a; box-shadow: 0 2px 10px rgba(0,0,0,0.08); }

/* Hero Section */
.hero {
    background: linear-gradient(135deg, #ffffff 0%, #f8f8f8 100%);
    padding: 4rem 0;
    text-align: center;
    border-bottom: 1px solid #e0e0e0;
    position: relative;
    overflow: hidden;
}

.hero::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(to right, transparent, #c0c0c0, transparent);
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
    position: relative;
    display: inline-block;
}

.hero h2::after {
    content: '';
    position: absolute;
    bottom: -10px;
    left: 50%;
    transform: translateX(-50%);
    width: 80px;
    height: 2px;
    background: #c0c0c0;
    border-radius: 1px;
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

/* About Content */
.about-content {
    background: linear-gradient(135deg, #ffffff 0%, #fafafa 100%);
    border: 1px solid #e5e5e5;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    margin: 4rem 0;
    border-radius: 12px;
    overflow: hidden;
    padding: 3rem;
    text-align: center;
    position: relative;
}

.about-content::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(to right, transparent, #c0c0c0, transparent);
}

.about-text {
    font-size: 1.2rem;
    line-height: 1.8;
    color: #555;
    margin-bottom: 2rem;
    max-width: 800px;
    margin-left: auto;
    margin-right: auto;
}

.highlight-text {
    color: #2a2a2a;
    font-weight: 600;
    font-style: italic;
}

/* Location Section */
.location-section {
    background: linear-gradient(135deg, #ffffff 0%, #fafafa 100%);
    border: 1px solid #e5e5e5;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    margin: 4rem 0;
    border-radius: 12px;
    overflow: hidden;
    position: relative;
}

.location-section::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(to right, transparent, #c0c0c0, transparent);
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
    background: linear-gradient(135deg, #f8f8f8 0%, #ffffff 100%);
    padding: 1.8rem;
    border: 1px solid #e5e5e5;
    border-right: 4px solid #c0c0c0;
    border-radius: 8px;
    transition: all 0.3s ease;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
}

.info-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0,0,0,0.12);
    border-color: #c0c0c0;
    background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%);
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

.phone-number {
    direction: ltr;
    display: inline-block;
    unicode-bidi: bidi-override;
}

/* Social Media Section */
.social-section {
    background: linear-gradient(135deg, #ffffff 0%, #fafafa 100%);
    border: 1px solid #e5e5e5;
    box-shadow: 0 4px 20px rgba(0,0,0,0.08);
    margin: 4rem 0;
    border-radius: 12px;
    overflow: hidden;
    padding: 3rem;
    position: relative;
}

.social-section::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 1px;
    background: linear-gradient(to right, transparent, #c0c0c0, transparent);
}

.social-grid {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-top: 2rem;
    max-width: 600px;
    margin-left: auto;
    margin-right: auto;
}

.social-card {
    background: linear-gradient(135deg, #f8f8f8 0%, #ffffff 100%);
    padding: 1rem 1.5rem;
    border: 1px solid #e5e5e5;
    border-radius: 25px;
    text-align: right;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    gap: 1rem;
    min-height: 70px;
    box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    cursor: pointer;
    text-decoration: none;
}

.social-card:hover {
    transform: translateY(-3px);
    box-shadow: 0 8px 25px rgba(0,0,0,0.15);
    border-color: #c0c0c0;
    background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%);
    text-decoration: none;
}

.social-icon {
    width: 45px;
    height: 45px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.2rem;
    color: #2a2a2a;
    border: 2px solid #e0e0e0;
    background: #ffffff;
    transition: all 0.3s ease;
    flex-shrink: 0;
}

.social-card:hover .social-icon {
    border-color: #2a2a2a;
    transform: scale(1.1);
    box-shadow: 0 4px 15px rgba(0,0,0,0.1);
}

/* Brand colors for social cards */
.social-card.facebook {
    background: linear-gradient(135deg, #1877F2 0%, #0f5ad9 100%);
    border-color: #1158d3;
}
.social-card.instagram {
    background: linear-gradient(45deg, #f58529, #dd2a7b, #8134af, #515bd4);
    border-color: #dd2a7b;
}
.social-card.telegram {
    background: linear-gradient(135deg, #229ED9 0%, #1c84b6 100%);
    border-color: #1b84b5;
}
.social-card.whatsapp {
    background: linear-gradient(135deg, #25D366 0%, #1bb954 100%);
    border-color: #1bb954;
}
.social-card.maps {
    background: linear-gradient(135deg, #4285F4 0%, #2b64c9 100%);
    border-color: #2b64c9;
}
.social-card.website {
    background: linear-gradient(135deg, #2a2a2a 0%, #000000 100%);
    border-color: #2a2a2a;
}
/* Snapchat */
.social-card.snapchat {
    background: linear-gradient(135deg,rgb(133, 131, 19) 0%, rgb(133, 131, 19) 100%);
    border-color: rgb(133, 131, 19);
}

/* Make text and icons readable on colored cards */
.social-card.facebook h3, .social-card.facebook p,
.social-card.instagram h3, .social-card.instagram p,
.social-card.telegram h3, .social-card.telegram p,
.social-card.whatsapp h3, .social-card.whatsapp p,
.social-card.maps h3, .social-card.maps p,
.social-card.website h3, .social-card.website p,
.social-card.snapchat h3, .social-card.snapchat p {
    color: #ffffff;
}

.social-card.facebook .social-icon,
.social-card.instagram .social-icon,
.social-card.telegram .social-icon,
.social-card.whatsapp .social-icon,
.social-card.maps .social-icon,
.social-card.website .social-icon,
.social-card.snapchat .social-icon {
    background: transparent;
    border-color: rgba(255,255,255,0.8);
}

/* Invert SVG icons to white on colored backgrounds */
.social-card.facebook .social-icon::before,
.social-card.instagram .social-icon::before,
.social-card.telegram .social-icon::before,
.social-card.whatsapp .social-icon::before,
.social-card.maps .social-icon::before,
.social-card.website .social-icon::before,
.social-card.snapchat .social-icon::before {
    filter: invert(1) brightness(2);
}

/* Mini social icons bar */
.social-mini {
    display: flex;
    justify-content: center;
    gap: 0.6rem;
    flex-wrap: wrap;
    margin-top: 0.5rem;
}

.mini-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    border: 2px solid transparent;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
    text-decoration: none;
}

.mini-icon .glyph {
    width: 18px;
    height: 18px;
    display: block;
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    filter: invert(1) brightness(2);
}

.mini-icon.facebook { background: #1877F2; border-color: #1158d3; }
.mini-icon.instagram { background: linear-gradient(45deg, #f58529, #dd2a7b, #8134af, #515bd4); }
.mini-icon.telegram { background: #229ED9; border-color: #1b84b5; }
.mini-icon.whatsapp { background: #25D366; border-color: #1bb954; }
.mini-icon.maps { background: #4285F4; border-color: #2b64c9; }
.mini-icon.snapchat { background: rgb(163, 156, 20); border-color:rgb(163, 156, 20); }

.mini-icon:hover { transform: translateY(-2px) scale(1.05); box-shadow: 0 6px 16px rgba(0,0,0,0.15); }

/* Reuse existing social-icon for mini icons */
.social-mini .social-icon {
    width: 18px;
    height: 18px;
    border: none;
    background: transparent;
    box-shadow: none;
}

.social-mini .social-icon::before {
    filter: invert(1) brightness(2);
}

/* Social Icons SVGs - Black and White */
.icon-facebook::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M24 12.073c0-6.627-5.373-12-12-12s-12 5.373-12 12c0 5.99 4.388 10.954 10.125 11.854v-8.385H7.078v-3.47h3.047V9.43c0-3.007 1.792-4.669 4.533-4.669 1.312 0 2.686.235 2.686.235v2.953H15.83c-1.491 0-1.956.925-1.956 1.874v2.25h3.328l-.532 3.47h-2.796v8.385C19.612 23.027 24 18.062 24 12.073z'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

.icon-instagram::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.265.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zM12 0C8.741 0 8.333.014 7.053.072 2.695.272.273 2.69.073 7.052.014 8.333 0 8.741 0 12c0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98C8.333 23.986 8.741 24 12 24c3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98C15.668.014 15.259 0 12 0zm0 5.838a6.162 6.162 0 100 12.324 6.162 6.162 0 000-12.324zM12 16a4 4 0 110-8 4 4 0 010 8zm6.406-11.845a1.44 1.44 0 100 2.881 1.44 1.44 0 000-2.881z'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

.icon-telegram::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M11.944 0A12 12 0 0 0 0 12a12 12 0 0 0 12 12 12 12 0 0 0 12-12A12 12 0 0 0 12 0a12 12 0 0 0-.056 0zm4.962 7.224c.1-.002.321.023.465.14a.506.506 0 0 1 .171.325c.016.093.036.306.02.472-.18 1.898-.962 6.502-1.36 8.627-.168.9-.499 1.201-.820 1.23-.696.065-1.225-.46-1.9-.902-1.056-.693-1.653-1.124-2.678-1.8-1.185-.78-.417-1.21.258-1.91.177-.184 3.247-2.977 3.307-3.23.007-.032.014-.15-.056-.212s-.174-.041-.249-.024c-.106.024-1.793 1.14-5.061 3.345-.48.33-.913.49-1.302.48-.428-.008-1.252-.241-1.865-.44-.752-.245-1.349-.374-1.297-.789.027-.216.325-.437.893-.663 3.498-1.524 5.83-2.529 6.998-3.014 3.332-1.386 4.025-1.627 4.476-1.635z'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

.icon-whatsapp::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M17.472 14.382c-.297-.149-1.758-.867-2.03-.967-.273-.099-.471-.148-.67.15-.197.297-.767.966-.94 1.164-.173.199-.347.223-.644.075-.297-.15-1.255-.463-2.39-1.475-.883-.788-1.48-1.761-1.653-2.059-.173-.297-.018-.458.13-.606.134-.133.298-.347.446-.52.149-.174.198-.298.298-.497.099-.198.05-.371-.025-.52-.075-.149-.669-1.612-.916-2.207-.242-.579-.487-.5-.669-.51-.173-.008-.371-.01-.57-.01-.198 0-.52.074-.792.372-.272.297-1.04 1.016-1.04 2.479 0 1.462 1.065 2.875 1.213 3.074.149.198 2.096 3.2 5.077 4.487.709.306 1.262.489 1.694.625.712.227 1.36.195 1.871.118.571-.085 1.758-.719 2.006-1.413.248-.694.248-1.289.173-1.413-.074-.124-.272-.198-.57-.347m-5.421 7.403h-.004a9.87 9.87 0 01-5.031-1.378l-.361-.214-3.741.982.998-3.648-.235-.374a9.86 9.86 0 01-1.51-5.26c.001-5.45 4.436-9.884 9.888-9.884 2.64 0 5.122 1.03 6.988 2.898a9.825 9.825 0 012.893 6.994c-.003 5.45-4.437 9.884-9.885 9.884m8.413-18.297A11.815 11.815 0 0012.05 0C5.495 0 .16 5.335.157 11.892c0 2.096.547 4.142 1.588 5.945L.057 24l6.305-1.654a11.882 11.882 0 005.683 1.448h.005c6.554 0 11.89-5.335 11.893-11.893A11.821 11.821 0 0020.451 3.488'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

.icon-maps::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M12 0C7.589 0 4 3.589 4 8c0 7.5 8 16 8 16s8-8.5 8-16c0-4.411-3.589-8-8-8zm0 11c-1.657 0-3-1.343-3-3s1.343-3 3-3 3 1.343 3 3-1.343 3-3 3z'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

.icon-website::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M12 0C5.373 0 0 5.373 0 12s5.373 12 12 12 12-5.373 12-12S18.627 0 12 0zm5.568 8.16c-.169-.137-.277-.17-.277-.17s.508.154.508.463-.241.618-.336.618c-.096 0-.387-.394-.387-.394s-.277.437-.617.644c-.34.207-.736.305-1.173.305s-.814-.098-1.155-.305c-.34-.207-.617-.644-.617-.644s-.291-.394-.387-.394c-.095 0-.336.309-.336.618s.508.463.508.463-.108.033-.277.17z'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

/* Snapchat Icon (black) */
.icon-snapchat::before {
    content: '';
    width: 24px;
    height: 24px;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='%23000'%3E%3Cpath d='M12 2.25c2.485 0 4.5 2.015 4.5 4.5 0 .63-.132 1.212-.368 1.742.534.39 1.035.98 1.283 1.854.11.385.16.792.16 1.235 0 1.29-.462 2.034-1.029 2.64.151.144.32.276.502.392.43.276.924.45 1.356.584.29.09.51.35.51.655 0 .412-.36.72-.76.72-.237 0-.48-.072-.72-.148-.202-.064-.41-.13-.62-.18-.32-.078-.63-.126-.89-.126-.186 0-.35.027-.49.084-.19.078-.326.22-.412.41-.232.51-.604.95-1.078 1.25-.51.32-1.14.49-1.88.49-.51 0-1.02-.08-1.5-.23-.48.15-.99.23-1.5.23-.74 0-1.37-.17-1.88-.49-.474-.3-.846-.74-1.078-1.25-.086-.19-.223-.332-.412-.41-.14-.057-.304-.084-.49-.084-.26 0-.57.048-.89.126-.21.05-.418.116-.62.18-.24.076-.483.148-.72.148-.4 0-.76-.308-.76-.72 0-.305.22-.565.51-.655.432-.134.926-.308 1.356-.584.182-.116.351-.248.502-.392-.567-.606-1.029-1.35-1.029-2.64 0-.443.05-.85.16-1.235.248-.874.749-1.464 1.283-1.854A4.45 4.45 0 0 1 7.5 6.75c0-2.485 2.015-4.5 4.5-4.5z'/%3E%3C/svg%3E");
    background-size: contain;
    background-repeat: no-repeat;
    background-position: center;
    display: block;
}

.social-card-content {
    flex: 1;
    text-align: right;
}

.social-card h3 {
    color: #2a2a2a;
    margin-bottom: 0.3rem;
    font-size: 1.1rem;
    font-weight: 600;
    text-decoration: none;
}

.social-card p {
    color: #666;
    margin-bottom: 0;
    line-height: 1.4;
    font-size: 0.9rem;
    text-decoration: none;
}

/* Mini icons use the same SVGs via a span.glyph with the icon-* classes */
.mini-icon .glyph.icon-facebook { background-image: inherit; }
.mini-icon .glyph.icon-instagram { background-image: inherit; }
.mini-icon .glyph.icon-telegram { background-image: inherit; }
.mini-icon .glyph.icon-whatsapp { background-image: inherit; }
.mini-icon .glyph.icon-maps { background-image: inherit; }

.social-link {
    display: none; /* Hide the separate link as the whole card is clickable */
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

/* Developer Footer */
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

/* Responsive Design */
@media (max-width: 768px) {
    .header-content {
        flex-direction: column;
        gap: 1.5rem;
        text-align: center;
    }
    
    .nav-menu {
        flex-wrap: wrap;
        justify-content: center;
    }
    
    .hero h2 {
        font-size: 2.2rem;
    }
    
    .section-title {
        font-size: 1.8rem;
    }
    
    .social-links {
        flex-direction: column;
        gap: 0.5rem;
    }
    
    .location-content, .social-section {
        padding: 2rem;
    }
    
    .location-grid, .social-grid {
        grid-template-columns: 1fr;
    }
    
    .social-grid {
        max-width: 100%;
    }

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

/* Mobile Responsive Design */
@media (max-width: 768px) {
    .header-top { 
        flex-direction: column; 
        gap: 1rem; 
        text-align: center; 
    }
    
    .nav-menu { 
        flex-wrap: wrap; 
        justify-content: center; 
    }
    
    .hero h2 {
        font-size: 2.2rem;
    }
    
    .hero p {
        font-size: 1.1rem;
    }
    
    .about-content,
    .location-content,
    .social-section {
        padding: 2rem;
    }
    
    .about-text {
        font-size: 1.1rem;
    }
    
    .location-grid {
        grid-template-columns: 1fr;
        gap: 1.5rem;
    }
    
    .info-card {
        text-align: center;
        padding: 1.5rem;
        border-right: none;
        border-top: 4px solid #c0c0c0;
    }
    
    .phone-number {
        direction: ltr !important;
        text-align: center !important;
        display: block !important;
        font-weight: 600;
        color: #2a2a2a;
        font-size: 1.1rem;
    }
    
    .map-container {
        height: 300px;
    }
}

@media (max-width: 480px) {
    .hero {
        padding: 3rem 0;
    }
    
    .hero h2 {
        font-size: 1.8rem;
    }
    
    .hero p {
        font-size: 1rem;
    }
    
    .about-content,
    .location-content,
    .social-section {
        padding: 1.5rem;
        margin: 2rem 0;
    }
    
    .about-text {
        font-size: 1rem;
    }
    
    .info-card {
        padding: 1.2rem;
    }
    
    .info-card h3 {
        font-size: 1.1rem;
    }
    
    .info-card p {
        font-size: 0.9rem;
    }
    
    .social-card {
        padding: 1rem;
        min-height: 60px;
    }
    
    .social-icon {
        width: 40px;
        height: 40px;
        font-size: 1rem;
    }
    
    .map-container {
        height: 250px;
    }
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
                    <a href="index.php" class="nav-link">سەرەکی</a>
                    <a href="allbooks.php" class="nav-link">هەموو کتێبەکان</a>
                    <a href="chatbot.php" class="nav-link">چات بۆت</a>
                    <a href="about.php" class="nav-link active">دەربارە</a>

                </nav>
            </div>
        </div>
    </header>

  
    <!-- Social Media Section -->
    <section class="social-section">
        <div class="container">
            <div class="section-header">
                <h2 class="section-title">سۆشیاڵ میدیاکانمان</h2>
                <p class="section-subtitle">لە گەڵماندا پەیوەست بن</p>
                <div class="social-mini">
                    <a href="https://www.facebook.com/ktebxany.ashti" class="mini-icon facebook" title="Facebook"><span class="social-icon icon-facebook"></span></a>
                    <a href="https://www.instagram.com/ktebxanay.ashti/" class="mini-icon instagram" title="Instagram"><span class="social-icon icon-instagram"></span></a>
                    <a href="https://t.me/ktebxanai1ashti" class="mini-icon telegram" title="Telegram"><span class="social-icon icon-telegram"></span></a>
                    <a href="https://wa.me/9647503866000" class="mini-icon whatsapp" title="WhatsApp"><span class="social-icon icon-whatsapp"></span></a>
                    <a href="https://www.snapchat.com/add/ktebxanayashti" class="mini-icon snapchat" title="Snapchat"><span class="social-icon icon-snapchat"></span></a>
                    <a href="index.php" class="mini-icon maps" title="Website"><span class="social-icon icon-website"></span></a>
                </div>
            </div>
            
            <div class="social-grid">
                <a id="facebook" href="https://www.facebook.com/ktebxany.ashti" target="_blank" class="social-card facebook">
                    <div class="social-icon icon-facebook"></div>
                    <div class="social-card-content">
                        <h3>Facebook</h3>
                        <p>نوێترین کتێبەکان و بەرهەمە تازەکانمان ببینن</p>
                    </div>
                </a>
                
                <a id="instagram" href="https://www.instagram.com/ktebxanay.ashti/" target="_blank" class="social-card instagram">
                    <div class="social-icon icon-instagram"></div>
                    <div class="social-card-content">
                        <h3>Instagram</h3>
                        <p>وێنەکانی کتێبەکان و چالاکیەکانی کتێبخانە</p>
                    </div>
                </a>
                
                <a id="telegram" href="https://t.me/ktebxanai1ashti" target="_blank" class="social-card telegram">
                    <div class="social-icon icon-telegram"></div>
                    <div class="social-card-content">
                        <h3>Telegram</h3>
                        <p>گروپی تایبەتمان بۆ پرسیار و خزمەتگوزاری</p>
                    </div>
                </a>
                
                <a id="telegram-channel" href="https://t.me/ashtibookstore" target="_blank" class="social-card telegram">
                    <div class="social-icon icon-telegram"></div>
                    <div class="social-card-content">
                        <h3>Telegram Channel</h3>
                        <p>کەناڵی فەرمیمان بۆ ئاگادارکردنەوەکان</p>
                    </div>
                </a>
                
                <a id="whatsapp" href="https://wa.me/9647503866000" target="_blank" class="social-card whatsapp">
                    <div class="social-icon icon-whatsapp"></div>
                    <div class="social-card-content">
                        <h3>WhatsApp</h3>
                        <p>پەیوەندی راستەوخۆ بۆ داواکردن و پرسیار</p>
                    </div>
                </a>
                
                <a id="snapchat" href="https://www.snapchat.com/add/ktebxanayashti" target="_blank" class="social-card snapchat">
                    <div class="social-icon icon-snapchat"></div>
                    <div class="social-card-content">
                        <h3>Snapchat</h3>
                        <p>@ktebxanayashti</p>
                    </div>
                </a>
                
                <a id="website" href="index.php" class="social-card website">
                    <div class="social-icon icon-website"></div>
                    <div class="social-card-content">
                        <h3>وێبسایتی کتێبخانە</h3>
                        <p>گەڕانەوە بۆ پەیجی سەرەکی کتێبەکان</p>
                    </div>
                </a>
            </div>
        </div>
    </section>

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
                    <div class="info-card">
                        <h3>نەخشەی گووگڵ</h3>
                        <p><a href="https://maps.app.goo.gl/qwt2qHbjN68D7TTdA" target="_blank" style="color: #2a2a2a; text-decoration: underline;">کلیک بکە بۆ بینینی شوێن</a></p>
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
                <a href="https://maps.app.goo.gl/qwt2qHbjN68D7TTdA" target="_blank">Google Maps</a>
                <a href="https://www.facebook.com/ktebxany.ashti" target="_blank">Facebook</a>
                <a href="https://t.me/ktebxanai1ashti" target="_blank">Telegram</a>
                <a href="https://t.me/ashtibookstore" target="_blank">Telegram Channel</a>
                <a href="https://wa.me/9647503866000" target="_blank">WhatsApp</a>
                <a href="https://www.instagram.com/ktebxanay.ashti/" target="_blank">Instagram</a>
            </div>
        </div>
    </footer>

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

        // Social card hover effects
        document.querySelectorAll('.social-card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.transform = 'translateY(-3px) scale(1.02)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.transform = 'translateY(0) scale(1)';
            });
        });
    </script>
</body>
</html>