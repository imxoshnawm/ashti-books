<?php
header('Content-Type: application/json; charset=utf-8');
require_once 'config.php';
require_once 'gemini_api.php';

// CORS headers بۆ Ajax requests
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'error' => 'تەنها POST method پەسەند کراوە']);
    exit;
}

// Get input data
$input = json_decode(file_get_contents('php://input'), true);

if (!isset($input['message']) || empty(trim($input['message']))) {
    echo json_encode(['success' => false, 'error' => 'پەیامەکە نابێت بەتاڵ بێت']);
    exit;
}

$user_message = trim($input['message']);

try {
    // Initialize API with your key
    $gemini = new GeminiAPI('AIzaSyCSoM4kaauuUGE-5hvkK1eAjMydx9JPySk');
    
    // Initialize book recommendation system
    $book_system = new BookRecommendationSystem($conn);
    
    // Get relevant books based on user message
    $relevant_books = $book_system->getRelevantBooks($user_message);
    $books_context = $book_system->formatBooksForAI($relevant_books);
    
    // Generate session ID if not exists
    if (!isset($_SESSION['chat_session_id'])) {
        $_SESSION['chat_session_id'] = uniqid('chat_', true);
    }
    
    $session_id = $_SESSION['chat_session_id'];
    
    // Get AI response
    $ai_result = $gemini->generateContent($user_message, $books_context);
    
    if (!$ai_result['success']) {
        throw new Exception($ai_result['error']);
    }
    
    $ai_response = $ai_result['response'];
    
    // Extract book IDs that were mentioned (for analytics)
    $book_ids = [];
    foreach ($relevant_books as $book) {
        $book_ids[] = $book['book_id'];
    }
    $books_mentioned = !empty($book_ids) ? implode(',', $book_ids) : null;
    
    // Save chat to database
    $save_sql = "INSERT INTO chat_sessions (session_id, user_message, ai_response, books_mentioned, user_ip, user_agent, created_date) 
                 VALUES (?, ?, ?, ?, ?, ?, NOW())";
    
    $save_stmt = $conn->prepare($save_sql);
    $save_stmt->execute([
        $session_id,
        $user_message,
        $ai_response,
        $books_mentioned,
        $_SERVER['REMOTE_ADDR'] ?? null,
        $_SERVER['HTTP_USER_AGENT'] ?? null
    ]);
    
    // Add to session history for immediate display
    if (!isset($_SESSION['chat_history'])) {
        $_SESSION['chat_history'] = [];
    }
    
    $_SESSION['chat_history'][] = [
        'type' => 'user',
        'content' => $user_message,
        'time' => date('H:i')
    ];
    
    $_SESSION['chat_history'][] = [
        'type' => 'bot',
        'content' => $ai_response,
        'time' => date('H:i')
    ];
    
    // Keep only last 20 messages in session to prevent memory issues
    if (count($_SESSION['chat_history']) > 40) {
        $_SESSION['chat_history'] = array_slice($_SESSION['chat_history'], -40);
    }
    
    // Return success response
    echo json_encode([
        'success' => true,
        'response' => $ai_response,
        'books_found' => count($relevant_books),
        'session_id' => $session_id
    ]);
    
} catch (Exception $e) {
    // Log error (you might want to implement proper logging)
    error_log("Chatbot API Error: " . $e->getMessage());
    
    // Return fallback response
    echo json_encode([
        'success' => true,
        'response' => 'ببورە، لە ئێستادا نایتوانم یارمەتیت بدەم. تکایە دواتر هەوڵبدەرەوە یان بە ڕاستەوخۆ لەگەڵ کارمەندەکانمان پەیوەندی بکە.',
        'books_found' => 0
    ]);
}
?>