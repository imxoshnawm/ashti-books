<?php
// api/index.php - Complete Ashti Library API

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-API-Key');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

require_once '../config.php';
require_once '../gemini_api.php';

class AshtiLibraryCompleteAPI {
    private $conn;
    private $api_key;
    private $user_permissions;
    
    private $valid_api_keys = [
        'ashti-web-2024' => [
            'name' => 'Website Access',
            'permissions' => ['chat', 'books:read', 'categories:read', 'contact:read']
        ],
        'ashti-mobile-2024' => [
            'name' => 'Mobile App',
            'permissions' => ['chat', 'books:read', 'categories:read', 'favorites:write']
        ],
        'ashti-admin-2024' => [
            'name' => 'Admin Panel',
            'permissions' => ['*'] // هەموو شتێک
        ],
        'ashti-partner-2024' => [
            'name' => 'Partner Integration', 
            'permissions' => ['books:read', 'categories:read']
        ]
    ];
    
    public function __construct($database) {
        $this->conn = $database;
        $this->authenticate();
        $this->checkRateLimit();
    }
    
    private function authenticate() {
        $api_key = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? null;
        
        if (!$api_key || !isset($this->valid_api_keys[$api_key])) {
            $this->sendError(401, 'INVALID_API_KEY', 'Invalid or missing API key');
        }
        
        $this->api_key = $api_key;
        $this->user_permissions = $this->valid_api_keys[$api_key]['permissions'];
    }
    
    private function hasPermission($permission) {
        return in_array('*', $this->user_permissions) || in_array($permission, $this->user_permissions);
    }
    
    private function requirePermission($permission) {
        if (!$this->hasPermission($permission)) {
            $this->sendError(403, 'PERMISSION_DENIED', "Permission required: $permission");
        }
    }
    
    private function checkRateLimit() {
        $limits = [
            'ashti-web-2024' => 100,
            'ashti-mobile-2024' => 200,
            'ashti-admin-2024' => 1000,
            'ashti-partner-2024' => 50
        ];
        
        $max_requests = $limits[$this->api_key] ?? 60;
        $rate_limit_file = "rate_limits/" . md5($this->api_key) . ".txt";
        
        if (!file_exists("rate_limits")) {
            mkdir("rate_limits", 0755, true);
        }
        
        $now = time();
        $requests = [];
        
        if (file_exists($rate_limit_file)) {
            $data = file_get_contents($rate_limit_file);
            $requests = $data ? json_decode($data, true) : [];
        }
        
        $requests = array_filter($requests, function($timestamp) use ($now) {
            return ($now - $timestamp) < 3600; // 1 کاتژمێر
        });
        
        if (count($requests) >= $max_requests) {
            $this->sendError(429, 'RATE_LIMIT_EXCEEDED', 'Rate limit exceeded', ['retry_after' => 3600]);
        }
        
        $requests[] = $now;
        file_put_contents($rate_limit_file, json_encode($requests));
    }
    
    private function sendError($code, $error_code, $message, $extra = []) {
        http_response_code($code);
        echo json_encode(array_merge([
            'success' => false,
            'error' => [
                'code' => $error_code,
                'message' => $message
            ],
            'timestamp' => date('c')
        ], $extra));
        exit;
    }
    
    private function sendResponse($data, $meta = []) {
        echo json_encode([
            'success' => true,
            'data' => $data,
            'meta' => array_merge([
                'timestamp' => date('c'),
                'api_version' => '1.0'
            ], $meta)
        ]);
    }
    
    public function route() {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = $_SERVER['REQUEST_URI'];
        $path = parse_url($path, PHP_URL_PATH);
        $path = str_replace('/api', '', $path);
        $segments = array_filter(explode('/', $path));
        $segments = array_values($segments);
        
        if (empty($segments)) {
            $this->sendResponse(['message' => 'Ashti Library API v1.0', 'endpoints' => $this->getEndpoints()]);
            return;
        }
        
        $resource = $segments[0];
        $id = $segments[1] ?? null;
        $action = $segments[2] ?? null;
        
        switch ($resource) {
            case 'chat':
                $this->handleChat($method);
                break;
            case 'books':
                $this->handleBooks($method, $id, $action);
                break;
            case 'categories':
                $this->handleCategories($method, $id);
                break;
            case 'admin':
                $this->handleAdmin($method, $id, $action);
                break;
            case 'stats':
                $this->handleStats($method);
                break;
            case 'search':
                $this->handleSearch($method);
                break;
            default:
                $this->sendError(404, 'ENDPOINT_NOT_FOUND', 'Endpoint not found');
        }
    }
    
    private function getEndpoints() {
        return [
            'GET /' => 'API information',
            'POST /chat' => 'Chat with AI assistant',
            'GET /books' => 'Get books list',
            'GET /books/{id}' => 'Get specific book',
            'POST /books' => 'Add new book (admin)',
            'PUT /books/{id}' => 'Update book (admin)',
            'DELETE /books/{id}' => 'Delete book (admin)',
            'GET /categories' => 'Get categories',
            'GET /search' => 'Search books and content',
            'GET /stats' => 'Get statistics',
            'POST /admin/login' => 'Admin login',
            'GET /admin/dashboard' => 'Admin dashboard data'
        ];
    }
    
    // CHAT ENDPOINTS
    private function handleChat($method) {
        if ($method !== 'POST') {
            $this->sendError(405, 'METHOD_NOT_ALLOWED', 'Only POST allowed');
        }
        
        $this->requirePermission('chat');
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['message']) || empty(trim($input['message']))) {
            $this->sendError(400, 'MISSING_MESSAGE', 'Message is required');
        }
        
        $user_message = trim($input['message']);
        $session_id = $input['session_id'] ?? uniqid('api_', true);
        
        try {
            // کۆدی چاتبۆت - هەمان کۆدی ئێستات
            $gemini = new GeminiAPI('AIzaSyCSoM4kaauuUGE-5hvkK1eAjMydx9JPySk');
            $book_system = new BookRecommendationSystem($this->conn);
            
            $relevant_books = $book_system->getRelevantBooks($user_message);
            $books_context = $book_system->formatBooksForAI($relevant_books);
            
            $ai_result = $gemini->generateContent($user_message, $books_context);
            
            if (!$ai_result['success']) {
                throw new Exception($ai_result['error']);
            }
            
            // Save to database
            $this->saveChatSession($session_id, $user_message, $ai_result['response'], $relevant_books);
            
            $this->sendResponse([
                'response' => $ai_result['response'],
                'session_id' => $session_id,
                'books_found' => count($relevant_books),
                'books' => array_map([$this, 'formatBook'], $relevant_books)
            ]);
            
        } catch (Exception $e) {
            error_log("Chat API Error: " . $e->getMessage());
            $this->sendError(500, 'CHAT_ERROR', 'Failed to process chat message');
        }
    }
    
    // BOOKS ENDPOINTS
    private function handleBooks($method, $id, $action) {
        switch ($method) {
            case 'GET':
                if ($id) {
                    $this->getBook($id);
                } else {
                    $this->getBooks();
                }
                break;
            case 'POST':
                $this->requirePermission('books:write');
                $this->createBook();
                break;
            case 'PUT':
                $this->requirePermission('books:write');
                $this->updateBook($id);
                break;
            case 'DELETE':
                $this->requirePermission('books:write');
                $this->deleteBook($id);
                break;
            default:
                $this->sendError(405, 'METHOD_NOT_ALLOWED', 'Method not allowed');
        }
    }
    
    private function getBooks() {
        $this->requirePermission('books:read');
        
        $page = max(1, intval($_GET['page'] ?? 1));
        $limit = min(50, max(1, intval($_GET['limit'] ?? 20)));
        $offset = ($page - 1) * $limit;
        
        $category = $_GET['category'] ?? null;
        $search = $_GET['search'] ?? null;
        $featured = $_GET['featured'] ?? null;
        $bestseller = $_GET['bestseller'] ?? null;
        $sort = $_GET['sort'] ?? 'created_date';
        $order = $_GET['order'] ?? 'DESC';
        
        $where_conditions = ["status = 'active'"];
        $params = [];
        
        if ($category) {
            $where_conditions[] = "category_id = ?";
            $params[] = $category;
        }
        
        if ($search) {
            $where_conditions[] = "(book_title LIKE ? OR author LIKE ? OR description LIKE ?)";
            $search_term = '%' . $search . '%';
            $params[] = $search_term;
            $params[] = $search_term;
            $params[] = $search_term;
        }
        
        if ($featured === '1') {
            $where_conditions[] = "is_featured = 1";
        }
        
        if ($bestseller === '1') {
            $where_conditions[] = "is_bestseller = 1";
        }
        
        $where_clause = implode(' AND ', $where_conditions);
        $order_clause = "ORDER BY $sort $order";
        
        // Get total count
        $count_sql = "SELECT COUNT(*) as total FROM books WHERE $where_clause";
        $count_stmt = $this->conn->prepare($count_sql);
        $count_stmt->execute($params);
        $total = $count_stmt->fetchColumn();
        
        // Get books
        $sql = "SELECT * FROM books WHERE $where_clause $order_clause LIMIT $limit OFFSET $offset";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute($params);
        $books = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $this->sendResponse([
            'books' => array_map([$this, 'formatBook'], $books),
            'pagination' => [
                'page' => $page,
                'limit' => $limit,
                'total' => intval($total),
                'pages' => ceil($total / $limit)
            ]
        ]);
    }
    
    private function getBook($id) {
        $this->requirePermission('books:read');
        
        $sql = "SELECT * FROM books WHERE book_id = ? AND status = 'active'";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$id]);
        $book = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$book) {
            $this->sendError(404, 'BOOK_NOT_FOUND', 'Book not found');
        }
        
        $this->sendResponse(['book' => $this->formatBook($book)]);
    }
    
    private function createBook() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $required = ['book_title', 'author', 'price', 'category_id'];
        foreach ($required as $field) {
            if (!isset($input[$field]) || empty($input[$field])) {
                $this->sendError(400, 'MISSING_FIELD', "Required field: $field");
            }
        }
        
        $sql = "INSERT INTO books (book_title, author, translator, price, genre, description, category_id, is_featured, is_bestseller, status, created_date) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'active', NOW())";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([
            $input['book_title'],
            $input['author'],
            $input['translator'] ?? null,
            $input['price'],
            $input['genre'] ?? null,
            $input['description'] ?? null,
            $input['category_id'],
            $input['is_featured'] ?? 0,
            $input['is_bestseller'] ?? 0
        ]);
        
        $book_id = $this->conn->lastInsertId();
        
        $this->sendResponse(['book_id' => $book_id, 'message' => 'کتێبەکە زیادکرا'], ['status' => 201]);
    }
    
    private function updateBook($id) {
        $input = json_decode(file_get_contents('php://input'), true);
        
        $fields = [];
        $params = [];
        
        $allowed_fields = ['book_title', 'author', 'translator', 'price', 'genre', 'description', 'category_id', 'is_featured', 'is_bestseller'];
        
        foreach ($allowed_fields as $field) {
            if (isset($input[$field])) {
                $fields[] = "$field = ?";
                $params[] = $input[$field];
            }
        }
        
        if (empty($fields)) {
            $this->sendError(400, 'NO_FIELDS', 'No fields to update');
        }
        
        $params[] = $id;
        $sql = "UPDATE books SET " . implode(', ', $fields) . " WHERE book_id = ?";
        
        $stmt = $this->conn->prepare($sql);
        $result = $stmt->execute($params);
        
        if ($stmt->rowCount() === 0) {
            $this->sendError(404, 'BOOK_NOT_FOUND', 'Book not found or no changes made');
        }
        
        $this->sendResponse(['message' => 'کتێبەکە نوێکرایەوە']);
    }
    
    private function deleteBook($id) {
        $sql = "UPDATE books SET status = 'deleted' WHERE book_id = ?";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$id]);
        
        if ($stmt->rowCount() === 0) {
            $this->sendError(404, 'BOOK_NOT_FOUND', 'Book not found');
        }
        
        $this->sendResponse(['message' => 'کتێبەکە سڕایەوە']);
    }
    
    // CATEGORIES ENDPOINTS
    private function handleCategories($method, $id) {
        if ($method !== 'GET') {
            $this->sendError(405, 'METHOD_NOT_ALLOWED', 'Only GET allowed');
        }
        
        $this->requirePermission('categories:read');
        
        if ($id) {
            $this->getCategory($id);
        } else {
            $this->getCategories();
        }
    }
    
    private function getCategories() {
        $sql = "SELECT c.*, COUNT(b.book_id) as book_count 
                FROM categories c 
                LEFT JOIN books b ON c.category_id = b.category_id AND b.status = 'active'
                GROUP BY c.category_id 
                ORDER BY c.category_name";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute();
        $categories = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $this->sendResponse(['categories' => $categories]);
    }
    
    private function getCategory($id) {
        $sql = "SELECT * FROM categories WHERE category_id = ?";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$id]);
        $category = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$category) {
            $this->sendError(404, 'CATEGORY_NOT_FOUND', 'Category not found');
        }
        
        $this->sendResponse(['category' => $category]);
    }
    
    // SEARCH ENDPOINT
    private function handleSearch($method) {
        if ($method !== 'GET') {
            $this->sendError(405, 'METHOD_NOT_ALLOWED', 'Only GET allowed');
        }
        
        $this->requirePermission('books:read');
        
        $query = $_GET['q'] ?? '';
        if (empty($query)) {
            $this->sendError(400, 'MISSING_QUERY', 'Search query required');
        }
        
        $search_term = '%' . $query . '%';
        
        $sql = "SELECT b.*, c.category_name 
                FROM books b 
                LEFT JOIN categories c ON b.category_id = c.category_id 
                WHERE b.status = 'active' 
                AND (b.book_title LIKE ? OR b.author LIKE ? OR b.description LIKE ?)
                ORDER BY 
                    CASE WHEN b.book_title LIKE ? THEN 1 
                         WHEN b.author LIKE ? THEN 2 
                         ELSE 3 END,
                    b.book_title
                LIMIT 20";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$search_term, $search_term, $search_term, $search_term, $search_term]);
        $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $this->sendResponse([
            'results' => array_map([$this, 'formatBook'], $results),
            'query' => $query,
            'count' => count($results)
        ]);
    }
    
    // ADMIN ENDPOINTS
    private function handleAdmin($method, $id, $action) {
        $this->requirePermission('*');
        
        if ($action === 'login' && $method === 'POST') {
            $this->adminLogin();
        } elseif ($action === 'dashboard' && $method === 'GET') {
            $this->adminDashboard();
        } else {
            $this->sendError(404, 'ADMIN_ENDPOINT_NOT_FOUND', 'Admin endpoint not found');
        }
    }
    
    private function adminLogin() {
        $input = json_decode(file_get_contents('php://input'), true);
        
        if (!isset($input['username']) || !isset($input['password'])) {
            $this->sendError(400, 'MISSING_CREDENTIALS', 'Username and password required');
        }
        
        // Check admin credentials
        $sql = "SELECT * FROM admin_users WHERE username = ? AND password = ? AND status = 'active'";
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([$input['username'], md5($input['password'])]); // Consider using password_hash instead
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$admin) {
            $this->sendError(401, 'INVALID_CREDENTIALS', 'Invalid username or password');
        }
        
        $this->sendResponse([
            'admin' => [
                'id' => $admin['admin_id'],
                'name' => $admin['admin_name'],
                'type' => $admin['admin_type']
            ],
            'message' => 'Login successful'
        ]);
    }
    
    private function adminDashboard() {
        // Get statistics
        $stats = [];
        
        // Total books
        $stmt = $this->conn->query("SELECT COUNT(*) FROM books WHERE status = 'active'");
        $stats['total_books'] = $stmt->fetchColumn();
        
        // Total categories
        $stmt = $this->conn->query("SELECT COUNT(*) FROM categories");
        $stats['total_categories'] = $stmt->fetchColumn();
        
        // Total chat sessions today
        $stmt = $this->conn->query("SELECT COUNT(*) FROM chat_sessions WHERE DATE(created_date) = CURDATE()");
        $stats['chats_today'] = $stmt->fetchColumn();
        
        // Recent books
        $stmt = $this->conn->query("SELECT * FROM books WHERE status = 'active' ORDER BY created_date DESC LIMIT 5");
        $recent_books = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        // Popular books (most mentioned in chats)
        $stmt = $this->conn->query("
            SELECT b.*, COUNT(cs.id) as mention_count 
            FROM books b 
            LEFT JOIN chat_sessions cs ON FIND_IN_SET(b.book_id, cs.books_mentioned) > 0 
            WHERE b.status = 'active' 
            GROUP BY b.book_id 
            ORDER BY mention_count DESC 
            LIMIT 5
        ");
        $popular_books = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $this->sendResponse([
            'stats' => $stats,
            'recent_books' => array_map([$this, 'formatBook'], $recent_books),
            'popular_books' => array_map([$this, 'formatBook'], $popular_books)
        ]);
    }
    
    // STATS ENDPOINT
    private function handleStats($method) {
        if ($method !== 'GET') {
            $this->sendError(405, 'METHOD_NOT_ALLOWED', 'Only GET allowed');
        }
        
        $this->requirePermission('books:read');
        
        $stats = [];
        
        // Basic counts
        $stmt = $this->conn->query("SELECT COUNT(*) FROM books WHERE status = 'active'");
        $stats['total_books'] = intval($stmt->fetchColumn());
        
        $stmt = $this->conn->query("SELECT COUNT(*) FROM categories");
        $stats['total_categories'] = intval($stmt->fetchColumn());
        
        // Books by category
        $stmt = $this->conn->query("
            SELECT c.category_name, COUNT(b.book_id) as book_count 
            FROM categories c 
            LEFT JOIN books b ON c.category_id = b.category_id AND b.status = 'active'
            GROUP BY c.category_id 
            ORDER BY book_count DESC
        ");
        $stats['books_by_category'] = $stmt->fetchAll(PDO::FETCH_ASSOC);
        
        $this->sendResponse(['stats' => $stats]);
    }
    
    // Helper Methods
    private function formatBook($book) {
        return [
            'id' => intval($book['book_id']),
            'title' => $book['book_title'],
            'author' => $book['author'],
            'translator' => $book['translator'],
            'price' => intval($book['price']),
            'genre' => $book['genre'],
            'description' => $book['description'],
            'category_id' => intval($book['category_id']),
            'category_name' => $book['category_name'] ?? null,
            'is_featured' => (bool)$book['is_featured'],
            'is_bestseller' => (bool)$book['is_bestseller'],
            'created_date' => $book['created_date']
        ];
    }
    
    private function saveChatSession($session_id, $message, $response, $books) {
        $book_ids = array_column($books, 'book_id');
        $books_mentioned = !empty($book_ids) ? implode(',', $book_ids) : null;
        
        $sql = "INSERT INTO chat_sessions (session_id, user_message, ai_response, books_mentioned, user_ip, user_agent, created_date, source, api_key) 
                VALUES (?, ?, ?, ?, ?, ?, NOW(), 'api', ?)";
        
        $stmt = $this->conn->prepare($sql);
        $stmt->execute([
            $session_id, $message, $response, $books_mentioned,
            $_SERVER['REMOTE_ADDR'] ?? null,
            $_SERVER['HTTP_USER_AGENT'] ?? null,
            $this->api_key
        ]);
    }
}

// Initialize API
try {
    // Update database schema
    try {
        $conn->exec("ALTER TABLE chat_sessions 
                     ADD COLUMN IF NOT EXISTS source VARCHAR(20) DEFAULT 'web',
                     ADD COLUMN IF NOT EXISTS api_key VARCHAR(50) NULL");
    } catch (Exception $e) {
        // Columns might exist
    }
    
    $api = new AshtiLibraryCompleteAPI($conn);
    $api->route();
    
} catch (Exception $e) {
    error_log("API Error: " . $e->getMessage());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => [
            'code' => 'INTERNAL_ERROR',
            'message' => 'Server error occurred'
        ],
        'timestamp' => date('c')
    ]);
}
?>