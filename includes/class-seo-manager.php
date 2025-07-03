<?php
// includes/class-seo-manager.php

if (!defined('ABSPATH')) {
    exit;
}

class SEOManager {
    private $options_cache = array();
    
    private function get_option($key, $default = false) {
        if (!isset($this->options_cache[$key])) {
            $this->options_cache[$key] = get_option($key, $default);
        }
        return $this->options_cache[$key];
    }

    private function is_woocommerce_active() {
        return class_exists('WooCommerce');
    }

    public function init() {
        // CRITICAL: Run spam detection BEFORE any security checks
        add_action('plugins_loaded', array($this, 'handle_spam_urls'), 1);
        add_action('init', array($this, 'handle_spam_urls'), 1);
        add_action('template_redirect', array($this, 'handle_410_responses'), 1);
        add_action('wp_trash_post', array($this, 'store_deleted_post_url'));
        add_action('before_delete_post', array($this, 'store_deleted_post_url'));
        
        // Add admin hooks for 410 management
        add_action('admin_init', array($this, 'add_410_meta_box_hooks'));
        add_action('save_post', array($this, 'save_410_meta_box'));
        
        // Add bulk action for 410
        add_filter('bulk_actions-edit-post', array($this, 'add_410_bulk_action'));
        add_filter('bulk_actions-edit-page', array($this, 'add_410_bulk_action'));
        add_filter('handle_bulk_actions-edit-post', array($this, 'handle_410_bulk_action'), 10, 3);
        add_filter('handle_bulk_actions-edit-page', array($this, 'handle_410_bulk_action'), 10, 3);
        
        // Add spam logs submenu properly
        add_action('admin_menu', array($this, 'add_spam_logs_menu'), 20);
        
        // FIXED: Add rewrite rules for secure 410 page
        add_action('init', array($this, 'add_410_rewrite_rules'));
        add_filter('query_vars', array($this, 'add_410_query_vars'));
        add_action('template_redirect', array($this, 'handle_410_endpoint'));
        
        // Add caching headers
        add_action('wp_headers', array($this, 'add_410_cache_headers'));
    }

    // FIXED: Add secure 410 endpoint without exposing plugin directory
    public function add_410_rewrite_rules() {
        // Add rewrite rule for secure 410 page
        add_rewrite_rule(
            '^security-410/?$',
            'index.php?security_410=1',
            'top'
        );
        
        // Flush rewrite rules if needed
        if (!get_option('security_410_rules_flushed')) {
            flush_rewrite_rules();
            update_option('security_410_rules_flushed', true);
        }
    }
    
    public function add_410_query_vars($vars) {
        $vars[] = 'security_410';
        return $vars;
    }
    
    public function handle_410_endpoint() {
        if (get_query_var('security_410')) {
            $this->serve_cached_410_page();
        }
    }
    
    public function add_410_cache_headers($headers) {
        if (get_query_var('security_410')) {
            // Add aggressive caching for 410 pages
            $headers['Cache-Control'] = 'public, max-age=86400, s-maxage=86400'; // 24 hours
            $headers['Expires'] = gmdate('D, d M Y H:i:s', time() + 86400) . ' GMT';
            $headers['Pragma'] = 'cache';
            $headers['Vary'] = 'Accept-Encoding';
        }
        return $headers;
    }
    
    private function serve_cached_410_page() {
        // Check cache first
        $cache_key = 'security_410_page_cache';
        $cached_content = get_transient($cache_key);
        
        if ($cached_content !== false) {
            // Serve from cache
            $this->send_410_headers();
            echo $cached_content;
            exit;
        }
        
        // Generate and cache the 410 page
        $content = $this->generate_410_page_content();
        
        // Cache for 24 hours
        set_transient($cache_key, $content, 24 * HOUR_IN_SECONDS);
        
        // Serve the content
        $this->send_410_headers();
        echo $content;
        exit;
    }
    
    private function send_410_headers() {
        if (!headers_sent()) {
            status_header(410);
            nocache_headers();
            header('HTTP/1.1 410 Gone');
            header('Status: 410 Gone');
            header('Content-Type: text/html; charset=utf-8');
            header('X-Robots-Tag: noindex, nofollow');
            header('X-Content-Security: blocked');
            
            // Add caching headers for performance
            header('Cache-Control: public, max-age=86400, s-maxage=86400');
            header('Expires: ' . gmdate('D, d M Y H:i:s', time() + 86400) . ' GMT');
            header('Pragma: cache');
            header('Vary: Accept-Encoding');
        }
    }
    
    private function generate_410_page_content() {
        $site_name = get_bloginfo('name') ?: 'Wild Dragon';
        $home_url = home_url() ?: 'https://wilddragon.in';
        $site_description = get_bloginfo('description');
        $custom_410_content = $this->get_option('security_410_page_content', '');
        
        if (!empty($custom_410_content)) {
            return $custom_410_content;
        }
        
        // Enhanced default 410 page with Wild Dragon branding
        ob_start();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>410 - Content Permanently Removed | <?php echo esc_html($site_name); ?></title>
            <meta name="robots" content="noindex, nofollow">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <meta name="description" content="The requested content has been permanently removed from <?php echo esc_attr($site_name); ?>">
            <link rel="canonical" href="<?php echo esc_url($home_url); ?>">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                }
                
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
                    text-align: center; 
                    padding: 20px; 
                    background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%);
                    color: #333;
                    margin: 0;
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    line-height: 1.6;
                }
                
                .error-container { 
                    max-width: 700px; 
                    margin: 0 auto; 
                    background: white; 
                    padding: 50px 40px; 
                    border-radius: 16px; 
                    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
                    position: relative;
                    overflow: hidden;
                }
                
                .error-container::before {
                    content: '';
                    position: absolute;
                    top: 0;
                    left: 0;
                    right: 0;
                    height: 4px;
                    background: linear-gradient(90deg, #e74c3c, #f39c12, #e74c3c);
                }
                
                .logo-area {
                    margin-bottom: 30px;
                }
                
                .site-logo {
                    font-size: 2em;
                    font-weight: 900;
                    color: #1a1a2e;
                    margin-bottom: 10px;
                    text-transform: uppercase;
                    letter-spacing: 2px;
                }
                
                .status-code {
                    font-size: 8em;
                    font-weight: 900;
                    color: #e74c3c;
                    margin: 0 0 20px 0;
                    line-height: 1;
                    text-shadow: 2px 2px 4px rgba(0,0,0,0.1);
                }
                
                h1 { 
                    color: #2c3e50; 
                    font-size: 2.5em;
                    margin: 0 0 30px 0;
                    font-weight: 600;
                }
                
                .subtitle {
                    font-size: 1.2em;
                    color: #7f8c8d;
                    margin-bottom: 40px;
                    font-weight: 300;
                }
                
                p { 
                    color: #555; 
                    line-height: 1.8; 
                    font-size: 1.1em;
                    margin: 20px 0;
                }
                
                .back-link { 
                    display: inline-block;
                    color: white;
                    background: linear-gradient(135deg, #1a1a2e, #16213e);
                    text-decoration: none; 
                    padding: 15px 30px;
                    border-radius: 8px;
                    font-weight: 600;
                    font-size: 1.1em;
                    transition: all 0.3s ease;
                    margin: 30px 10px 10px 10px;
                    box-shadow: 0 4px 15px rgba(26, 26, 46, 0.3);
                }
                
                .back-link:hover { 
                    background: linear-gradient(135deg, #16213e, #0f3460);
                    transform: translateY(-2px);
                    box-shadow: 0 6px 20px rgba(26, 26, 46, 0.4);
                }
                
                .explanation {
                    background: #f8f9fa;
                    padding: 30px;
                    border-radius: 12px;
                    margin: 30px 0;
                    border-left: 5px solid #e74c3c;
                    text-align: left;
                }
                
                .explanation h3 {
                    margin: 0 0 15px 0;
                    color: #e74c3c;
                    font-size: 1.3em;
                }
                
                .security-notice {
                    background: linear-gradient(135deg, #fff3cd, #ffeaa7);
                    border: 1px solid #f39c12;
                    padding: 25px;
                    border-radius: 12px;
                    margin: 30px 0;
                    border-left: 5px solid #f39c12;
                    text-align: left;
                }
                
                .security-notice h3 {
                    color: #d68910;
                    margin: 0 0 15px 0;
                    font-size: 1.2em;
                }
                
                .actions-list {
                    text-align: left;
                    display: inline-block;
                    margin: 20px 0;
                }
                
                .actions-list li {
                    margin: 10px 0;
                    padding: 5px 0;
                    font-size: 1.1em;
                }
                
                .site-info {
                    margin-top: 40px;
                    padding-top: 30px;
                    border-top: 1px solid #ecf0f1;
                    color: #7f8c8d;
                    font-size: 0.9em;
                }
                
                .cache-info {
                    position: absolute;
                    bottom: 10px;
                    right: 15px;
                    font-size: 0.7em;
                    color: #bdc3c7;
                    opacity: 0.7;
                }
                
                @media (max-width: 768px) {
                    .error-container {
                        padding: 30px 20px;
                        margin: 20px;
                    }
                    
                    .status-code {
                        font-size: 5em;
                    }
                    
                    h1 {
                        font-size: 2em;
                    }
                    
                    .back-link {
                        display: block;
                        margin: 20px 0;
                    }
                }
            </style>
        </head>
        <body>
            <div class="error-container">
                <div class="logo-area">
                    <div class="site-logo"><?php echo esc_html($site_name); ?></div>
                </div>
                
                <div class="status-code">410</div>
                <h1>Content Permanently Removed</h1>
                <p class="subtitle">The content you are looking for is no longer available</p>
                
                <div class="explanation">
                    <h3>🔍 What does this mean?</h3>
                    <p>A 410 status indicates that the content has been intentionally removed and will not be available again. This helps search engines understand that this content should be removed from their index.</p>
                </div>
                
                <div class="security-notice">
                    <h3>🛡️ Security Protection Active</h3>
                    <p>This request was blocked by our security system because it contained excessive filter parameters. Our system protects against:</p>
                    <ul style="margin: 10px 0 0 20px;">
                        <li>Spam filter URLs with too many color/size combinations</li>
                        <li>Automated scraping attempts</li>
                        <li>Malicious bot requests</li>
                        <li>Invalid or suspicious URL patterns</li>
                    </ul>
                    <p style="margin-top: 15px;"><strong>Blocked URL pattern:</strong> Too many filter parameters detected</p>
                </div>
                
                <p><strong>What you can do:</strong></p>
                <ul class="actions-list">
                    <li>🏠 Return to our homepage</li>
                    <li>👕 Browse our men's collection</li>
                    <li>👗 Browse our women's collection</li>
                    <li>🔍 Use our search function</li>
                    <li>📧 Contact us if you believe this is an error</li>
                </ul>
                
                <a href="<?php echo esc_url($home_url); ?>" class="back-link">← Return to <?php echo esc_html($site_name); ?> Homepage</a>
                
                <div class="site-info">
                    <strong><?php echo esc_html($site_name); ?></strong><br>
                    Premium Fashion & Lifestyle Brand
                </div>
                
                <div class="cache-info">
                    Cached: <?php echo date('Y-m-d H:i:s'); ?>
                </div>
            </div>
            
            <!-- Structured Data for SEO -->
            <script type="application/ld+json">
            {
                "@context": "https://schema.org",
                "@type": "WebPage",
                "name": "410 - Content Permanently Removed",
                "description": "The requested content has been permanently removed",
                "url": "<?php echo esc_url($_SERVER['REQUEST_URI'] ?? ''); ?>",
                "isPartOf": {
                    "@type": "WebSite",
                    "name": "<?php echo esc_js($site_name); ?>",
                    "url": "<?php echo esc_url($home_url); ?>"
                }
            }
            </script>
        </body>
        </html>
        <?php
        return ob_get_clean();
    }

    public function handle_spam_urls() {
        // Skip admin area
        if (is_admin()) {
            return;
        }

        // Skip for logged-in users with manage capabilities
        if (is_user_logged_in() && current_user_can('manage_options')) {
            return;
        }

        $current_url = $_SERVER['REQUEST_URI'];
        
        // PRIORITY 1: Check for custom blocked paths (like /shop/)
        if ($this->is_custom_blocked_path($current_url)) {
            $this->send_410_response('Custom blocked path - Content permanently removed');
        }
        
        // PRIORITY 2: Check for WooCommerce spam URLs
        if ($this->is_woocommerce_active()) {
            if ($this->is_spam_filter_url($current_url)) {
                $this->send_410_response('Spam filter URL detected - Content permanently removed');
            }
        }

        // PRIORITY 3: Handle excessive query parameters
        if ($this->has_excessive_query_params($current_url)) {
            $this->send_410_response('Excessive query parameters - Content permanently removed');
        }

        // PRIORITY 4: Check for manually marked 410 URLs
        if ($this->is_manual_410_url($current_url)) {
            $this->send_410_response('Content permanently removed');
        }
    }

    private function is_custom_blocked_path($url) {
        $blocked_paths = get_option('security_modsec_custom_blocked_paths', '/shop/');
        $paths = array_filter(array_map('trim', explode("\n", $blocked_paths)));
        
        $parsed_url = parse_url($url);
        $path = $parsed_url['path'] ?? '';
        
        foreach ($paths as $blocked_path) {
            if (strpos($path, $blocked_path) === 0) {
                $this->log_spam_attempt($url, "Custom blocked path: {$blocked_path}");
                return true;
            }
        }
        
        return false;
    }

    private function is_spam_filter_url($url) {
        // Only run if WooCommerce is active
        if (!$this->is_woocommerce_active()) {
            return false;
        }

        // Parse URL to get query parameters
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['query'])) {
            return false;
        }

        parse_str($parsed_url['query'], $query_params);

        // Check if this is a product category or product page
        $path = $parsed_url['path'] ?? '';
        $is_product_page = (strpos($path, '/product-category/') !== false || strpos($path, '/product/') !== false);
        
        if (!$is_product_page) {
            return false;
        }

        // AGGRESSIVE SPAM DETECTION for your specific spam patterns
        
        // 1. Check for excessive color filters (your spam URLs have 15+ colors)
        if (isset($query_params['filter_colour']) || isset($query_params['filter_color'])) {
            $color_param = $query_params['filter_colour'] ?? $query_params['filter_color'];
            $colors = explode(',', $color_param);
            
            // If more than 2 colors, it's spam
            if (count($colors) > 2) {
                $this->log_spam_attempt($url, "Too many colors: " . count($colors) . " (spam threshold: >2)");
                return true;
            }
        }

        // 2. Check for excessive size filters
        if (isset($query_params['filter_size'])) {
            $sizes = explode(',', $query_params['filter_size']);
            
            // If more than 3 sizes, it's spam
            if (count($sizes) > 3) {
                $this->log_spam_attempt($url, "Too many sizes: " . count($sizes) . " (spam threshold: >3)");
                return true;
            }
        }

        // 3. Check for your specific spam color patterns
        $spam_color_patterns = array(
            'maroon,peace-orange,black,bottle-green,white,mint-green,yellow,red',
            'mustard-yellow,black,chocolate-brown,red,bottle-green,white,royal-blue',
            'baby-pink,chocolate-brown,dusty-pink,bottle-green,magenta,emerald-green'
        );

        $query_string = $parsed_url['query'];
        foreach ($spam_color_patterns as $pattern) {
            if (strpos($query_string, $pattern) !== false) {
                $this->log_spam_attempt($url, "Known spam color pattern detected: " . substr($pattern, 0, 50) . "...");
                return true;
            }
        }

        // 4. Check for your specific spam size patterns
        $spam_size_patterns = array(
            'too-large,s,xxl,l,large,xl',
            'medium,xl,too-large,large',
            'small,too-large,xxl,xl,l'
        );

        foreach ($spam_size_patterns as $pattern) {
            if (strpos($query_string, $pattern) !== false) {
                $this->log_spam_attempt($url, "Known spam size pattern detected: " . $pattern);
                return true;
            }
        }

        // 5. Check total filter count (your spam URLs have 20+ total filters)
        $total_filters = 0;
        $filter_params = array('filter_colour', 'filter_color', 'filter_size', 'filter_brand');
        
        foreach ($filter_params as $filter) {
            if (isset($query_params[$filter])) {
                $values = explode(',', $query_params[$filter]);
                $total_filters += count($values);
            }
        }

        // If total filters exceed 5, it's spam
        if ($total_filters > 5) {
            $this->log_spam_attempt($url, "Too many total filters: {$total_filters} (spam threshold: >5)");
            return true;
        }

        // 6. Check query string length (your spam URLs are very long)
        if (strlen($parsed_url['query']) > 300) {
            $this->log_spam_attempt($url, "Query string too long: " . strlen($parsed_url['query']) . " chars (spam threshold: >300)");
            return true;
        }

        return false;
    }

    private function log_spam_attempt($url, $reason) {
        // Log spam attempts for analysis
        $log_entry = array(
            'url' => $url,
            'reason' => $reason,
            'timestamp' => current_time('mysql'),
            'ip' => $this->get_client_ip(),
            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'
        );
        
        $spam_logs = get_option('security_spam_url_logs', array());
        $spam_logs[] = $log_entry;
        
        // Keep only last 200 entries
        if (count($spam_logs) > 200) {
            $spam_logs = array_slice($spam_logs, -200);
        }
        
        update_option('security_spam_url_logs', $spam_logs);
    }

    private function get_client_ip() {
        $ip_keys = array('HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 'HTTP_CLIENT_IP', 'REMOTE_ADDR');
        
        foreach ($ip_keys as $key) {
            if (!empty($_SERVER[$key])) {
                $ip = $_SERVER[$key];
                if (strpos($ip, ',') !== false) {
                    $ip = trim(explode(',', $ip)[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        
        return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function has_excessive_query_params($url) {
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['query'])) {
            return false;
        }

        parse_str($parsed_url['query'], $query_params);
        
        // Check total number of query parameters
        if (count($query_params) > 8) {
            $this->log_spam_attempt($url, "Too many query parameters: " . count($query_params) . " (max: 8)");
            return true;
        }

        return false;
    }

    private function is_manual_410_url($url) {
        $manual_410_urls = get_option('security_manual_410_urls', array());
        $path = parse_url($url, PHP_URL_PATH);
        
        return in_array($path, $manual_410_urls) || in_array($url, $manual_410_urls);
    }

    public function handle_410_responses() {
        global $wp_query;

        // Handle 410 for deleted posts
        if (is_404()) {
            $current_url = $_SERVER['REQUEST_URI'];
            $deleted_urls = get_option('security_deleted_post_urls', array());
            
            if (in_array($current_url, $deleted_urls)) {
                $this->send_410_response('Content permanently removed');
            }
        }

        // Handle posts marked as 410
        if (is_single() || is_page()) {
            global $post;
            if ($post && get_post_meta($post->ID, '_send_410_response', true)) {
                $this->send_410_response('Content permanently removed');
            }
        }
    }

    public function store_deleted_post_url($post_id) {
        $post = get_post($post_id);
        if (!$post) {
            return;
        }

        $post_url = parse_url(get_permalink($post_id), PHP_URL_PATH);
        $deleted_urls = get_option('security_deleted_post_urls', array());
        
        if (!in_array($post_url, $deleted_urls)) {
            $deleted_urls[] = $post_url;
            // Keep only last 1000 deleted URLs to prevent database bloat
            if (count($deleted_urls) > 1000) {
                $deleted_urls = array_slice($deleted_urls, -1000);
            }
            update_option('security_deleted_post_urls', $deleted_urls);
        }
    }

    public function add_410_meta_box_hooks() {
        add_action('add_meta_boxes', array($this, 'add_410_meta_box'));
    }

    public function add_410_meta_box() {
        $post_types = get_post_types(array('public' => true));
        foreach ($post_types as $post_type) {
            add_meta_box(
                'seo_410_response',
                '410 Response Settings',
                array($this, 'render_410_meta_box'),
                $post_type,
                'side',
                'default'
            );
        }
    }

    public function render_410_meta_box($post) {
        wp_nonce_field('seo_410_meta_box', 'seo_410_nonce');
        $send_410 = get_post_meta($post->ID, '_send_410_response', true);
        ?>
        <p>
            <label>
                <input type="checkbox" name="send_410_response" value="1" <?php checked($send_410); ?>>
                Send 410 (Gone) response for this content
            </label>
        </p>
        <p class="description">
            When enabled, this page will return a 410 "Gone" status instead of displaying content. 
            This tells search engines the content has been permanently removed.
        </p>
        <?php
    }

    public function save_410_meta_box($post_id) {
        if (!isset($_POST['seo_410_nonce']) || !wp_verify_nonce($_POST['seo_410_nonce'], 'seo_410_meta_box')) {
            return;
        }

        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return;
        }

        if (!current_user_can('edit_post', $post_id)) {
            return;
        }

        if (isset($_POST['send_410_response'])) {
            update_post_meta($post_id, '_send_410_response', 1);
        } else {
            delete_post_meta($post_id, '_send_410_response');
        }
    }

    public function add_410_bulk_action($bulk_actions) {
        $bulk_actions['mark_410'] = 'Mark as 410 (Gone)';
        $bulk_actions['unmark_410'] = 'Remove 410 Status';
        return $bulk_actions;
    }

    public function handle_410_bulk_action($redirect_to, $doaction, $post_ids) {
        if ($doaction === 'mark_410') {
            foreach ($post_ids as $post_id) {
                update_post_meta($post_id, '_send_410_response', 1);
            }
            $redirect_to = add_query_arg('marked_410', count($post_ids), $redirect_to);
        } elseif ($doaction === 'unmark_410') {
            foreach ($post_ids as $post_id) {
                delete_post_meta($post_id, '_send_410_response');
            }
            $redirect_to = add_query_arg('unmarked_410', count($post_ids), $redirect_to);
        }
        
        return $redirect_to;
    }

    public function add_spam_logs_menu() {
        add_submenu_page(
            'security-settings',
            'Spam URL Logs',
            'Spam Logs',
            'manage_options',
            'security-spam-logs',
            array($this, 'render_spam_logs_page')
        );
    }

    public function render_spam_logs_page() {
        if (!current_user_can('manage_options')) {
            wp_die('You do not have sufficient permissions to access this page.');
        }

        // Handle clear logs action
        if (isset($_POST['clear_logs']) && check_admin_referer('clear_spam_logs', 'spam_logs_nonce')) {
            $this->clear_spam_logs();
            echo '<div class="notice notice-success"><p>Spam logs cleared successfully.</p></div>';
        }

        $spam_logs = $this->get_spam_logs();
        ?>
        <div class="wrap">
            <h1>Spam URL Logs</h1>
            <p>This page shows URLs that have been blocked with 410 (Gone) responses due to spam detection.</p>
            
            <form method="post" style="margin-bottom: 20px;">
                <?php wp_nonce_field('clear_spam_logs', 'spam_logs_nonce'); ?>
                <input type="submit" name="clear_logs" class="button" value="Clear All Logs" 
                       onclick="return confirm('Are you sure you want to clear all spam logs?');">
            </form>

            <?php if (empty($spam_logs)): ?>
                <div class="notice notice-info">
                    <p>No spam URLs have been detected yet.</p>
                </div>
            <?php else: ?>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>URL</th>
                            <th>Reason</th>
                            <th>IP Address</th>
                            <th>User Agent</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_reverse($spam_logs) as $log): ?>
                            <tr>
                                <td><?php echo esc_html($log['timestamp']); ?></td>
                                <td style="word-break: break-all; max-width: 300px;">
                                    <code><?php echo esc_html($log['url']); ?></code>
                                </td>
                                <td><?php echo esc_html($log['reason']); ?></td>
                                <td><?php echo esc_html($log['ip']); ?></td>
                                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;">
                                    <?php echo esc_html(substr($log['user_agent'], 0, 100)); ?>
                                    <?php if (strlen($log['user_agent']) > 100): ?>...<?php endif; ?>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <p><strong>Total spam URLs blocked:</strong> <?php echo count($spam_logs); ?></p>
            <?php endif; ?>
        </div>
        <?php
    }

    private function send_410_response($message = 'Gone') {
        // FIXED: Redirect to secure cached 410 endpoint instead of direct response
        $secure_410_url = home_url('/security-410/');
        
        // Log the blocked request
        $this->log_spam_attempt($_SERVER['REQUEST_URI'], $message);
        
        // Redirect to secure 410 page
        wp_redirect($secure_410_url, 301);
        exit;
    }

    public function clean_url_for_seo($url) {
        // Only run WooCommerce-specific cleaning if WooCommerce is active
        if (!$this->is_woocommerce_active()) {
            return $url;
        }

        // Remove excessive parameters while keeping essential ones
        $parsed_url = parse_url($url);
        if (!isset($parsed_url['query'])) {
            return $url;
        }

        parse_str($parsed_url['query'], $query_params);
        
        // Keep only essential WooCommerce parameters with strict limits
        $essential_params = array(
            'filter_colour' => 2, // Max 2 colors
            'filter_color' => 2,  // Max 2 colors (alternative spelling)
            'filter_size' => 2,   // Max 2 sizes
            'orderby' => true,
            'order' => true,
            'paged' => true,
            'per_page' => true,
            'in-stock' => true,
            'on-sale' => true,
            'on-backorder' => true,
            'featured' => true
        );

        $cleaned_params = array();
        foreach ($essential_params as $param => $limit) {
            if (isset($query_params[$param])) {
                if (is_numeric($limit)) {
                    // Limit multiple values
                    $values = explode(',', $query_params[$param]);
                    $cleaned_params[$param] = implode(',', array_slice($values, 0, $limit));
                } else {
                    $cleaned_params[$param] = $query_params[$param];
                }
            }
        }

        if (empty($cleaned_params)) {
            return $parsed_url['path'];
        }

        return $parsed_url['path'] . '?' . http_build_query($cleaned_params);
    }

    // Admin method to manually add URLs to 410 list
    public function add_manual_410_url($url) {
        if (!current_user_can('manage_options')) {
            return false;
        }
        
        $manual_410_urls = get_option('security_manual_410_urls', array());
        $path = parse_url($url, PHP_URL_PATH);
        
        if (!in_array($path, $manual_410_urls)) {
            $manual_410_urls[] = $path;
            update_option('security_manual_410_urls', $manual_410_urls);
            return true;
        }
        
        return false;
    }

    // Get spam logs for admin review
    public function get_spam_logs() {
        return get_option('security_spam_url_logs', array());
    }

    // Clear spam logs
    public function clear_spam_logs() {
        if (current_user_can('manage_options')) {
            delete_option('security_spam_url_logs');
            // Clear 410 page cache when logs are cleared
            delete_transient('security_410_page_cache');
            return true;
        }
        return false;
    }
    
    // FIXED: Add method to clear 410 page cache
    public function clear_410_cache() {
        delete_transient('security_410_page_cache');
    }
}