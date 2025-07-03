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
        // Clear any output buffers
        if (ob_get_level()) {
            ob_end_clean();
        }
        
        status_header(410);
        nocache_headers();
        header('HTTP/1.1 410 Gone');
        header('Status: 410 Gone');
        header('Content-Type: text/html; charset=utf-8');
        
        // Add SEO-friendly headers
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        
        // Custom 410 page content
        $custom_410_content = $this->get_option('security_410_page_content', '');
        
        if (!empty($custom_410_content)) {
            echo $custom_410_content;
        } else {
            echo $this->get_default_410_page($message);
        }
        
        exit;
    }

    private function get_default_410_page($message = 'Gone') {
        $site_name = get_bloginfo('name');
        $home_url = home_url();
        
        return '<!DOCTYPE html>
<html lang="en">
<head>
    <title>410 - Content Permanently Removed | ' . esc_html($site_name) . '</title>
    <meta name="robots" content="noindex, nofollow">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; 
            text-align: center; 
            padding: 50px 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #333;
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: white; 
            padding: 40px; 
            border-radius: 12px; 
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        h1 { 
            color: #e74c3c; 
            font-size: 3em;
            margin: 0 0 20px 0;
            font-weight: 300;
        }
        .status-code {
            font-size: 6em;
            font-weight: bold;
            color: #e74c3c;
            margin: 0;
            line-height: 1;
        }
        p { 
            color: #666; 
            line-height: 1.6; 
            font-size: 1.1em;
            margin: 20px 0;
        }
        .back-link { 
            display: inline-block;
            color: white;
            background: #3498db;
            text-decoration: none; 
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 500;
            transition: background 0.3s ease;
            margin-top: 20px;
        }
        .back-link:hover { 
            background: #2980b9;
        }
        .explanation {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #e74c3c;
        }
        .explanation h3 {
            margin: 0 0 10px 0;
            color: #e74c3c;
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="status-code">410</div>
        <h1>Content Permanently Removed</h1>
        <p>The content you are looking for has been permanently removed and is no longer available.</p>
        
        <div class="explanation">
            <h3>What does this mean?</h3>
            <p>A 410 status indicates that the content has been intentionally removed and will not be available again. This helps search engines understand that this content should be removed from their index.</p>
        </div>
        
        <p>You can:</p>
        <ul style="text-align: left; display: inline-block;">
            <li>Return to our homepage</li>
            <li>Use our search function to find similar content</li>
            <li>Browse our categories</li>
        </ul>
        
        <a href="' . esc_url($home_url) . '" class="back-link">← Return to Homepage</a>
    </div>
</body>
</html>';
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
            return true;
        }
        return false;
    }
}