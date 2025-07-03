<?php
// templates/410-page.php
// Custom 410 page for ModSecurity integration

// Prevent direct access and handle both WordPress and direct access
if (!defined('ABSPATH')) {
    // If accessed directly (from ModSecurity), try to load WordPress
    $wp_load_paths = array(
        dirname(dirname(dirname(dirname(__FILE__)))) . '/wp-load.php',
        dirname(dirname(dirname(dirname(dirname(__FILE__))))) . '/wp-load.php',
        $_SERVER['DOCUMENT_ROOT'] . '/wp-load.php'
    );
    
    $wp_loaded = false;
    foreach ($wp_load_paths as $wp_load_path) {
        if (file_exists($wp_load_path)) {
            require_once($wp_load_path);
            $wp_loaded = true;
            break;
        }
    }
    
    // If WordPress couldn't be loaded, use fallback values
    if (!$wp_loaded) {
        $site_name = 'Website';
        $home_url = '/';
        $custom_410_content = '';
    }
} else {
    $wp_loaded = true;
}

// Set proper headers
if (!headers_sent()) {
    status_header(410);
    nocache_headers();
    header('HTTP/1.1 410 Gone');
    header('Status: 410 Gone');
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-cache, no-store, must-revalidate');
    header('Pragma: no-cache');
    header('Expires: 0');
}

// Get custom 410 content from WordPress options (if available)
if ($wp_loaded && function_exists('get_option')) {
    $custom_410_content = get_option('security_410_page_content', '');
    $site_name = get_bloginfo('name');
    $home_url = home_url();
} else {
    $custom_410_content = '';
    $site_name = 'Website';
    $home_url = '/';
}

if (!empty($custom_410_content)) {
    echo $custom_410_content;
} else {
    // Default 410 page
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>410 - Content Permanently Removed | <?php echo esc_html($site_name); ?></title>
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
            .security-notice {
                background: #fff3cd;
                border: 1px solid #ffeaa7;
                padding: 15px;
                border-radius: 8px;
                margin: 20px 0;
                border-left: 4px solid #f39c12;
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
            
            <div class="security-notice">
                <h3>🛡️ Security Protection Active</h3>
                <p>This request was blocked by our security system because it appeared to be spam or malicious. If you believe this is an error, please contact us.</p>
            </div>
            
            <p>You can:</p>
            <ul style="text-align: left; display: inline-block;">
                <li>Return to our homepage</li>
                <li>Use our search function to find similar content</li>
                <li>Browse our categories</li>
            </ul>
            
            <a href="<?php echo esc_url($home_url); ?>" class="back-link">← Return to Homepage</a>
        </div>
    </body>
    </html>
    <?php
}

// Log the 410 response for analytics (if WordPress is loaded)
if ($wp_loaded && function_exists('get_option') && get_option('security_enable_seo_features', true)) {
    $log_entry = array(
        'url' => $_SERVER['REQUEST_URI'] ?? '',
        'reason' => 'ModSecurity 410 Block',
        'timestamp' => current_time('mysql'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0',
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

exit;
?>