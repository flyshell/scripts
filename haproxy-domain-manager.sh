#!/bin/bash

# HAProxy 域名管理器 - 支援多檔案配置
# 版本: 2.0
# 作者: Auto Generated
# 用途: 自動管理域名、SSL憑證和HAProxy配置

set -euo pipefail

# 配置目錄
CONFIG_DIR="/etc/haproxy"
SITES_DIR="/etc/haproxy/sites"
SSL_DIR="/etc/haproxy/ssl"
DOMAINS_DIR="$SITES_DIR"  # 為了保持向下相容
SSL_CERTS_LIST="$SSL_DIR/ssl-certificates.txt"
MAIN_CONFIG="$CONFIG_DIR/haproxy.cfg"

# 創建必要目錄
create_directories() {
    mkdir -p "$CONFIG_DIR" "$SITES_DIR" "$SSL_DIR"
    chown -R haproxy:haproxy "$CONFIG_DIR" "$SITES_DIR" "$SSL_DIR" 2>/dev/null || true
}

# 日誌函數
info() {
    echo -e "\033[32m[INFO]\033[0m $1"
}

success() {
    echo -e "\033[32m[SUCCESS]\033[0m $1"
}

warning() {
    echo -e "\033[33m[WARNING]\033[0m $1"
}

error() {
    echo -e "\033[31m[ERROR]\033[0m $1"
}

# 備份配置
backup_config() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_dir="/etc/haproxy/backups/$timestamp"
    
    mkdir -p "$backup_dir"
    
    # 備份主配置
    if [ -f "$MAIN_CONFIG" ]; then
        cp "$MAIN_CONFIG" "$backup_dir/"
        info "主配置已備份到: $backup_dir/"
    fi
    
    # 備份站點配置
    if [ -d "$SITES_DIR" ] && [ "$(ls -A $SITES_DIR 2>/dev/null)" ]; then
        cp -r "$SITES_DIR" "$backup_dir/"
        info "站點配置已備份到: $backup_dir/"
    fi
    
    # 備份 SSL 配置
    if [ -d "$SSL_DIR" ] && [ "$(ls -A $SSL_DIR 2>/dev/null)" ]; then
        cp -r "$SSL_DIR" "$backup_dir/"
        info "SSL 配置已備份到: $backup_dir/"
    fi
}

# 初始化主配置文件
init_main_config() {
    info "初始化主配置文件..."
    
    cat > "$MAIN_CONFIG" << 'EOF'
global
    log         127.0.0.1:514 local0
    chroot      /var/lib/haproxy
    stats       socket /run/haproxy/admin.sock mode 660 level admin expose-fd listeners
    stats       timeout 30s
    user        haproxy
    group       haproxy
    daemon
    
    # SSL 配置
    ssl-default-bind-ciphers ECDHE+AESGCM:ECDHE+CHACHA20:RSA+AESGCM:RSA+AES:!aNULL:!MD5:!DSS
    ssl-default-bind-options ssl-min-ver TLSv1.2 no-tls-tickets

defaults
    mode                    http
    log                     global
    option                  httplog
    option                  dontlognull
    option                  http-server-close
    option                  forwardfor       except 127.0.0.0/8
    option                  redispatch
    retries                 3
    timeout http-request    10s
    timeout queue           1m
    timeout connect         10s
    timeout client          1m
    timeout server          1m
    timeout http-keep-alive 10s
    timeout check           10s
    maxconn                 3000

# 統計頁面
listen stats
    bind *:8404
    stats enable
    stats uri /
    stats refresh 30s
    stats admin if TRUE
EOF

    success "主配置文件已初始化"
}

# 初始化共用前端配置
init_frontend_config() {
    local frontend_config="$SITES_DIR/00-frontend.cfg"
    
    info "初始化前端配置..."
    
    cat > "$frontend_config" << 'EOF'
# 主前端配置
frontend main_frontend
    bind *:80
    
    # 條件性綁定 HTTPS（只有在有 SSL 憑證時）
    # 註解：如果沒有 SSL 憑證，會在添加第一個域名時啟用 HTTPS

    # 安全性標頭（僅對 HTTPS）
    http-response set-header X-Frame-Options DENY if { ssl_fc }
    http-response set-header X-Content-Type-Options nosniff if { ssl_fc }
    http-response set-header X-XSS-Protection "1; mode=block" if { ssl_fc }
    http-response set-header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" if { ssl_fc }

    # ACME Challenge 處理 (最高優先級)
    use_backend acme_challenge if { path_beg /.well-known/acme-challenge/ }
    
    # HTTP 重導向到 HTTPS (除了 ACME Challenge，且僅在有 SSL 憑證時)
    # 註解：會在有 SSL 憑證後動態啟用
    
    # 預設後端（當沒有匹配的域名時）
    default_backend default_backend

# ACME Challenge 後端
backend acme_challenge
    server acme-server 127.0.0.1:8888 check

# 預設後端
backend default_backend
    http-request return status 404 content-type text/html string "<h1>404 Not Found</h1><p>Domain not configured</p>"
EOF

    success "前端配置已初始化"
}

# 更新前端配置以啟用 HTTPS
update_frontend_for_ssl() {
    local frontend_config="$SITES_DIR/00-frontend.cfg"
    
    info "更新前端配置以啟用 HTTPS..."
    
    # 檢查是否有有效的 SSL 憑證
    if [ -s "$SSL_CERTS_LIST" ] && [ "$(grep -v '^#' "$SSL_CERTS_LIST" | wc -l)" -gt 0 ]; then
        # 更新前端配置以包含 HTTPS 綁定
        sed -i 's|^    # 條件性綁定 HTTPS.*|    bind *:443 ssl crt-list /etc/haproxy/ssl/ssl-certificates.txt|' "$frontend_config"
        sed -i 's|^    # 註解：如果沒有 SSL 憑證.*||' "$frontend_config"
        
        # 啟用 HTTP 到 HTTPS 重導向
        sed -i 's|^    # HTTP 重導向到 HTTPS.*|    http-request redirect scheme https code 301 unless { ssl_fc } or { path_beg /.well-known/acme-challenge/ }|' "$frontend_config"
        sed -i 's|^    # 註解：會在有 SSL 憑證後動態啟用||' "$frontend_config"
        
        success "前端配置已更新以支援 HTTPS"
    else
        warning "沒有有效的 SSL 憑證，HTTPS 綁定保持停用狀態"
    fi
}

# 產生域名站點配置
generate_site_config() {
    local domain=$1
    local backends="$2"
    local site_config="$SITES_DIR/${domain}.cfg"
    
    info "生成 $domain 的站點配置..."
    
    cat > "$site_config" << EOF
# 域名: $domain
# 後端: $backends
# 創建時間: $(date)
# 配置文件: ${domain}.cfg

# $domain 域名路由
frontend main_frontend
    # $domain 主域名路由
    use_backend ${domain//./_}_backend if { hdr(host) -i $domain } or { ssl_fc_sni $domain }
EOF

    # 檢查是否為主域名（沒有子域名），如果是則添加 www 重導向
    local domain_parts=$(echo "$domain" | tr '.' '\n' | wc -l)
    if [ $domain_parts -eq 2 ]; then
        cat >> "$site_config" << EOF
    
    # WWW 重導向到主域名
    http-request redirect location https://$domain%[capture.req.uri] code 301 if { hdr(host) -i www.$domain } or { ssl_fc_sni www.$domain }
EOF
    fi

    cat >> "$site_config" << EOF

# $domain 後端配置
backend ${domain//./_}_backend
    balance roundrobin
    option httpclose
    option forwardfor
    option httpchk GET /
    
EOF

    # 添加後端服務器
    local IFS=','
    local server_count=1
    for backend in $backends; do
        cat >> "$site_config" << EOF
    server ${domain//./_}_server${server_count} $backend check inter 5000 rise 2 fall 3
EOF
        ((server_count++))
    done
    
    echo "" >> "$site_config"
    
    success "$domain 的站點配置已生成: $site_config"
}

# 更新 SSL 憑證清單
update_ssl_list() {
    info "更新 SSL 憑證清單..."
    
    # 確保 SSL 目錄存在
    mkdir -p "$SSL_DIR"
    
    # 重新生成憑證清單
    > "$SSL_CERTS_LIST"
    
    local cert_count=0
    
    # 只處理包含私鑰的 HAProxy SSL 憑證
    for cert_file in /etc/ssl/certs/*.pem; do
        if [ -f "$cert_file" ]; then
            # 檢查文件是否包含私鑰（HAProxy 格式）
            if grep -q "BEGIN PRIVATE KEY" "$cert_file" || grep -q "BEGIN RSA PRIVATE KEY" "$cert_file"; then
                # 進一步檢查是否包含憑證
                if grep -q "BEGIN CERTIFICATE" "$cert_file"; then
                    echo "$cert_file" >> "$SSL_CERTS_LIST"
                    ((cert_count++))
                    success "添加 SSL 憑證: $(basename "$cert_file")"
                fi
            fi
        fi
    done
    
    if [ $cert_count -gt 0 ]; then
        success "SSL 憑證清單已更新: $cert_count 個有效憑證"
    else
        warning "沒有找到有效的 HAProxy SSL 憑證"
        echo "# No valid HAProxy SSL certificates found" > "$SSL_CERTS_LIST"
        echo "# HAProxy SSL certificates must contain both certificate and private key" >> "$SSL_CERTS_LIST"
    fi
}

# 測試配置
test_config() {
    info "測試 HAProxy 配置..."
    
    local config_files="-f $MAIN_CONFIG"
    
    # 添加所有站點配置文件
    if [ -d "$SITES_DIR" ]; then
        for site_config in "$SITES_DIR"/*.cfg; do
            if [ -f "$site_config" ]; then
                config_files="$config_files -f $site_config"
            fi
        done
    fi
    
    if haproxy -c $config_files; then
        success "HAProxy 配置測試通過"
        return 0
    else
        error "HAProxy 配置測試失敗"
        return 1
    fi
}

# 重載 HAProxy
reload_haproxy() {
    info "重載 HAProxy..."
    
    if systemctl is-active --quiet haproxy; then
        systemctl reload haproxy
        success "HAProxy 已重載"
    else
        systemctl start haproxy
        success "HAProxy 已啟動"
    fi
}

# 更新 systemd 服務配置以支援多檔案
update_systemd_config() {
    info "更新 systemd 服務配置..."
    
    # 創建 systemd override 目錄
    mkdir -p /etc/systemd/system/haproxy.service.d
    
    # 創建 override 配置
    cat > /etc/systemd/system/haproxy.service.d/override.conf << 'EOF'
[Service]
ExecStart=
ExecStart=/usr/sbin/haproxy -Ws -f /etc/haproxy/haproxy.cfg -f /etc/haproxy/sites/ -p /run/haproxy.pid
ExecReload=/bin/kill -USR2 $MAINPID
EOF

    # 重載 systemd
    systemctl daemon-reload
    
    success "systemd 服務配置已更新"
}

# 添加域名
add_domain() {
    local domain=$1
    local backends=$2
    
    if [ -z "$domain" ] || [ -z "$backends" ]; then
        error "用法: $0 add <domain> <backend1:port,backend2:port>"
        exit 1
    fi
    
    info "添加域名: $domain"
    info "後端服務器: $backends"
    
    # 備份配置
    backup_config
    
    # 生成站點配置
    generate_site_config "$domain" "$backends"
    
    # 生成 SSL 憑證
    info "生成 SSL 憑證..."
    if /usr/local/bin/dehydrated --cron --domain "$domain"; then
        success "SSL 憑證生成成功"
        update_ssl_list
        update_frontend_for_ssl
    else
        error "SSL 憑證生成失敗"
        exit 1
    fi
    
    # 測試並重載配置
    if test_config; then
        reload_haproxy
        success "域名 $domain 已成功添加"
        
        # 顯示狀態
        echo ""
        info "訪問資訊:"
        echo "  HTTP:  http://$domain"
        echo "  HTTPS: https://$domain"
        echo "  配置:  $SITES_DIR/${domain}.cfg"
        echo "  憑證:  /etc/ssl/certs/${domain}.pem"
    else
        error "配置測試失敗，請檢查配置"
        exit 1
    fi
}

# 移除域名
remove_domain() {
    local domain=$1
    
    if [ -z "$domain" ]; then
        error "用法: $0 remove <domain>"
        exit 1
    fi
    
    info "移除域名: $domain"
    
    # 備份配置
    backup_config
    
    # 移除站點配置文件
    if [ -f "$SITES_DIR/${domain}.cfg" ]; then
        rm -f "$SITES_DIR/${domain}.cfg"
        success "已移除站點配置: $SITES_DIR/${domain}.cfg"
    else
        warning "站點配置文件不存在: $SITES_DIR/${domain}.cfg"
    fi
    
    # 移除 SSL 憑證
    if [ -f "/etc/ssl/certs/${domain}.pem" ]; then
        rm -f "/etc/ssl/certs/${domain}.pem"
        success "已移除 SSL 憑證: /etc/ssl/certs/${domain}.pem"
    else
        warning "SSL 憑證文件不存在: /etc/ssl/certs/${domain}.pem"
    fi
    
    # 更新 SSL 清單
    update_ssl_list
    
    # 測試並重載配置
    if test_config; then
        reload_haproxy
        success "域名 $domain 已成功移除"
    else
        error "配置測試失敗，請檢查配置"
        exit 1
    fi
}

# 列出所有域名
list_domains() {
    info "已配置的域名:"
    echo ""
    
    if [ ! -d "$SITES_DIR" ] || [ ! "$(ls -A $SITES_DIR/*.cfg 2>/dev/null)" ]; then
        warning "沒有找到任何域名配置"
        return
    fi
    
    printf "%-30s %-20s %-30s\n" "域名" "狀態" "配置文件"
    printf "%-30s %-20s %-30s\n" "----" "----" "----------"
    
    for config_file in "$SITES_DIR"/*.cfg; do
        if [ -f "$config_file" ]; then
            local basename=$(basename "$config_file" .cfg)
            
            # 跳過前端配置文件
            if [ "$basename" = "00-frontend" ]; then
                continue
            fi
            
            local domain="$basename"
            local status="❌ 無憑證"
            
            if [ -f "/etc/ssl/certs/${domain}.pem" ]; then
                # 檢查憑證是否即將過期
                local expiry=$(openssl x509 -enddate -noout -in "/etc/ssl/certs/${domain}.pem" | cut -d= -f2)
                local expiry_epoch=$(date -d "$expiry" +%s)
                local current_epoch=$(date +%s)
                local days_left=$(( (expiry_epoch - current_epoch) / 86400 ))
                
                if [ $days_left -lt 7 ]; then
                    status="⚠️  即將過期 ($days_left 天)"
                elif [ $days_left -lt 30 ]; then
                    status="🟡 $days_left 天後過期"
                else
                    status="✅ 有效 ($days_left 天)"
                fi
            fi
            
            printf "%-30s %-20s %-30s\n" "$domain" "$status" "$(basename $config_file)"
        fi
    done
}

# 重新載入所有配置
reload_all() {
    info "重新載入所有配置..."
    
    # 備份配置
    backup_config
    
    # 更新 SSL 清單
    update_ssl_list
    
    # 測試並重載配置
    if test_config; then
        reload_haproxy
        success "所有配置已重新載入"
    else
        error "配置測試失敗，請檢查配置"
        exit 1
    fi
}

# 初始化整個系統
init_system() {
    info "初始化 HAProxy 多檔案管理系統..."
    
    # 創建目錄
    create_directories
    
    # 備份現有配置
    if [ -f "$MAIN_CONFIG" ]; then
        backup_config
    fi
    
    # 初始化配置文件
    init_main_config
    init_frontend_config
    
    # 更新 systemd 配置
    update_systemd_config
    
    # 更新 SSL 清單
    update_ssl_list
    
    # 測試配置
    if test_config; then
        success "HAProxy 多檔案管理系統初始化完成"
        
        echo ""
        info "系統資訊:"
        echo "  主配置:   $MAIN_CONFIG"
        echo "  站點目錄: $SITES_DIR"
        echo "  SSL 目錄: $SSL_DIR"
        echo "  統計頁面: http://your-server:8404"
        echo ""
        info "使用方法:"
        echo "  添加域名: $0 add domain.com 127.0.0.1:8001,127.0.0.1:8002"
        echo "  移除域名: $0 remove domain.com"
        echo "  列出域名: $0 list"
        echo "  重新載入: $0 reload"
    else
        error "初始化失敗，請檢查配置"
        exit 1
    fi
}

# 顯示幫助
show_help() {
    echo "HAProxy 域名管理器 v2.0 - 多檔案配置支援"
    echo ""
    echo "用法: $0 <command> [arguments]"
    echo ""
    echo "命令:"
    echo "  init                     - 初始化系統"
    echo "  add <domain> <backends>  - 添加域名"
    echo "  remove <domain>          - 移除域名"
    echo "  list                     - 列出所有域名"
    echo "  reload                   - 重新載入配置"
    echo "  test                     - 測試配置"
    echo "  help                     - 顯示此幫助"
    echo ""
    echo "範例:"
    echo "  $0 init"
    echo "  $0 add example.com 127.0.0.1:8001,127.0.0.1:8002"
    echo "  $0 remove example.com"
    echo "  $0 list"
    echo "  $0 reload"
    echo ""
    echo "檔案結構:"
    echo "  /etc/haproxy/haproxy.cfg     - 主配置檔案"
    echo "  /etc/haproxy/sites/*.cfg     - 站點配置檔案"
    echo "  /etc/haproxy/ssl/            - SSL 相關檔案"
}

# 主函數
main() {
    case "${1:-}" in
        "init")
            init_system
            ;;
        "add")
            add_domain "${2:-}" "${3:-}"
            ;;
        "remove")
            remove_domain "${2:-}"
            ;;
        "list")
            list_domains
            ;;
        "reload")
            reload_all
            ;;
        "test")
            test_config
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        *)
            error "未知命令: ${1:-}"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# 檢查是否為 root
if [ "$EUID" -ne 0 ]; then
    error "請使用 root 權限執行此腳本"
    exit 1
fi

# 確保必要目錄存在
create_directories

# 執行主函數
main "$@"
