#!/bin/bash

# HAProxy 域名自動化管理腳本
# 支援 dehydrated 和 certbot
# 使用方式: ./haproxy-domain-manager.sh add example.com 10.0.4.5:8002,10.0.4.6:8002

set -e

# 配置常數
HAPROXY_DIR="/etc/haproxy"
DOMAINS_DIR="$HAPROXY_DIR/domains"
BACKENDS_DIR="$HAPROXY_DIR/backends"
SSL_DIR="$HAPROXY_DIR/ssl"
ERRORS_DIR="$HAPROXY_DIR/errors"
MAIN_CONFIG="$HAPROXY_DIR/haproxy.cfg"
SSL_CERT_LIST="$SSL_DIR/ssl-certificates.txt"
BACKUP_DIR="$HAPROXY_DIR/backups"

# SSL 工具配置 (選擇 dehydrated 或 certbot)
SSL_TOOL="dehydrated"  # 或 "certbot"
DEHYDRATED_DIR="/etc/dehydrated"
CERTBOT_DIR="/etc/letsencrypt"

# 日誌配置
LOG_FILE="/var/log/haproxy-domain-manager.log"

# 顏色定義
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 記錄函數
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}ERROR: $1${NC}" >&2
    log "ERROR: $1"
    exit 1
}

info() {
    echo -e "${BLUE}INFO: $1${NC}"
    log "INFO: $1"
}

success() {
    echo -e "${GREEN}SUCCESS: $1${NC}"
    log "SUCCESS: $1"
}

warning() {
    echo -e "${YELLOW}WARNING: $1${NC}"
    log "WARNING: $1"
}

# 檢查並初始化 SSL 工具
check_ssl_tool_init() {
    if [ "$SSL_TOOL" = "dehydrated" ]; then
        # 檢查 dehydrated 是否已註冊
        if [ ! -f "/etc/dehydrated/accounts/*/account_key.pem" ] 2>/dev/null; then
            info "首次使用 dehydrated，正在註冊..."
            
            # 自動接受服務條款並註冊
            if ! dehydrated --register --accept-terms >/dev/null 2>&1; then
                error "dehydrated 註冊失敗，請手動執行: dehydrated --register --accept-terms"
            fi
            
            success "dehydrated 註冊成功"
        fi
    elif [ "$SSL_TOOL" = "certbot" ]; then
        # 檢查 certbot 是否已初始化
        if [ ! -d "/etc/letsencrypt/accounts" ]; then
            info "首次使用 certbot，正在初始化..."
            
            # 創建虛擬憑證以初始化 certbot
            if ! certbot register --agree-tos --email "$CONTACT_EMAIL" --no-eff-email >/dev/null 2>&1; then
                warning "certbot 初始化失敗，但可能仍能正常工作"
            fi
        fi
    fi
}

# 檢查依賴
check_dependencies() {
    info "檢查依賴工具..."
    
    # 檢查 HAProxy
    if ! command -v haproxy &> /dev/null; then
        error "HAProxy 未安裝"
    fi
    
    # 檢查 SSL 工具
    if [ "$SSL_TOOL" = "dehydrated" ]; then
        if ! command -v dehydrated &> /dev/null; then
            error "dehydrated 未安裝"
        fi
        # 檢查並初始化 dehydrated
        check_ssl_tool_init
    elif [ "$SSL_TOOL" = "certbot" ]; then
        if ! command -v certbot &> /dev/null; then
            error "certbot 未安裝"
        fi
        # 檢查並初始化 certbot
        check_ssl_tool_init
    fi
    
    # 檢查 jq (用於 JSON 處理)
    if ! command -v jq &> /dev/null; then
        warning "jq 未安裝，建議安裝以獲得更好的 JSON 處理能力"
    fi
}

# 初始化目錄結構
init_directories() {
    info "初始化目錄結構..."
    
    mkdir -p "$DOMAINS_DIR" "$BACKENDS_DIR" "$SSL_DIR" "$ERRORS_DIR" "$BACKUP_DIR"
    
    # 建立 SSL 憑證清單文件
    if [ ! -f "$SSL_CERT_LIST" ]; then
        touch "$SSL_CERT_LIST"
    fi
    
    # 檢查並創建預設 SSL 憑證
    create_default_ssl_cert
    
    # 設定權限
    chown -R haproxy:haproxy "$HAPROXY_DIR"
    chmod 755 "$DOMAINS_DIR" "$BACKENDS_DIR" "$SSL_DIR" "$ERRORS_DIR"
    chmod 644 "$SSL_CERT_LIST"
}

# 創建預設 SSL 憑證
create_default_ssl_cert() {
    local default_cert="/etc/ssl/haproxy/default.pem"
    
    if [ ! -f "$default_cert" ]; then
        info "創建預設 SSL 憑證..."
        
        # 創建目錄
        mkdir -p /etc/ssl/haproxy
        
        # 生成自簽憑證
        openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/haproxy/default.key \
            -out /etc/ssl/haproxy/default.crt \
            -subj "/C=TW/ST=Taiwan/L=Taoyuan/O=HAProxy/CN=default.local" \
            >/dev/null 2>&1
        
        # 合併憑證文件
        cat /etc/ssl/haproxy/default.crt /etc/ssl/haproxy/default.key > "$default_cert"
        
        # 設定權限
        chmod 600 "$default_cert"
        chown haproxy:haproxy "$default_cert"
        
        # 清理臨時文件
        rm -f /etc/ssl/haproxy/default.key /etc/ssl/haproxy/default.crt
        
        success "預設 SSL 憑證已創建: $default_cert"
    fi
}

# 驗證域名格式
validate_domain() {
    local domain=$1
    
    if [[ ! "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        error "無效的域名格式: $domain"
    fi
}

# 檢查域名是否已存在
check_domain_exists() {
    local domain=$1
    
    if [ -f "$DOMAINS_DIR/${domain}.cfg" ]; then
        error "域名 $domain 已存在"
    fi
}

# 備份現有配置
backup_config() {
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/haproxy_backup_$timestamp.tar.gz"
    
    info "備份現有配置到 $backup_file"
    
    tar -czf "$backup_file" -C "$HAPROXY_DIR" \
        --exclude=backups \
        --exclude=ssl/*.pem \
        --exclude=ssl/*.key \
        .
    
    # 只保留最近 10 個備份
    ls -t "$BACKUP_DIR"/haproxy_backup_*.tar.gz | tail -n +11 | xargs -r rm
}

# 產生 SSL 憑證
generate_ssl_cert() {
    local domain=$1
    local cert_path=""
    
    info "為域名 $domain 產生 SSL 憑證..."
    
    if [ "$SSL_TOOL" = "dehydrated" ]; then
        # 使用 dehydrated
        if ! dehydrated --cron --domain "$domain" --domain "www.$domain"; then
            error "dehydrated 憑證產生失敗"
        fi
        
        # 合併憑證文件
        cert_path="/etc/ssl/certs/${domain}.pem"
        cat "$DEHYDRATED_DIR/certs/$domain/fullchain.pem" \
            "$DEHYDRATED_DIR/certs/$domain/privkey.pem" > "$cert_path"
            
    elif [ "$SSL_TOOL" = "certbot" ]; then
        # 使用 certbot
        if ! certbot certonly --webroot --webroot-path=/var/www/html \
            -d "$domain" -d "www.$domain" --non-interactive --agree-tos; then
            error "certbot 憑證產生失敗"
        fi
        
        # 合併憑證文件
        cert_path="/etc/ssl/certs/${domain}.pem"
        cat "$CERTBOT_DIR/live/$domain/fullchain.pem" \
            "$CERTBOT_DIR/live/$domain/privkey.pem" > "$cert_path"
    fi
    
    # 設定權限
    chmod 600 "$cert_path"
    chown haproxy:haproxy "$cert_path"
    
    # 添加到憑證清單
    if ! grep -q "$cert_path" "$SSL_CERT_LIST"; then
        echo "$cert_path" >> "$SSL_CERT_LIST"
    fi
    
    success "SSL 憑證已產生: $cert_path"
}

# 產生域名前端配置
generate_domain_config() {
    local domain=$1
    local config_file="$DOMAINS_DIR/${domain}.cfg"
    
    info "產生域名 $domain 的前端配置..."
    
    cat > "$config_file" << EOF
# $domain 的 ACL 和路由規則
# 自動產生於 $(date)

acl is_${domain//[.-]/_} hdr(host) -i $domain                    # 檢查是否為 $domain
acl has_www_${domain//[.-]/_} hdr(host) -i www.$domain           # 檢查是否有 www 前綴

# WWW 重導向 - 移除 www 前綴
redirect prefix https://$domain code 301 if has_www_${domain//[.-]/_}

# 路由到後端
use_backend ${domain//[.-]/_}_servers if is_${domain//[.-]/_}
EOF
    
    chmod 644 "$config_file"
    chown haproxy:haproxy "$config_file"
    
    success "域名配置已產生: $config_file"
}

# 產生後端配置
generate_backend_config() {
    local domain=$1
    local servers=$2
    local backend_file="$BACKENDS_DIR/${domain}-backend.cfg"
    
    info "產生域名 $domain 的後端配置..."
    
    cat > "$backend_file" << EOF
# $domain 後端服務器配置
# 自動產生於 $(date)

backend ${domain//[.-]/_}_servers
    balance roundrobin                                    # 負載均衡算法：輪詢
    
    # Sticky Session 配置
    cookie SERVERID insert indirect nocache              # Cookie 插入模式
    stick-table type string len 52 size 30k expire 30m  # 黏性表設定
    stick on cookie(JSESSIONID)                          # 基於 JSESSIONID 綁定
    
    # 健康檢查
    option httpchk GET /health-check HTTP/1.1\\r\\nHost:\\ $domain
    http-check expect status 200                         # 期望 HTTP 200 回應
    
    # 後端服務器定義
EOF
    
    # 解析服務器列表
    IFS=',' read -ra SERVER_LIST <<< "$servers"
    local server_count=1
    
    for server in "${SERVER_LIST[@]}"; do
        # 移除空白
        server=$(echo "$server" | xargs)
        
        # 驗證 IP:PORT 格式
        if [[ ! "$server" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+$ ]]; then
            error "無效的服務器格式: $server (應為 IP:PORT)"
        fi
        
        local server_name="${domain//[.-]/_}_${server_count}"
        echo "    server $server_name $server check cookie $server_name weight 100 maxconn 500" >> "$backend_file"
        ((server_count++))
    done
    
    # 添加錯誤頁面
    cat >> "$backend_file" << EOF
    
    # 錯誤頁面
    errorfile 503 $ERRORS_DIR/503-${domain}.http
EOF
    
    chmod 644 "$backend_file"
    chown haproxy:haproxy "$backend_file"
    
    success "後端配置已產生: $backend_file"
}

# 產生錯誤頁面
generate_error_page() {
    local domain=$1
    local error_file="$ERRORS_DIR/503-${domain}.http"
    
    info "產生域名 $domain 的錯誤頁面..."
    
    cat > "$error_file" << EOF
HTTP/1.0 503 Service Unavailable
Cache-Control: no-cache
Connection: close
Content-Type: text/html

<!DOCTYPE html>
<html>
<head>
    <title>服務暫時無法使用 - $domain</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; text-align: center; padding: 50px; }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { color: #e74c3c; }
        p { color: #666; line-height: 1.6; }
    </style>
</head>
<body>
    <div class="container">
        <h1>服務暫時無法使用</h1>
        <p>抱歉，$domain 的服務目前暫時無法使用。</p>
        <p>我們正在努力修復此問題，請稍後再試。</p>
        <p>如有緊急問題，請聯繫系統管理員。</p>
    </div>
</body>
</html>
EOF
    
    chmod 644 "$error_file"
    chown haproxy:haproxy "$error_file"
    
    success "錯誤頁面已產生: $error_file"
}

# 更新主配置文件
update_main_config() {
    local domain=$1
    
    info "更新主配置文件..."
    
    # 檢查是否已包含域名配置
    if grep -q "include.*domains/${domain}.cfg" "$MAIN_CONFIG"; then
        warning "域名 $domain 已在主配置文件中"
        return
    fi
    
    # 找到 include domains 區域，如果不存在則創建
    if ! grep -q "# Domain configurations" "$MAIN_CONFIG"; then
        # 在 frontend https_frontend 區域添加註釋
        sed -i '/frontend https_frontend/a\    \n    # Domain configurations' "$MAIN_CONFIG"
    fi
    
    # 添加域名配置引用
    sed -i "/# Domain configurations/a\    include $DOMAINS_DIR/${domain}.cfg" "$MAIN_CONFIG"
    
    # 添加後端配置引用
    if ! grep -q "# Backend configurations" "$MAIN_CONFIG"; then
        echo -e "\n# Backend configurations" >> "$MAIN_CONFIG"
    fi
    
    echo "include $BACKENDS_DIR/${domain}-backend.cfg" >> "$MAIN_CONFIG"
    
    success "主配置文件已更新"
}

# 測試 HAProxy 配置
test_haproxy_config() {
    info "測試 HAProxy 配置..."
    
    if ! haproxy -c -f "$MAIN_CONFIG"; then
        error "HAProxy 配置測試失敗"
    fi
    
    success "HAProxy 配置測試通過"
}

# 重載 HAProxy
reload_haproxy() {
    info "重載 HAProxy..."
    
    if ! systemctl reload haproxy; then
        error "HAProxy 重載失敗"
    fi
    
    success "HAProxy 已重載"
}

# 檢查系統狀態
check_system_status() {
    info "檢查系統狀態..."
    
    # 檢查 HAProxy 狀態
    if systemctl is-active --quiet haproxy; then
        success "HAProxy 服務正在運行"
    else
        warning "HAProxy 服務未運行"
    fi
    
    # 檢查 SSL 工具狀態
    if [ "$SSL_TOOL" = "dehydrated" ]; then
        if [ -f "/etc/dehydrated/accounts/*/account_key.pem" ] 2>/dev/null; then
            success "dehydrated 已註冊並可使用"
        else
            warning "dehydrated 尚未註冊，請執行: dehydrated --register --accept-terms"
            info "或者使用此腳本的 init-ssl 命令"
        fi
    elif [ "$SSL_TOOL" = "certbot" ]; then
        if [ -d "/etc/letsencrypt/accounts" ]; then
            success "certbot 已初始化並可使用"
        else
            warning "certbot 尚未初始化"
        fi
    fi
    
    # 檢查目錄結構
    for dir in "$DOMAINS_DIR" "$BACKENDS_DIR" "$SSL_DIR" "$ERRORS_DIR"; do
        if [ -d "$dir" ]; then
            success "目錄 $dir 存在"
        else
            warning "目錄 $dir 不存在"
        fi
    done
    
    # 檢查預設 SSL 憑證
    if [ -f "/etc/ssl/haproxy/default.pem" ]; then
        success "預設 SSL 憑證存在"
    else
        warning "預設 SSL 憑證不存在"
    fi
}

# 初始化 SSL 工具
init_ssl_tool() {
    info "初始化 SSL 工具..."
    
    if [ "$SSL_TOOL" = "dehydrated" ]; then
        info "正在註冊 dehydrated..."
        
        # 確保配置目錄存在
        mkdir -p /etc/dehydrated
        
        # 註冊 dehydrated
        if dehydrated --register --accept-terms; then
            success "dehydrated 註冊成功"
        else
            error "dehydrated 註冊失敗"
        fi
        
    elif [ "$SSL_TOOL" = "certbot" ]; then
        info "正在初始化 certbot..."
        
        # 初始化 certbot
        if certbot register --agree-tos --email "${CONTACT_EMAIL:-admin@example.com}" --no-eff-email; then
            success "certbot 初始化成功"
        else
            error "certbot 初始化失敗"
        fi
    fi
}

# 添加新域名
add_domain() {
    local domain=$1
    local servers=$2
    
    info "開始添加域名: $domain"
    
    # 驗證輸入
    validate_domain "$domain"
    check_domain_exists "$domain"
    
    if [ -z "$servers" ]; then
        error "必須指定後端服務器 (格式: IP:PORT,IP:PORT)"
    fi
    
    # 執行添加流程
    backup_config
    generate_ssl_cert "$domain"
    generate_domain_config "$domain"
    generate_backend_config "$domain" "$servers"
    generate_error_page "$domain"
    update_main_config "$domain"
    test_haproxy_config
    reload_haproxy
    
    # 等待服務穩定
    sleep 5
    
    # 驗證配置
    verify_domain "$domain"
    
    success "域名 $domain 添加完成！"
    
    # 顯示總結信息
    cat << EOF

=== 域名添加總結 ===
域名: $domain
SSL 憑證: /etc/ssl/certs/${domain}.pem
前端配置: $DOMAINS_DIR/${domain}.cfg
後端配置: $BACKENDS_DIR/${domain}-backend.cfg
錯誤頁面: $ERRORS_DIR/503-${domain}.http

測試連接:
- HTTP:  curl -I http://$domain
- HTTPS: curl -I https://$domain
- WWW:   curl -I https://www.$domain

EOF
}

# 移除域名
remove_domain() {
    local domain=$1
    
    info "開始移除域名: $domain"
    
    # 驗證域名存在
    if [ ! -f "$DOMAINS_DIR/${domain}.cfg" ]; then
        error "域名 $domain 不存在"
    fi
    
    # 備份配置
    backup_config
    
    # 移除配置文件
    rm -f "$DOMAINS_DIR/${domain}.cfg"
    rm -f "$BACKENDS_DIR/${domain}-backend.cfg"
    rm -f "$ERRORS_DIR/503-${domain}.http"
    
    # 從主配置文件中移除引用
    sed -i "/include.*domains\/${domain}.cfg/d" "$MAIN_CONFIG"
    sed -i "/include.*backends\/${domain}-backend.cfg/d" "$MAIN_CONFIG"
    
    # 從 SSL 憑證清單中移除
    sed -i "/\/etc\/ssl\/certs\/${domain}.pem/d" "$SSL_CERT_LIST"
    
    # 測試並重載配置
    test_haproxy_config
    reload_haproxy
    
    success "域名 $domain 已移除"
}

# 列出所有域名
list_domains() {
    info "已配置的域名列表:"
    
    if [ ! -d "$DOMAINS_DIR" ]; then
        warning "域名配置目錄不存在"
        return
    fi
    
    local count=0
    for config_file in "$DOMAINS_DIR"/*.cfg; do
        if [ -f "$config_file" ]; then
            local domain=$(basename "$config_file" .cfg)
            echo "  - $domain"
            ((count++))
        fi
    done
    
    if [ $count -eq 0 ]; then
        warning "沒有找到任何域名配置"
    else
        info "總共 $count 個域名"
    fi
}

# 更新 SSL 憑證
update_ssl_certs() {
    info "更新所有 SSL 憑證..."
    
    if [ "$SSL_TOOL" = "dehydrated" ]; then
        dehydrated --cron
    elif [ "$SSL_TOOL" = "certbot" ]; then
        certbot renew --quiet
    fi
    
    # 重載 HAProxy 以使用新憑證
    reload_haproxy
    
    success "SSL 憑證更新完成"
}

# 顯示幫助信息
show_help() {
    cat << EOF
HAProxy 域名自動化管理腳本

使用方式:
    $0 <command> [options]

可用命令:
    add <domain> <servers>     添加新域名
                              servers 格式: IP:PORT,IP:PORT
                              例如: 10.0.4.1:8002,10.0.4.2:8002

    remove <domain>           移除域名

    list                      列出所有域名

    update-ssl               更新所有 SSL 憑證

    test                     測試 HAProxy 配置

    reload                   重載 HAProxy

    status                   檢查系統狀態

    init-ssl                 初始化 SSL 工具 (首次使用必須執行)

    help                     顯示此幫助信息

範例:
    # 添加新域名
    $0 add example.com 10.0.4.1:8002,10.0.4.2:8002

    # 移除域名
    $0 remove example.com

    # 列出所有域名
    $0 list

    # 更新 SSL 憑證
    $0 update-ssl

配置文件位置:
    主配置: $MAIN_CONFIG
    域名配置: $DOMAINS_DIR/
    後端配置: $BACKENDS_DIR/
    SSL 憑證: /etc/ssl/certs/

日誌文件: $LOG_FILE

EOF
}

# 主程式
main() {
    # 檢查是否為 root
    if [ "$EUID" -ne 0 ]; then
        error "請使用 root 權限執行此腳本"
    fi
    
    # 檢查依賴
    check_dependencies
    
    # 初始化目錄
    init_directories
    
    # 處理命令
    case "${1:-}" in
        "add")
            if [ $# -ne 3 ]; then
                error "add 命令需要域名和服務器參數"
            fi
            add_domain "$2" "$3"
            ;;
        "remove")
            if [ $# -ne 2 ]; then
                error "remove 命令需要域名參數"
            fi
            remove_domain "$2"
            ;;
        "list")
            list_domains
            ;;
        "update-ssl")
            update_ssl_certs
            ;;
        "test")
            test_haproxy_config
            ;;
        "reload")
            reload_haproxy
            ;;
        "help"|"--help"|"-h")
            show_help
            ;;
        "")
            error "請指定命令。使用 '$0 help' 查看幫助"
            ;;
        *)
            error "未知命令: $1。使用 '$0 help' 查看幫助"
            ;;
    esac
}

# 執行主程式
main "$@"
