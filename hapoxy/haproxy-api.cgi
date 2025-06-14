#!/bin/bash

# HAProxy 域名管理 CGI API
# 放置於 /var/www/haproxy-manager/cgi-bin/haproxy-api.cgi

# 設定變數
DOMAIN_MANAGER="/usr/local/bin/haproxy-domain-manager.sh"
LOG_FILE="/var/log/haproxy-domain-manager.log"

# 輸出 HTTP 標頭
echo "Content-Type: application/json"
echo "Access-Control-Allow-Origin: *"
echo "Access-Control-Allow-Methods: POST, GET, OPTIONS"
echo "Access-Control-Allow-Headers: Content-Type"
echo ""

# 錯誤處理函數
send_error() {
    local message="$1"
    local code="${2:-500}"
    
    echo "{\"success\": false, \"error\": \"$message\", \"code\": $code}"
    exit 1
}

# 成功回應函數
send_success() {
    local data="$1"
    
    if [ -z "$data" ]; then
        echo "{\"success\": true}"
    else
        echo "{\"success\": true, $data}"
    fi
}

# 檢查 sudo 權限
check_sudo_permissions() {
    if ! sudo -n -l /usr/local/bin/haproxy-domain-manager.sh >/dev/null 2>&1; then
        send_error "CGI 腳本缺少 sudo 權限，請檢查 sudoers 配置"
    fi
}

# 執行帶 sudo 的命令
run_with_sudo() {
    local command="$1"
    shift
    
    if ! sudo "$command" "$@" 2>&1; then
        return 1
    fi
    return 0
}

# 檢查腳本是否存在
if [ ! -f "$DOMAIN_MANAGER" ]; then
    send_error "域名管理腳本不存在"
fi

# 檢查 sudo 權限
check_sudo_permissions

# 讀取 POST 數據
if [ "$REQUEST_METHOD" = "POST" ]; then
    # 讀取 JSON 數據
    read -r POST_DATA
    
    # 檢查是否有數據
    if [ -z "$POST_DATA" ]; then
        send_error "缺少請求數據"
    fi
    
    # 解析 JSON（簡單的解析，實際使用建議用 jq）
    ACTION=$(echo "$POST_DATA" | grep -o '"action"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    
    if [ -z "$ACTION" ]; then
        send_error "缺少 action 參數"
    fi
    
    # 根據 action 執行對應操作
    case "$ACTION" in
        "add-domain")
            # 解析域名和服務器參數
            DOMAIN=$(echo "$POST_DATA" | grep -o '"domain"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
            SERVERS=$(echo "$POST_DATA" | grep -o '"servers"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
            
            if [ -z "$DOMAIN" ] || [ -z "$SERVERS" ]; then
                send_error "缺少域名或服務器參數"
            fi
            
            # 執行添加域名
            if OUTPUT=$(run_with_sudo "$DOMAIN_MANAGER" add "$DOMAIN" "$SERVERS" 2>&1); then
                send_success "\"message\": \"域名 $DOMAIN 添加成功\""
            else
                send_error "添加域名失敗: $OUTPUT"
            fi
            ;;
            
        "remove-domain")
            # 解析域名參數
            DOMAIN=$(echo "$POST_DATA" | grep -o '"domain"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
            
            if [ -z "$DOMAIN" ]; then
                send_error "缺少域名參數"
            fi
            
            # 執行移除域名
            if OUTPUT=$(run_with_sudo "$DOMAIN_MANAGER" remove "$DOMAIN" 2>&1); then
                send_success "\"message\": \"域名 $DOMAIN 移除成功\""
            else
                send_error "移除域名失敗: $OUTPUT"
            fi
            ;;
            
        "list-domains")
            # 列出所有域名
            DOMAINS_OUTPUT=$(run_with_sudo "$DOMAIN_MANAGER" list 2>&1)
            
            # 解析域名列表（簡化版）
            DOMAINS_JSON="["
            FIRST=true
            
            # 從 /etc/haproxy/domains/ 目錄讀取域名
            if [ -d "/etc/haproxy/domains" ]; then
                for config_file in /etc/haproxy/domains/*.cfg; do
                    if [ -f "$config_file" ]; then
                        DOMAIN_NAME=$(basename "$config_file" .cfg)
                        
                        # 檢查域名狀態
                        HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN_NAME" 2>/dev/null || echo "000")
                        
                        if [ "$HTTP_STATUS" = "200" ]; then
                            STATUS="active"
                            STATUS_TEXT="正常"
                        else
                            STATUS="inactive"
                            STATUS_TEXT="異常"
                        fi
                        
                        # 讀取後端服務器信息
                        BACKEND_FILE="/etc/haproxy/backends/${DOMAIN_NAME}-backend.cfg"
                        SERVERS="未知"
                        if [ -f "$BACKEND_FILE" ]; then
                            SERVERS=$(grep "server " "$BACKEND_FILE" | wc -l)
                            SERVERS="${SERVERS} 台服務器"
                        fi
                        
                        # 檢查 SSL 憑證
                        SSL_STATUS="未知"
                        if [ -f "/etc/ssl/certs/${DOMAIN_NAME}.pem" ]; then
                            SSL_EXPIRY=$(openssl x509 -in "/etc/ssl/certs/${DOMAIN_NAME}.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
                            if [ -n "$SSL_EXPIRY" ]; then
                                SSL_STATUS="有效"
                            else
                                SSL_STATUS="無效"
                            fi
                        else
                            SSL_STATUS="缺失"
                        fi
                        
                        if [ "$FIRST" = false ]; then
                            DOMAINS_JSON="$DOMAINS_JSON,"
                        fi
                        
                        DOMAINS_JSON="$DOMAINS_JSON{
                            \"name\": \"$DOMAIN_NAME\",
                            \"status\": \"$STATUS\",
                            \"servers\": \"$SERVERS\",
                            \"ssl_status\": \"$SSL_STATUS\",
                            \"last_check\": \"$(date '+%Y-%m-%d %H:%M:%S')\"
                        }"
                        
                        FIRST=false
                    fi
                done
            fi
            
            DOMAINS_JSON="$DOMAINS_JSON]"
            
            send_success "\"domains\": $DOMAINS_JSON"
            ;;
            
        "test-domain")
            # 測試單個域名
            DOMAIN=$(echo "$POST_DATA" | grep -o '"domain"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
            
            if [ -z "$DOMAIN" ]; then
                send_error "缺少域名參數"
            fi
            
            # 測試域名連接
            HTTP_TEST=$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN" 2>/dev/null || echo "000")
            HTTPS_TEST=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" 2>/dev/null || echo "000")
            WWW_TEST=$(curl -s -o /dev/null -w "%{http_code}" "https://www.$DOMAIN" 2>/dev/null || echo "000")
            
            if [ "$HTTP_TEST" = "301" ] && [ "$HTTPS_TEST" = "200" ] && [ "$WWW_TEST" = "301" ]; then
                send_success "\"message\": \"域名 $DOMAIN 測試通過\""
            else
                send_error "域名 $DOMAIN 測試失敗 (HTTP: $HTTP_TEST, HTTPS: $HTTPS_TEST, WWW: $WWW_TEST)"
            fi
            ;;
            
        "test-all-domains")
            # 測試所有域名
            TOTAL=0
            PASSED=0
            
            if [ -d "/etc/haproxy/domains" ]; then
                for config_file in /etc/haproxy/domains/*.cfg; do
                    if [ -f "$config_file" ]; then
                        DOMAIN_NAME=$(basename "$config_file" .cfg)
                        TOTAL=$((TOTAL + 1))
                        
                        # 測試域名
                        HTTPS_TEST=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN_NAME" 2>/dev/null || echo "000")
                        
                        if [ "$HTTPS_TEST" = "200" ]; then
                            PASSED=$((PASSED + 1))
                        fi
                    fi
                done
            fi
            
            send_success "\"total\": $TOTAL, \"passed\": $PASSED"
            ;;
            
        "update-ssl-certs")
            # 更新 SSL 憑證
            if OUTPUT=$("$DOMAIN_MANAGER" update-ssl 2>&1); then
                send_success "\"message\": \"SSL 憑證更新成功\""
            else
                send_error "SSL 憑證更新失敗: $OUTPUT"
            fi
            ;;
            
        "check-cert-expiry")
            # 檢查憑證有效期
            CERTS_JSON="["
            FIRST=true
            
            if [ -d "/etc/ssl/certs" ]; then
                for cert_file in /etc/ssl/certs/*.pem; do
                    if [ -f "$cert_file" ]; then
                        DOMAIN_NAME=$(basename "$cert_file" .pem)
                        
                        # 檢查憑證有效期
                        if EXPIRY_DATE=$(openssl x509 -in "$cert_file" -noout -enddate 2>/dev/null | cut -d= -f2); then
                            EXPIRY_TIMESTAMP=$(date -d "$EXPIRY_DATE" +%s 2>/dev/null || echo "0")
                            CURRENT_TIMESTAMP=$(date +%s)
                            DAYS_LEFT=$(( (EXPIRY_TIMESTAMP - CURRENT_TIMESTAMP) / 86400 ))
                            
                            if [ $DAYS_LEFT -gt 30 ]; then
                                STATUS="active"
                                STATUS_TEXT="正常"
                            elif [ $DAYS_LEFT -gt 7 ]; then
                                STATUS="warning"
                                STATUS_TEXT="即將到期"
                            else
                                STATUS="inactive"
                                STATUS_TEXT="已到期或即將到期"
                            fi
                            
                            EXPIRY_FORMATTED=$(date -d "$EXPIRY_DATE" '+%Y-%m-%d' 2>/dev/null || echo "無效日期")
                        else
                            STATUS="inactive"
                            STATUS_TEXT="憑證無效"
                            DAYS_LEFT=0
                            EXPIRY_FORMATTED="無效"
                        fi
                        
                        if [ "$FIRST" = false ]; then
                            CERTS_JSON="$CERTS_JSON,"
                        fi
                        
                        CERTS_JSON="$CERTS_JSON{
                            \"domain\": \"$DOMAIN_NAME\",
                            \"status\": \"$STATUS\",
                            \"status_text\": \"$STATUS_TEXT\",
                            \"expiry\": \"$EXPIRY_FORMATTED\",
                            \"days_left\": $DAYS_LEFT
                        }"
                        
                        FIRST=false
                    fi
                done
            fi
            
            CERTS_JSON="$CERTS_JSON]"
            
            send_success "\"certificates\": $CERTS_JSON"
            ;;
            
        "renew-cert")
            # 更新單個憑證
            DOMAIN=$(echo "$POST_DATA" | grep -o '"domain"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
            
            if [ -z "$DOMAIN" ]; then
                send_error "缺少域名參數"
            fi
            
            # 使用 dehydrated 或 certbot 更新憑證
            if command -v dehydrated &> /dev/null; then
                if OUTPUT=$(dehydrated --cron --domain "$DOMAIN" 2>&1); then
                    # 合併憑證文件
                    cat "/etc/dehydrated/certs/$DOMAIN/fullchain.pem" \
                        "/etc/dehydrated/certs/$DOMAIN/privkey.pem" > "/etc/ssl/certs/${DOMAIN}.pem"
                    systemctl reload haproxy
                    send_success "\"message\": \"域名 $DOMAIN 的憑證更新成功\""
                else
                    send_error "憑證更新失敗: $OUTPUT"
                fi
            elif command -v certbot &> /dev/null; then
                if OUTPUT=$(certbot renew --cert-name "$DOMAIN" 2>&1); then
                    # 合併憑證文件
                    cat "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" \
                        "/etc/letsencrypt/live/$DOMAIN/privkey.pem" > "/etc/ssl/certs/${DOMAIN}.pem"
                    systemctl reload haproxy
                    send_success "\"message\": \"域名 $DOMAIN 的憑證更新成功\""
                else
                    send_error "憑證更新失敗: $OUTPUT"
                fi
            else
                send_error "未找到 SSL 憑證工具"
            fi
            ;;
            
        "get-logs")
            # 獲取日誌
            if [ -f "$LOG_FILE" ]; then
                # 只取最後 1000 行日誌
                LOG_CONTENT=$(tail -n 1000 "$LOG_FILE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')
                send_success "\"logs\": \"$LOG_CONTENT\""
            else
                send_success "\"logs\": \"日誌文件不存在\""
            fi
            ;;
            
        "clear-logs")
            # 清空日誌
            if echo "" > "$LOG_FILE" 2>/dev/null; then
                send_success "\"message\": \"日誌已清空\""
            else
                send_error "清空日誌失敗"
            fi
            ;;
            
        "haproxy-status")
            # 獲取 HAProxy 狀態
            if systemctl is-active --quiet haproxy; then
                HAPROXY_STATUS="running"
                HAPROXY_UPTIME=$(systemctl show haproxy --property=ActiveEnterTimestamp --value)
            else
                HAPROXY_STATUS="stopped"
                HAPROXY_UPTIME="N/A"
            fi
            
            # 獲取統計信息
            STATS_URL="http://localhost:8404/stats"
            if command -v curl &> /dev/null; then
                STATS_AVAILABLE=$(curl -s -o /dev/null -w "%{http_code}" "$STATS_URL" 2>/dev/null)
                if [ "$STATS_AVAILABLE" = "200" ]; then
                    STATS_STATUS="available"
                else
                    STATS_STATUS="unavailable"
                fi
            else
                STATS_STATUS="unknown"
            fi
            
            send_success "\"haproxy_status\": \"$HAPROXY_STATUS\", \"uptime\": \"$HAPROXY_UPTIME\", \"stats_status\": \"$STATS_STATUS\""
            ;;
            
        "reload-haproxy")
            # 重載 HAProxy
            if OUTPUT=$(systemctl reload haproxy 2>&1); then
                send_success "\"message\": \"HAProxy 重載成功\""
            else
                send_error "HAProxy 重載失敗: $OUTPUT"
            fi
            ;;
            
        "test-config")
            # 測試 HAProxy 配置
            if OUTPUT=$(haproxy -c -f /etc/haproxy/haproxy.cfg 2>&1); then
                send_success "\"message\": \"HAProxy 配置測試通過\""
            else
                send_error "HAProxy 配置測試失敗: $OUTPUT"
            fi
            ;;
            
        *)
            send_error "未知的操作: $ACTION"
            ;;
    esac
    
elif [ "$REQUEST_METHOD" = "GET" ]; then
    # 處理 GET 請求（用於狀態查詢）
    send_success "\"status\": \"HAProxy 域名管理 API 正常運行\", \"timestamp\": \"$(date)\""
    
else
    send_error "不支援的請求方法: $REQUEST_METHOD"
fi
