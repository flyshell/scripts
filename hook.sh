#cat /etc/dehydrated/hook.sh
#sudo chmod +x /etc/dehydrated/hook.sh
#!/bin/bash

case "$1" in
    "startup_hook")
        # dehydrated 啟動時調用
        echo "Dehydrated startup"
        ;;
        
    "exit_hook")
        # dehydrated 退出時調用
        echo "Dehydrated exit"
        ;;
        
    "deploy_challenge")
        domain="$2"
        token="$3"
        keyauth="$4"
        
        # 創建驗證文件目錄
        mkdir -p /tmp/acme-challenge
        echo "$keyauth" > "/tmp/acme-challenge/$token"
        
        echo "Challenge deployed for domain: $domain, token: $token"
        ;;
        
    "clean_challenge")
        domain="$2"
        token="$3"
        
        # 清理驗證文件
        rm -f "/tmp/acme-challenge/$token"
        
        echo "Challenge cleaned for domain: $domain, token: $token"
        ;;
        
    "sync_cert")
        # 證書同步時調用（在 deploy_cert 之前）
        domain="$2"
        echo "Syncing certificate for domain: $domain"
        ;;
        
    "deploy_cert")
        domain="$2"
        keyfile="$3"
        certfile="$4"
        fullchainfile="$5"
        chainfile="$6"
        
        # 合併憑證文件供 HAProxy 使用
        cat "$fullchainfile" "$keyfile" > "/etc/ssl/haproxy/$domain.pem"
        chmod 600 "/etc/ssl/haproxy/$domain.pem"
        chown haproxy:haproxy "/etc/ssl/haproxy/$domain.pem"
        
        # 更新憑證清單
        if ! grep -q "/etc/ssl/haproxy/$domain.pem" /etc/haproxy/ssl/ssl-certificates.txt; then
            echo "/etc/ssl/haproxy/$domain.pem" >> /etc/haproxy/ssl/ssl-certificates.txt
        fi
        
        # 重載 HAProxy
        systemctl reload haproxy
        
        echo "Certificate deployed for domain: $domain"
        ;;
        
    "unchanged_cert")
        # 證書未變更時調用
        domain="$2"
        echo "Certificate unchanged for domain: $domain"
        ;;
        
    "invalid_challenge")
        # 挑戰失敗時調用
        domain="$2"
        response="$3"
        echo "Challenge failed for domain: $domain"
        ;;
        
    "request_failure")
        # 請求失敗時調用
        statuscode="$2"
        reason="$3"
        reqtype="$4"
        echo "Request failed: $statuscode $reason ($reqtype)"
        ;;
        
    "this_hookscript_is_broken__dehydrated_is_working_fine__please_ignore_unknown_hooks_in_your_script")
        # 這是 dehydrated 的測試 hook，靜默忽略
        ;;
        
    *)
        # 只有在不是測試 hook 時才顯示未知 hook 訊息
        if [[ "$1" != *"dehydrated_is_working_fine"* ]]; then
            echo "Unknown hook: $1"
        fi
        ;;
esac
