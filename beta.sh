#!/bin/bash

# delay print
print_with_delay() {
    text="$1"
    delay="$2"
    for ((i = 0; i < ${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "$delay"
    done
    echo
}
# colorful text
warning() { echo -e "\033[31m\033[01m$*\033[0m"; }  # 红色
error() { echo -e "\033[31m\033[01m$*\033[0m" && exit 1; } # 红色
info() { echo -e "\033[32m\033[01m$*\033[0m"; }   # 绿色
hint() { echo -e "\033[33m\033[01m$*\033[0m"; }   # 黄色
#show system and singbox info
show_status(){
    singbox_pid=$(pgrep sing-box)
    singbox_status=$(systemctl is-active sing-box)
    if [ "$singbox_status" == "active" ]; then
        cpu_usage=$(ps -p $singbox_pid -o %cpu | tail -n 1)
        memory_usage_mb=$(( $(ps -p "$singbox_pid" -o rss | tail -n 1) / 1024 ))

        p_latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')
        latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')

        latest_version=${latest_version_tag#v}  # Remove 'v' prefix from version number
        p_latest_version=${p_latest_version_tag#v}  # Remove 'v' prefix from version number

        iswarp=$(grep '^WARP_ENABLE=' /root/sbox/config | cut -d'=' -f2)

        warning "SING-BOX服务状态信息:"
        hint "========================="
        info "状态: 运行中"
        info "CPU 占用: $cpu_usage%"
        info "内存 占用: ${memory_usage_mb}MB"
        info "singbox测试版最新版本: $p_latest_version"
        info "singbox正式版最新版本: $latest_version"
        info "singbox当前版本(输入4管理切换): $(/root/sbox/sing-box version 2>/dev/null | awk '/version/{print $NF}')"
        info "WARP CLI集成(输入6管理): $(if [ "$iswarp" == "TRUE" ]; then echo "开启"; else echo "关闭"; fi)"
        hint "========================="
    else
        warning "SING-BOX 未运行！"
    fi

}

 
#show notice
show_notice() {
    local message="$1"
    local reset="\e[0m"
    local bold="\e[1m"
    local terminal_width=$(tput cols)
    local line=""
    local padding=$(( (terminal_width - ${#message}) / 2 ))
    local padded_message="$(printf "%*s%s" $padding '' "$message")"
    for ((i=1; i<=terminal_width; i++)); do
        line+="*"
    done
    warning "${bold}${line}${reset}"
    echo ""
    warning "${bold}${padded_message}${reset}"
    echo ""
    warning "${bold}${line}${reset}"
}
#install pkgs
install_pkgs() {
  # Install qrencode, jq, and iptables if not already installed
  local pkgs=("qrencode" "jq" "iptables")
  for pkg in "${pkgs[@]}"; do
    if command -v "$pkg" &> /dev/null; then
      echo "$pkg is already installed."
    else
      echo "Installing $pkg..."
      if command -v apt &> /dev/null; then
        sudo apt update > /dev/null 2>&1 && sudo apt install -y "$pkg" > /dev/null 2>&1
      elif command -v yum &> /dev/null; then
        sudo yum install -y "$pkg"
      elif command -v dnf &> /dev/null; then
        sudo dnf install -y "$pkg"
      else
        error "Unable to install $pkg. Please install it manually and rerun the script."
      fi
      echo "$pkg has been installed."
    fi
  done
}
install_shortcut() {
  cat > /root/sbox/mediocrebaby.sh << EOF
#!/usr/bin/env bash
bash <(curl -fsSL https://github.com/mediocrebaby/sing-box-reality-hysteria2/raw/main/beta.sh) \$1
EOF
  chmod +x /root/sbox/mediocrebaby.sh
  ln -sf /root/sbox/mediocrebaby.sh /usr/bin/mediocrebaby

}
reload_singbox(){
    if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
      echo "检查配置文件成功，重启服务..."
      systemctl reload sing-box
    else
      error "配置文件检查错误"
    fi
}
install_singbox(){
		echo "请选择需要安装的SING-BOX版本:"
		echo "1. 正式版"
		echo "2. 测试版"
		read -p "输入你的选项 (1-2, 默认: 1): " version_choice
		version_choice=${version_choice:-1}
		# Set the tag based on user choice
		if [ "$version_choice" -eq 2 ]; then
			echo "Installing Alpha version..."
			latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')
		else
			echo "Installing Stable version..."
			latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
		fi
		# No need to fetch the latest version tag again, it's already set based on user choice
		latest_version=${latest_version_tag#v}  # Remove 'v' prefix from version number
		echo "Latest version: $latest_version"
		# Detect server architecture
		arch=$(uname -m)
		echo "本机架构为: $arch"
    case ${arch} in
      x86_64) arch="amd64" ;;
      aarch64) arch="arm64" ;;
      armv7l) arch="armv7" ;;
    esac
    # latest_version_tag=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | grep -Po '"tag_name": "\K.*?(?=")' | sort -V | tail -n 1)
    # latest_version=${latest_version_tag#v}
    echo "最新版本为: $latest_version"
    package_name="sing-box-${latest_version}-linux-${arch}"
    url="https://github.com/SagerNet/sing-box/releases/download/${latest_version_tag}/${package_name}.tar.gz"
    curl -sLo "/root/${package_name}.tar.gz" "$url"
    tar -xzf "/root/${package_name}.tar.gz" -C /root
    mv "/root/${package_name}/sing-box" /root/sbox
    rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"
    chown root:root /root/sbox/sing-box
    chmod +x /root/sbox/sing-box
}

change_singbox(){
			echo "切换SING-BOX版本..."
			echo ""
			# Extract the current version
			current_version_tag=$(/root/sbox/sing-box version | grep 'sing-box version' | awk '{print $3}')

			# Fetch the latest stable and alpha version tags
			latest_stable_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==false)][0].tag_name')
			latest_alpha_version=$(curl -s "https://api.github.com/repos/SagerNet/sing-box/releases" | jq -r '[.[] | select(.prerelease==true)][0].tag_name')

			# Determine current version type (stable or alpha)
      if [[ $current_version_tag == *"-alpha"* || $current_version_tag == *"-rc"* || $current_version_tag == *"-beta"* ]]; then
				echo "当前为测试版，准备切换为最新正式版..."
				echo ""
				new_version_tag=$latest_stable_version
			else
				echo "当前为正式版，准备切换为最新测试版..."
				echo ""
				new_version_tag=$latest_alpha_version
			fi

			# Stop the service before updating
			systemctl stop sing-box

			# Download and replace the binary
			arch=$(uname -m)
			case $arch in
				x86_64) arch="amd64" ;;
				aarch64) arch="arm64" ;;
				armv7l) arch="armv7" ;;
			esac

			package_name="sing-box-${new_version_tag#v}-linux-${arch}"
			url="https://github.com/SagerNet/sing-box/releases/download/${new_version_tag}/${package_name}.tar.gz"

			curl -sLo "/root/${package_name}.tar.gz" "$url"
			tar -xzf "/root/${package_name}.tar.gz" -C /root
			mv "/root/${package_name}/sing-box" /root/sbox/sing-box

			# Cleanup the package
			rm -r "/root/${package_name}.tar.gz" "/root/${package_name}"

			# Set the permissions
			chown root:root /root/sbox/sing-box
			chmod +x /root/sbox/sing-box

			# Restart the service with the new binary
			systemctl daemon-reload
			systemctl start sing-box

			echo "Version switched and service restarted with the new binary."
			echo ""
}

generate_port() {
    while :; do
        port=$((RANDOM % 10001 + 10000))
        read -p "请输入协议监听端口(默认随机生成): " user_input
        port=${user_input:-$port}
        ss -tuln | grep -q ":$port\b" || { echo "$port"; return $port; }
        echo "端口 $port 被占用，请输入其他端口"
    done
}

modify_port() {
    local current_port="$1"
    while :; do
        read -p "请输入需要修改的端口，默认随机生成 (当前端口为: $current_port): " modified_port
        modified_port=${modified_port:-$current_port}
        if [ "$modified_port" -eq "$current_port" ]; then
            break
        fi
        if ss -tuln | grep -q ":$modified_port\b"; then
            echo "端口 $port 被占用，请输入其他端口"
        else
            break
        fi
    done
    echo "$modified_port"
}

# 覆盖上面旧版，精简为仅 Reality 输出
show_client_configuration() {
  server_ip=$(grep -o "SERVER_IP='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  public_key=$(grep -o "PUBLIC_KEY='[^']*'" /root/sbox/config | awk -F"'" '{print $2}')
  reality_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' /root/sbox/sbconfig_server.json)
  reality_uuid=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .users[0].uuid' /root/sbox/sbconfig_server.json)
  reality_server_name=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.server_name' /root/sbox/sbconfig_server.json)
  short_id=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.reality.short_id[0]' /root/sbox/sbconfig_server.json)

  reality_link="vless://$reality_uuid@$server_ip:$reality_port?encryption=none&flow=xtls-rprx-vision&security=reality&sni=$reality_server_name&fp=chrome&pbk=$public_key&sid=$short_id&type=tcp&headerType=none#SING-BOX-REALITY"
  echo ""
  show_notice "Vision Reality通用链接 二维码 通用参数"
  echo ""
  info "通用链接如下"
  echo ""
  echo "$reality_link"
  echo ""
  info "二维码如下"
  echo ""
  qrencode -t UTF8 $reality_link
  echo ""
  info "客户端通用参数如下"
  echo ""
  echo "服务器ip: $server_ip"
  echo "监听端口: $reality_port"
  echo "UUID: $reality_uuid"
  echo "域名SNI: $reality_server_name"
  echo "Public Key: $public_key"
  echo "Short ID: $short_id"
  echo ""

  # Clash Meta 示例（Reality-only）
  show_notice "Clash Meta配置示例"
  cat << EOF

port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
ipv6: true
dns:
  enable: true
  listen: :53
  ipv6: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  default-nameserver: 
    - 223.5.5.5
    - 8.8.8.8
  nameserver:
    - https://dns.alidns.com/dns-query
    - https://doh.pub/dns-query
  fallback:
    - https://1.0.0.1/dns-query
    - tls://dns.google
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
      - 240.0.0.0/4

proxies:
  - name: Reality
    type: vless
    server: $server_ip
    port: $reality_port
    uuid: $reality_uuid
    network: tcp
    udp: true
    tls: true
    flow: xtls-rprx-vision
    servername: $reality_server_name
    client-fingerprint: chrome
    reality-opts:
      public-key: $public_key
      short-id: $short_id

proxy-groups:
  - name: 节点选择
    type: select
    proxies:
      - Reality
      - DIRECT

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,节点选择

EOF
}

#enable bbr
enable_bbr() {
    # temporary workaround for installing bbr
    bash <(curl -L -s https://raw.githubusercontent.com/teddysun/across/master/bbr.sh)
    echo ""
}

modify_singbox() {
    #modifying reality configuration
    echo ""
    warning "开始修改reality端口号和域名"
    reality_current_port=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .listen_port' /root/sbox/sbconfig_server.json)
    reality_port=$(modify_port "$reality_current_port")
    reality_current_server_name=$(jq -r '.inbounds[] | select(.tag == "vless-in") | .tls.server_name' /root/sbox/sbconfig_server.json)
    reality_server_name="$reality_current_server_name"
    while :; do
        read -p "请输入需要偷取证书的网站，必须支持 TLS 1.3 and HTTP/2 (默认: $reality_server_name): " input_server_name
        reality_server_name=${input_server_name:-$reality_server_name}

        if curl --tlsv1.3 --http2 -sI "https://$reality_server_name" | grep -q "HTTP/2"; then
            break
        else
            echo "域名 $reality_server_name 不支持 TLS 1.3 或 HTTP/2，请重新输入."
        fi
    done
    echo "域名 $reality_server_name 符合."
    echo ""
    # 修改sing-box
    jq --arg reality_port "$reality_port" \
    --arg reality_server_name "$reality_server_name" \
    '
    (.inbounds[] | select(.tag == "vless-in") | .listen_port) |= ($reality_port | tonumber) |
    (.inbounds[] | select(.tag == "vless-in") | .tls.server_name) |= $reality_server_name |
    (.inbounds[] | select(.tag == "vless-in") | .tls.reality.handshake.server) |= $reality_server_name
    ' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json

    echo ""
    reload_singbox
    echo ""
}

uninstall_singbox() {

    warning "开始卸载..."
    # 若存在 WARP 集成，先卸载 WARP
    if has_warp_integration; then
        info "检测到 WARP 集成，先执行关闭与卸载..."
        disable_warp || true
    fi
    # Stop and disable services
    systemctl stop sing-box
    systemctl disable sing-box > /dev/null 2>&1

    # Remove service files
    rm -f /etc/systemd/system/sing-box.service

    # Remove configuration and executable files
    rm -f /root/sbox/sbconfig_server.json
    rm -f /root/sbox/sing-box
    rm -f /usr/bin/mianyang
    rm -f /root/sbox/mianyang.sh
    rm -f /root/sbox/config

    # Remove directories
    rm -rf /root/sbox/

    echo "卸载完成"
}
process_warp(){
    while :; do
        iswarp=$(grep '^WARP_ENABLE=' /root/sbox/config | cut -d'=' -f2)
        if [ "$iswarp" = "FALSE" ]; then
          warning "warp分流未开启，是否开启（默认解锁openai和奈飞）"
          read -p "是否开启? (y/n 默认为y): " confirm
          confirm=${confirm:-"y"}
          if [ "$confirm" = "y" ] || [ "$confirm" = "Y" ]; then
            enable_warp
          else
            break
          fi
        else
            warp_option=$(awk -F= '/^WARP_OPTION/{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}' /root/sbox/config)
            case $warp_option in
                0)
                    current_option="手动分流(使用geosite和domain分流)"
                    ;;
                1)
                    current_option="全局分流(接管所有流量)"
                    ;;
                *)
                    current_option="unknow!"
                    ;;
            esac
            echo ""
            warning "warp分流已经开启"
            echo ""
            hint "当前状态为: $current_option"
            echo ""
            info "请选择选项："
            echo ""
            info "1. 切换为手动分流(geosite和domain分流)"
            info "2. 切换为全局分流(接管所有流量)" 
            info "3. 设置手动分流规则(geosite和domain分流)"  
            info "4. 切换为warp策略"
            info "5. 删除warp解锁"
            info "0. 退出"
            echo ""
            read -p "请输入对应数字（0-5）: " warp_input
        case $warp_input in
          1)
            jq '.route.final = "direct"' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
            sed -i "s/WARP_OPTION=.*/WARP_OPTION=0/" /root/sbox/config
            reload_singbox
          ;;
          2)
            jq  '.route.final = "wireguard-out"' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
            sed -i "s/WARP_OPTION=.*/WARP_OPTION=1/" /root/sbox/config
            reload_singbox
            ;;
          3)
            info "请选择："
            echo ""
            info "1. 手动添加geosite分流（适配singbox1.8.0)"
            info "2. 手动添加域名关键字匹配分流"
            info "0. 退出"
            echo ""

            read -p "请输入对应数字（0-2）: " user_input
            case $user_input in
                1)
                    while :; do
                      echo ""
                      warning "geosite分流为: "
                      #域名关键字为
                      jq '.route.rules[] | select(.rule_set) | .rule_set' /root/sbox/sbconfig_server.json
                      info "请选择操作："
                      echo "1. 添加geosite"
                      echo "2. 删除geosite"
                      echo "0. 退出"
                      echo ""

                      read -p "请输入对应数字（0-2）: " user_input

                      case $user_input in
                          1)
                            #add domain
                            read -p "请输入要添加的域名关键字（若要添加geosite-openai，输入openai）: " new_keyword
                            url="https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/$new_keyword.srs"
                            formatted_keyword="geosite-$new_keyword"
                            # 检查是否存在相同的 geosite 关键字
                            if jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set | any(. == $formatted_keyword)' /root/sbox/sbconfig_server.json | grep -q "true"; then
                              echo "geosite已存在，不添加重复项: $formatted_keyword"
                            else
                              http_status=$(curl -s -o /dev/null -w "%{http_code}" "$url")

                              if [ "$http_status" -eq 200 ]; then
                                # 如果不存在，则添加
                                  new_rule='{
                                    "tag": "'"$formatted_keyword"'",
                                    "type": "remote",
                                    "format": "binary",
                                    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/'"$new_keyword"'.srs",
                                    "download_detour": "direct"
                                  }'

                                jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set += [$formatted_keyword]' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
                                jq --argjson new_rule "$new_rule" '.route.rule_set += [$new_rule]' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json

                                echo "geosite已添加: $new_rule"
                              else
                                echo "geosite srs文件不存在，请重新输入..."
                              fi
                            fi
                            ;;
                          2)
                            #delete domain keywords
                            read -p "请输入要删除的域名关键字（若要删除geosite-openai，输入openai） " keyword_to_delete
                            formatted_keyword="geosite-$keyword_to_delete"
                            if jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set | any(. == $formatted_keyword)' /root/sbox/sbconfig_server.json | grep -q "true"; then
                              jq --arg formatted_keyword "$formatted_keyword" '.route.rules[0].rule_set -= [$formatted_keyword]' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
                              #卸载ruleset
                              jq --arg formatted_keyword "$formatted_keyword" 'del(.route.rule_set[] | select(.tag == $formatted_keyword))' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
                              echo "域名关键字已删除: $formatted_keyword"
                            else
                              echo "域名关键字不存在，不执行删除操作: $formatted_keyword"
                            fi
                              ;;
                          0)
                              echo "退出"
                              break
                              ;;
                          *)
                              echo "无效的输入，请重新输入"
                              ;;
                      esac
                  done
                    break
                    ;;
                2)
                    while :; do
                      echo ""
                      warning "域名关键字为: "
                      #域名关键字为
                      jq '.route.rules[] | select(.domain_keyword) | .domain_keyword' /root/sbox/sbconfig_server.json
                      info "请选择操作："
                      echo "1. 添加域名关键字"
                      echo "2. 删除域名关键字"
                      echo "0. 退出"
                      echo ""

                      read -p "请输入对应数字（0-2）: " user_input

                      case $user_input in
                          1)
                            #add domain keywords
                            read -p "请输入要添加的域名关键字: " new_keyword
                            if jq --arg new_keyword "$new_keyword" '.route.rules[1].domain_keyword | any(. == $new_keyword)' /root/sbox/sbconfig_server.json | grep -q "true"; then
                              echo "域名关键字已存在，不添加重复项: $new_keyword"
                            else
                              jq --arg new_keyword "$new_keyword" '.route.rules[1].domain_keyword += [$new_keyword]' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
                              echo "域名关键字已添加: $new_keyword"
                            fi
                            ;;
                          2)
                            #delete domain keywords
                            read -p "请输入要删除的域名关键字: " keyword_to_delete
                            if jq --arg keyword_to_delete "$keyword_to_delete" '.route.rules[1].domain_keyword | any(. == $keyword_to_delete)' /root/sbox/sbconfig_server.json | grep -q "true"; then
                              jq --arg keyword_to_delete "$keyword_to_delete" '.route.rules[1].domain_keyword -= [$keyword_to_delete]' /root/sbox/sbconfig_server.json > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp /root/sbox/sbconfig_server.json
                              echo "域名关键字已删除: $keyword_to_delete"
                            else
                              echo "域名关键字不存在，不执行删除操作: $keyword_to_delete"
                            fi
                              ;;
                          0)
                              echo "退出"
                              break
                              ;;
                          *)
                              echo "无效的输入，请重新输入"
                              ;;
                      esac
                  done

                    break
                    ;;

                0)
                    # Exit the loop if option 0 is selected
                    echo "退出"
                    exit 0
                    ;;
                *)
                    # Handle invalid input
                    echo "无效的输入"
                    ;;
            esac
            reload_singbox
            break
            ;;
          5)
              disable_warp
              break
            ;;
          *)
              echo "退出"
              break
              ;;
        esac


        fi
        echo "配置文件更新成功"
    done
}

# 安装warp-cli
install_warp_cli(){
    info "开始安装Cloudflare WARP CLI..."

    # 检测系统架构
    ARCH=$(uname -m)
    case $ARCH in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64)
            ARCH="arm64"
            ;;
        *)
            error "不支持的架构: $ARCH"
            ;;
    esac

    # 下载并安装warp-cli
    if [[ -f /etc/debian_version ]]; then
        # Debian/Ubuntu系统
        curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
        echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/cloudflare-client.list
        apt update
        apt install -y cloudflare-warp
    elif [[ -f /etc/redhat-release ]]; then
        # RHEL/CentOS系统
        curl -fsSl https://pkg.cloudflareclient.com/cloudflare-warp-ascii.repo | tee /etc/yum.repos.d/cloudflare-warp.repo
        yum install -y cloudflare-warp
    else
        error "不支持的操作系统"
    fi

    info "WARP CLI安装完成"
}

# 配置warp-cli为SOCKS代理
configure_warp_proxy(){
    info "配置WARP CLI为SOCKS代理模式..."

    # 检查warp-cli是否已安装
    if ! command -v warp-cli &> /dev/null; then
        install_warp_cli
    fi

    # 注册并配置warp
    warp-cli registration new
    warp-cli mode proxy
    warp-cli connect

    # 检查连接状态
    sleep 3
    if warp-cli status | grep -q "Connected"; then
        info "WARP代理配置成功，监听端口: 40000"
    else
        error "WARP代理配置失败"
    fi
}

enable_warp(){
    warning "开始配置WARP CLI集成..."
    echo ""
    info "此功能将:"
    info "1. 安装Cloudflare WARP CLI"
    info "2. 配置为SOCKS代理模式"
    info "3. 更新sing-box配置使用WARP出站"
    echo ""

    read -p "是否继续? (y/n, 默认: y): " confirm
    confirm=${confirm:-y}

    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        configure_warp_proxy

        # 更新sing-box配置
        jq '
        # 添加warp SOCKS出站
        .outbounds += [{
            "type": "socks",
            "tag": "warp-out",
            "server": "127.0.0.1",
            "server_port": 40000,
            "version": "5"
        }] |
        # 添加路由规则
        .route = {
            "final": "direct",
            "rules": [
                {
                    "rule_set": ["geosite-openai", "geosite-netflix"],
                    "outbound": "warp-out"
                },
                {
                    "domain_keyword": ["ipaddress"],
                    "outbound": "warp-out"
                }
            ],
            "rule_set": [
                {
                    "tag": "geosite-openai",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/openai.srs",
                    "download_detour": "direct"
                },
                {
                    "tag": "geosite-netflix",
                    "type": "remote",
                    "format": "binary",
                    "url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/netflix.srs",
                    "download_detour": "direct"
                }
            ]
        }' "/root/sbox/sbconfig_server.json" > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp "/root/sbox/sbconfig_server.json"

        # 创建warp-cli systemd服务（oneshot，避免守护进程退出导致重启循环）
        cat > /etc/systemd/system/warp-proxy.service << EOF
[Unit]
Description=Cloudflare WARP Proxy (oneshot)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
RemainAfterExit=yes
ExecStart=/usr/bin/warp-cli mode proxy
ExecStart=/usr/bin/warp-cli connect
ExecStop=/usr/bin/warp-cli disconnect

[Install]
WantedBy=multi-user.target
EOF

        systemctl daemon-reload
        systemctl enable warp-proxy
        systemctl start warp-proxy

        sed -i "s/WARP_ENABLE=FALSE/WARP_ENABLE=TRUE/" /root/sbox/config
        sed -i "s/WARP_OPTION=.*/WARP_OPTION=1/" /root/sbox/config
        reload_singbox

        info "WARP CLI集成配置完成!"
    else
        info "取消配置"
    fi
}

# 判定是否存在 WARP 集成
has_warp_integration(){
    if [ -f /root/sbox/config ] && grep -q '^WARP_ENABLE=TRUE' /root/sbox/config 2>/dev/null; then
        return 0
    fi
    if command -v warp-cli >/dev/null 2>&1; then
        return 0
    fi
    if [ -f /etc/systemd/system/warp-proxy.service ]; then
        return 0
    fi
    return 1
}

# 仅卸载 WARP 包和仓库（幂等）
uninstall_warp_packages(){
    info "卸载 WARP 客户端与仓库配置..."
    if [[ -f /etc/debian_version ]]; then
        apt purge -y cloudflare-warp >/dev/null 2>&1 || true
        rm -f /etc/apt/sources.list.d/cloudflare-client.list || true
        rm -f /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg || true
        apt autoremove -y >/dev/null 2>&1 || true
    elif [[ -f /etc/redhat-release ]]; then
        yum remove -y cloudflare-warp >/dev/null 2>&1 || true
        rm -f /etc/yum.repos.d/cloudflare-warp.repo || true
    fi
    info "WARP 客户端卸载完成（如原本未安装则忽略）。"
}

#关闭warp（作为完整卸载入口）
disable_warp(){
    warning "开始关闭WARP集成..."

    # 停止并禁用warp-cli服务
    if systemctl is-active --quiet warp-proxy; then
        systemctl stop warp-proxy
        systemctl disable warp-proxy
        rm -f /etc/systemd/system/warp-proxy.service
        systemctl daemon-reload
        info "WARP CLI服务已停止"
    fi

    # 断开warp连接
    if command -v warp-cli &> /dev/null; then
        warp-cli disconnect 2>/dev/null || true
        info "WARP连接已断开"
    fi

    # 从sing-box配置中移除warp相关配置
    if [ -f "/root/sbox/sbconfig_server.json" ]; then
        jq 'del(.route) | del (.endpoints) | del(.outbounds[] | select(.tag == "warp-IPv4-out" or .tag == "warp-IPv6-out" or .tag == "warp-IPv4-prefer-out" or .tag == "warp-IPv6-prefer-out" or .tag == "wireguard-out" or .tag == "warp-out"))' "/root/sbox/sbconfig_server.json" > /root/sbox/sbconfig_server.temp && mv /root/sbox/sbconfig_server.temp "/root/sbox/sbconfig_server.json"
    fi

    if [ -f "/root/sbox/config" ]; then
        sed -i "s/WARP_ENABLE=TRUE/WARP_ENABLE=FALSE/" /root/sbox/config || true
        sed -i "s/^WARP_OPTION=.*/WARP_OPTION=0/" /root/sbox/config || true
    fi

    # 重载 sing-box（若已安装）
    if command -v systemctl >/dev/null 2>&1; then
        reload_singbox || true
    fi

    # 卸载 WARP 客户端与仓库
    uninstall_warp_packages

    info "WARP集成已完全关闭并卸载客户端"
}
#更新singbox
update_singbox(){
    info "更新singbox..."
    install_singbox
    # 检查配置
    if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
      echo "检查配置文件成功，重启服务..."
      systemctl restart sing-box
    else
      error "启动失败，请检查配置文件"
    fi
}

process_singbox() {
  while :; do
    echo ""
    echo ""
    info "请选择选项："
    echo ""
    info "1. 重启sing-box"
    info "2. 更新sing-box内核"
    info "3. 查看sing-box状态"
    info "4. 查看sing-box实时日志"
    info "5. 查看sing-box服务端配置"
    info "6. 切换SINGBOX内核版本"
    info "0. 退出"
    echo ""
    read -p "请输入对应数字（0-）: " user_input
    echo ""
    case "$user_input" in
        1)
            warning "重启sing-box..."
            # 检查配置
            if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
                info "检查配置文件，启动服务..."
                systemctl restart sing-box
            fi
            info "重启完成"
            break
            ;;
        2)
            update_singbox
            break
            ;;
        3)
            warning "singbox基本信息如下(ctrl+c退出)"
            systemctl status sing-box
            break
            ;;
        4)
            warning "singbox日志如下(ctrl+c退出)："
            journalctl -u sing-box -o cat -f
            break
            ;;
        5)
            echo "singbox服务端如下："
            cat /root/sbox/sbconfig_server.json
            break
            ;;
        6)
            change_singbox
            break
            ;;
        0)
          echo "退出"
          break
          ;;
        *)
            echo "请输入正确选项: 0-6"
            ;;
    esac
  done
}

 

# 作者介绍
print_with_delay "Reality 单协议脚本 Create by mediocrebaby" 0.04
echo ""
echo ""
#install pkgs
install_pkgs
# Check if reality.json, sing-box, and sing-box.service already exist
if [ -f "/root/sbox/sbconfig_server.json" ] && [ -f "/root/sbox/config" ] && [ -f "/root/sbox/mianyang.sh" ] && [ -f "/usr/bin/mianyang" ] && [ -f "/root/sbox/sing-box" ] && [ -f "/etc/systemd/system/sing-box.service" ]; then
    echo ""
    warning "sing-box-reality已安装"
    show_status
    warning "请选择选项:"
    echo ""
    info "1. 重新安装"
    info "2. 修改配置"
    info "3. 显示客户端配置"
    info "4. sing-box基础操作"
    info "5. 一键开启bbr"
    info "6. WARP CLI集成管理"
    info "0. 卸载"
    hint "========================="
    echo ""
    read -p "请输入对应数字 (0-6): " choice

    case $choice in
      1)
          uninstall_singbox
        ;;
      2)
          #修改sb
          modify_singbox
          show_client_configuration
          exit 0
        ;;
      3)  
          show_client_configuration
          exit 0
      ;;	
      4)  
          process_singbox
          exit 0
          ;;
      5)
          enable_bbr
          mianyang
          exit 0
          ;;
      6)
          process_warp
          exit 0
          ;;
      
      0)
          uninstall_singbox
	        exit 0
          ;;
      *)
          echo "Invalid choice. Exiting."
          exit 1
          ;;
	esac
	fi

mkdir -p "/root/sbox/"

install_singbox

echo ""
echo ""
# reality
warning "开始配置Reality..."
echo ""
key_pair=$(/root/sbox/sing-box generate reality-keypair)
private_key=$(echo "$key_pair" | awk '/PrivateKey/ {print $2}' | tr -d '"')
public_key=$(echo "$key_pair" | awk '/PublicKey/ {print $2}' | tr -d '"')
info "生成的公钥为:  $public_key"
info "生成的私钥为:  $private_key"
reality_uuid=$(/root/sbox/sing-box generate uuid)
short_id=$(/root/sbox/sing-box generate rand --hex 8)
info "生成的uuid为:  $reality_uuid"
info "生成的短id为:  $short_id"
echo ""
# Reality端口，默认443
default_reality_port=443
while :; do
    read -p "请输入协议监听端口(默认: $default_reality_port): " user_input
    reality_port=${user_input:-$default_reality_port}
    if ss -tuln | grep -q ":$reality_port\b"; then
        echo "端口 $reality_port 被占用，请输入其他端口"
    else
        break
    fi
done
info "使用端口号: $reality_port"
reality_server_name="itunes.apple.com"
while :; do
    read -p "请输入需要偷取证书的网站，必须支持 TLS 1.3 and HTTP/2 (默认: $reality_server_name): " input_server_name
    reality_server_name=${input_server_name:-$reality_server_name}

    if curl --tlsv1.3 --http2 -sI "https://$reality_server_name" | grep -q "HTTP/2"; then
        break
    else
        echo "域名 $reality_server_name 不支持 TLS 1.3 或 HTTP/2，请重新输入."
    fi
done
info "域名 $reality_server_name 符合."
echo ""
echo ""
#get ip
server_ip=$(curl -s4m8 ip.sb -k) || server_ip=$(curl -s6m8 ip.sb -k)

# 备份旧配置（如存在）
if [ -f /root/sbox/sbconfig_server.json ]; then
  cp /root/sbox/sbconfig_server.json "/root/sbox/sbconfig_server.json.bak.$(date +%s)"
fi

#generate config
cat > /root/sbox/config <<EOF
# VPS ip
SERVER_IP='$server_ip'
# Reality
PUBLIC_KEY='$public_key'
# Warp
WARP_ENABLE=FALSE
# 0 局部分流 1 全局分流
WARP_OPTION=0
EOF

 

#generate singbox server config
cat > /root/sbox/sbconfig_server.json << EOF
{
  "log": {
    "disabled": false,
    "level": "info",
    "timestamp": true
  },
  "inbounds": [
    {
      "sniff": true,
      "sniff_override_destination": true,
      "type": "vless",
      "tag": "vless-in",
      "listen": "::",
      "listen_port": $reality_port,
      "users": [
        {
          "uuid": "$reality_uuid",
          "flow": "xtls-rprx-vision"
        }
      ],
      "tls": {
        "enabled": true,
        "server_name": "$reality_server_name",
        "reality": {
          "enabled": true,
          "handshake": {
            "server": "$reality_server_name",
            "server_port": 443
          },
          "private_key": "$private_key",
          "short_id": ["$short_id"]
        }
      }
    }
  ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ]
}
EOF
# Create sing-box.service
cat > /etc/systemd/system/sing-box.service <<EOF
[Unit]
After=network.target nss-lookup.target

[Service]
User=root
WorkingDirectory=/root/sbox
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
ExecStart=/root/sbox/sing-box run -c /root/sbox/sbconfig_server.json
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=10
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF


# Check configuration and start the service
if /root/sbox/sing-box check -c /root/sbox/sbconfig_server.json; then
    hint "check config profile..."
    systemctl daemon-reload
    systemctl enable sing-box > /dev/null 2>&1
    systemctl start sing-box
    systemctl restart sing-box
    install_shortcut
    show_client_configuration
    hint "输入mianyang,打开菜单"
else
    error "check sing-box server config profile error!"
fi
