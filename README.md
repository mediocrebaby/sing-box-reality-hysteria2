- 强烈建议开启bbr加速，可大幅加快节点reality和vmess节点的速度
- 安装完成后终端输入 mianyang 可再次调用本脚本


# 新增功能（排序从新到旧）
- 新增sing-box正式版和测试版版本切换
- 任意门，ss解锁流媒体，任意门中转（仅在二合一版本中）
- 全面适配sing-box1.8.0
- 新增更多warp解锁功能，geo和domain_keword,全局接管等
- 新添加了hysteria2端口跳跃功能

# 简介
- Reality Hysteria2 （vmess ws）一键安装脚本
  
## 使用教程

### reality和hysteria2 vmess ws三合一脚本

```bash
bash <(curl -fsSL https://github.com/mediocrebaby/sing-box-reality-hysteria2/raw/main/beta.sh)
```


## 功能

- 无脑回车一键安装或者自定义安装
- 完全无需域名，使用自签证书部署hy2，（使用argo隧道支持vmess ws优选ip（理论上比普通优选ip更快））
- 支持修改reality端口号和域名，hysteria2端口号
- 无脑生成sing-box，clash-meta，v2rayN，nekoray等通用链接格式
- 支持warp，任意门，ss解锁流媒体
- 支持任意门中转
- 支持端口跳跃

### warp自定义解锁功能
![](https://img.mareep.net/blog/2023/12/d6fbf369c96dbabb160e67f76dac0d6d.jpg)


## Credit
- [sing-box-example](https://github.com/chika0801/sing-box-examples)
- [sing-reality-box](https://github.com/deathline94/sing-REALITY-Box)
- [sing-box](https://github.com/SagerNet/sing-box)
