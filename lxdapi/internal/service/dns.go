package service

import (
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
)

// validateDNSServer 严格校验是否为合法的 IPv4/IPv6 地址
func validateDNSServer(server string) error {
	server = strings.TrimSpace(server)
	if server == "" {
		return fmt.Errorf("DNS 地址不能为空")
	}
	// net.ParseIP 会拒绝包含分号、空格、$、() 等任何恶意字符的字符串
	if net.ParseIP(server) == nil {
		return fmt.Errorf("非法的 DNS 服务器地址: %q", server)
	}
	return nil
}

// ApplyContainerDNS 安全的写入容器 DNS
func ApplyContainerDNS(containerName string, servers []string) error {
	if len(servers) == 0 {
		return fmt.Errorf("DNS 列表不能为空")
	}
	if len(servers) > 3 {
		return fmt.Errorf("DNS 数量过多，最多允许 3 个")
	}

	// 1. 严格校验每一个 DNS
	for _, s := range servers {
		if err := validateDNSServer(s); err != nil {
			return err
		}
	}

	// 2. 构造 resolv.conf 内容（纯字符串拼接，不具备任何执行能力）
	var content strings.Builder
	for _, s := range servers {
		content.WriteString("nameserver ")
		content.WriteString(strings.TrimSpace(s))
		content.WriteString("\n")
	}

	// 3. 【防注入核心】使用 tee 写入文件，命令与参数完全分离
	// tee 不解析任何 shell 元字符，stdin 的数据原样写入目标文件
	cmd := exec.Command("lxc", "exec", containerName, "--", "tee", "/etc/resolv.conf")
	cmd.Stdin = strings.NewReader(content.String())
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("写入容器 DNS 失败: %v", err)
	}
	return nil
}
