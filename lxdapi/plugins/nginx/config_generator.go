package nginx

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"lxdapi/models"
	"lxdapi/pkg/logger"
)

type ConfigGenerator struct {
	confDir  string
	sitesDir string
	sslDir   string
	template *template.Template
}

func NewConfigGenerator(confDir, sitesDir, sslDir string) *ConfigGenerator {
	tmplPath := filepath.Join(filepath.Dir(confDir), "nginx-default.tmpl")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		logger.Error("加载模板失败: %v", err)
		return nil
	}
	return &ConfigGenerator{confDir: confDir, sitesDir: sitesDir, sslDir: sslDir, template: tmpl}
}

// Generate 生成所有反向代理配置。
// 安全：渲染前逐条校验，拒绝可造成配置注入的数据。
// 可用：全部记录非法时返回错误，阻止调用方 reload，避免 cleanup 后全站无配置。
func (g *ConfigGenerator) Generate(config *models.NginxConfig, proxies []models.ReverseProxy) error {
	if err := g.cleanupOldConfigs(); err != nil {
		logger.Warn("清理旧配置失败: %v", err)
	}

	total := len(proxies)
	generated := 0
	skipped := 0
	var reasons []string

	for _, proxy := range proxies {
		if err := g.generateProxyConfig(&proxy); err != nil {
			logger.Error("生成反向代理配置失败 [domain=%s]: %v", proxy.Domain, err)
			skipped++
			reasons = append(reasons, fmt.Sprintf("%s: %v", proxy.Domain, err))
			continue
		}
		generated++
	}

	if skipped > 0 {
		logger.Warn("生成统计: 总计 %d, 成功 %d, 跳过 %d", total, generated, skipped)
		for _, r := range reasons {
			logger.Warn("跳过原因: %s", r)
		}
	}

	if total > 0 && generated == 0 {
		return fmt.Errorf("全部 %d 条代理配置均生成失败，拒绝应用以避免全站中断", total)
	}
	return nil
}

type TemplateData struct {
	GeneratedAt   string
	ContainerName string
	Domain        string
	ContainerIP   string
	ContainerPort int
	SSLEnabled    bool
	SSLCertPath   string
	SSLKeyPath    string
	IPv6Enabled   bool
}

// ---------- 渲染层校验（最后一道防线） ----------

var (
	renderDomainRe        = regexp.MustCompile(`^[a-zA-Z0-9*._-]+$`)
	renderContainerNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$`)
)

func validateProxyForRender(p *models.ReverseProxy) error {
	// 1. 域名
	if p.Domain == "" || len(p.Domain) > 253 {
		return fmt.Errorf("域名非法: 长度为空或超限")
	}
	if !renderDomainRe.MatchString(p.Domain) {
		return fmt.Errorf("域名含非法字符: %q", p.Domain)
	}
	if strings.Contains(p.Domain, "..") {
		return fmt.Errorf("域名含非法序列: %q", p.Domain)
	}
	if p.Domain != "_" { // "_" 是 nginx 合法的 catch-all
		if strings.HasPrefix(p.Domain, ".") || strings.HasSuffix(p.Domain, ".") ||
			strings.HasPrefix(p.Domain, "-") || strings.HasSuffix(p.Domain, "-") {
			return fmt.Errorf("域名首尾非法: %q", p.Domain)
		}
	}
	if strings.Contains(p.Domain, "*") {
		if strings.Count(p.Domain, "*") != 1 {
			return fmt.Errorf("通配域名格式非法: %q", p.Domain)
		}
		isPrefix := strings.HasPrefix(p.Domain, "*.") && len(p.Domain) > 2
		isSuffix := strings.HasSuffix(p.Domain, ".*") && len(p.Domain) > 2
		if !isPrefix && !isSuffix {
			return fmt.Errorf("通配域名格式非法（只允许 *.example.com 或 www.example.*）: %q", p.Domain)
		}
	}

	// 2. 目标地址：入口层只允许 IP，这里保持一致
	// （hostname 在无 resolver 时会让 nginx -t 失败，不在渲染层放宽）
	if p.TargetIP == "" {
		return fmt.Errorf("目标地址为空")
	}
	if net.ParseIP(p.TargetIP) == nil {
		return fmt.Errorf("目标地址必须为 IP 字面量: %q", p.TargetIP)
	}
	if strings.ContainsAny(p.TargetIP, ";{}# \t\r\n'\"") {
		return fmt.Errorf("目标地址含非法字符: %q", p.TargetIP)
	}

	// 3. 端口
	if p.TargetPort < 1 || p.TargetPort > 65535 {
		return fmt.Errorf("目标端口非法: %d", p.TargetPort)
	}

	// 4. 协议：空值按 http 处理（与原版一致），其余非 http/https 拒绝
	if p.Protocol != "" && p.Protocol != "http" && p.Protocol != "https" {
		return fmt.Errorf("协议非法: %q", p.Protocol)
	}

	// 5. HTTPS 证书内容（依赖同包 api.go 的 validateSSL）
	if p.Protocol == "https" && p.EnableSSL && (p.SSLCert != "" || p.SSLKey != "") {
		if err := validateSSL(p.SSLCert, p.SSLKey); err != nil {
			return fmt.Errorf("SSL证书非法: %w", err)
		}
	}

	// 6. 容器名（当前模板未引用，纵深防御）
	if p.ContainerName != "" && !renderContainerNameRe.MatchString(p.ContainerName) {
		return fmt.Errorf("容器名非法: %q", p.ContainerName)
	}
	return nil
}

func (g *ConfigGenerator) generateProxyConfig(proxy *models.ReverseProxy) error {
	if err := validateProxyForRender(proxy); err != nil {
		return err
	}

	safeDomain := sanitizeDomain(proxy.Domain)
	var certPath, keyPath string
	var sslEnabled bool

	if proxy.Protocol == "https" && proxy.EnableSSL {
		sslEnabled = true
		certPath = filepath.Join(g.sslDir, safeDomain+".crt")
		keyPath = filepath.Join(g.sslDir, safeDomain+".key")

		if proxy.SSLCert != "" && proxy.SSLKey != "" {
			if err := os.WriteFile(certPath, []byte(proxy.SSLCert), 0644); err != nil {
				return fmt.Errorf("写入SSL证书失败: %v", err)
			}
			if err := os.WriteFile(keyPath, []byte(proxy.SSLKey), 0600); err != nil {
				return fmt.Errorf("写入SSL密钥失败: %v", err)
			}
		} else {
			if err := g.generateSelfSignedCert(proxy.Domain, certPath, keyPath); err != nil {
				return fmt.Errorf("生成自签名证书失败: %v", err)
			}
		}

		absCert, err := filepath.Abs(certPath)
		if err != nil {
			return fmt.Errorf("解析证书路径失败: %v", err)
		}
		absKey, err := filepath.Abs(keyPath)
		if err != nil {
			return fmt.Errorf("解析密钥路径失败: %v", err)
		}
		base, err := filepath.Abs(g.sslDir)
		if err != nil {
			return fmt.Errorf("解析 sslDir 失败: %v", err)
		}
		sep := string(os.PathSeparator)
		if !strings.HasPrefix(absCert, base+sep) {
			return fmt.Errorf("证书路径越界: %s", absCert)
		}
		if !strings.HasPrefix(absKey, base+sep) {
			return fmt.Errorf("密钥路径越界: %s", absKey)
		}
		certPath, keyPath = absCert, absKey
	}

	ipv6Enabled := g.hasIPv6()

	// IPv6 字面量在 proxy_pass 需要方括号
	containerIP := proxy.TargetIP
	if ip := net.ParseIP(containerIP); ip != nil && strings.Contains(containerIP, ":") {
		containerIP = "[" + containerIP + "]"
	}

	data := TemplateData{
		GeneratedAt:   time.Now().Format(time.RFC3339),
		ContainerName: proxy.ContainerName,
		Domain:        proxy.Domain,
		ContainerIP:   containerIP,
		ContainerPort: proxy.TargetPort,
		SSLEnabled:    sslEnabled,
		SSLCertPath:   certPath,
		SSLKeyPath:    keyPath,
		IPv6Enabled:   ipv6Enabled,
	}

	var buf bytes.Buffer
	if err := g.template.Execute(&buf, data); err != nil {
		return fmt.Errorf("生成配置失败: %v", err)
	}

	configPath := filepath.Join(g.sitesDir, safeDomain+".conf")
	if err := os.WriteFile(configPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("写入配置文件失败: %v", err)
	}

	logger.Info("已生成反向代理配置: %s -> %s:%d", proxy.Domain, proxy.TargetIP, proxy.TargetPort)
	return nil
}

func (g *ConfigGenerator) generateSelfSignedCert(domain, certPath, keyPath string) error {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成私钥失败: %v", err)
	}
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"lxdapi"}, CommonName: domain},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{domain},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("生成证书失败: %v", err)
	}

	certFile, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("创建证书文件失败: %v", err)
	}
	defer certFile.Close()
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("编码证书失败: %v", err)
	}

	keyFile, err := os.Create(keyPath)
	if err != nil {
		return fmt.Errorf("创建密钥文件失败: %v", err)
	}
	defer keyFile.Close()
	if err := pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}); err != nil {
		return fmt.Errorf("编码私钥失败: %v", err)
	}
	if err := os.Chmod(keyPath, 0600); err != nil {
		return fmt.Errorf("设置私钥权限失败: %v", err)
	}
	logger.Info("已为 %s 生成自签名证书（10年有效期）", domain)
	return nil
}

func (g *ConfigGenerator) hasIPv6() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if ok && ipNet.IP.IsGlobalUnicast() && len(ipNet.IP) == net.IPv6len {
				return true
			}
		}
	}
	return false
}

func (g *ConfigGenerator) cleanupOldConfigs() error {
	files, err := filepath.Glob(filepath.Join(g.sitesDir, "*.conf"))
	if err != nil {
		return err
	}
	for _, file := range files {
		if err := os.Remove(file); err != nil {
			logger.Warn("删除旧配置失败 %s: %v", file, err)
		}
	}
	return nil
}

// sanitizeDomain 生成安全文件名片段。合法域名输出不变。
func sanitizeDomain(domain string) string {
	domain = strings.ReplaceAll(domain, ":", "_")
	domain = strings.ReplaceAll(domain, "/", "_")
	domain = strings.ReplaceAll(domain, "\\", "_")
	for strings.Contains(domain, "..") {
		domain = strings.ReplaceAll(domain, "..", ".")
	}
	domain = strings.Trim(domain, ".")
	if domain == "" {
		domain = "invalid"
	}
	return domain
}
