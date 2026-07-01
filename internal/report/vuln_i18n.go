package report

import (
	"strings"

	"github.com/CycSpring/SpringX-Scanner/internal/model"
)

// vulnTranslation holds a Chinese name and default remediation for a common
// vulnerability class. Matched by CWE ID, template ID prefix, or keywords in
// the English name. This is a curated knowledge base, not exhaustive — unmatched
// vulnerabilities fall back to the original English name and (if absent) a
// generic remediation.
type vulnTranslation struct {
	cwe         string
	templateID  string // exact match on TemplateID
	nameKeyword string // case-insensitive substring match on Name
	zhName      string
	remediation string
}

var vulnTranslations = []vulnTranslation{
	// .env / config file disclosure
	{cwe: "cwe-552", zhName: "敏感文件泄露", remediation: "限制敏感配置文件（如 .env）的外部访问。在 Web 服务器配置中添加访问规则，禁止公开访问 .env、.git、备份文件等敏感路径。例如在 Nginx 中添加：location ~ /\\.env { deny all; }"},
	{cwe: "cwe-522", zhName: "凭据泄露", remediation: "确保包含凭据的文件（如 .env、配置文件）不被公开访问。将敏感凭据迁移到环境变量或密钥管理服务中，不要硬编码在代码或配置文件里。限制相关文件的外部访问权限。"},
	{templateID: "codeigniter-env", zhName: "CodeIgniter .env 配置文件泄露", remediation: "禁止公开访问 .env 文件。在 Web 服务器配置中添加访问规则：location ~ /\\.env { deny all; }。将敏感配置迁移到环境变量，确保 .env 文件不在 Web 根目录可访问范围内。"},
	{templateID: "laravel-env", zhName: "Laravel .env 敏感信息泄露", remediation: "禁止公开访问 .env 文件。在 Nginx/Apache 配置中添加：location ~ /\\.env { deny all; }。确保 Laravel 的 public 目录是唯一对外暴露的目录，其他所有文件应位于 Web 根目录之上。"},
	{templateID: "generic-env", zhName: ".env 环境配置文件泄露", remediation: "禁止公开访问 .env 文件。在 Web 服务器配置中添加访问规则阻止对 .env 的请求，将敏感凭据迁移到密钥管理服务。"},
	// git exposure
	{templateID: "git-config", zhName: "Git 仓库配置泄露", remediation: "禁止公开访问 .git 目录。在 Nginx 中添加：location ~ /\\.git { deny all; }。确保 .git 目录不在 Web 根目录中，或将其移到 Web 可访问目录之外。"},
	{nameKeyword: ".git", zhName: "Git 仓库信息泄露", remediation: "禁止公开访问 .git 目录及其内容。在 Web 服务器配置中添加规则阻止对 .git 路径的请求，防止源代码和提交历史泄露。"},
	// backup files
	{nameKeyword: "backup", zhName: "备份文件暴露", remediation: "删除 Web 根目录下的所有备份文件（.bak、.sql、.zip 等），或在 Web 服务器配置中禁止访问这些文件扩展名。定期检查 Web 目录确保无遗留备份。"},
	{nameKeyword: ".sql", zhName: "SQL 数据库备份泄露", remediation: "立即删除 Web 可访问目录中的 .sql 备份文件。将数据库备份存储在非 Web 可访问的位置，并设置适当的文件权限。"},
	// admin panels
	{nameKeyword: "admin", zhName: "管理后台暴露", remediation: "限制管理后台的访问：1）添加 IP 白名单；2）启用强密码和双因素认证；3）更改默认后台路径；4）在不需要时禁用或删除管理面板。"},
	{nameKeyword: "panel", zhName: "管理面板暴露", remediation: "限制管理面板的外部访问，添加 IP 白名单或 VPN 限制。启用强认证机制，更改默认路径，确保面板仅限授权用户访问。"},
	// phpinfo
	{nameKeyword: "phpinfo", zhName: "PHP 信息泄露", remediation: "禁用或限制访问 phpinfo.php 页面。在生产环境中移除该文件，或在 php.ini 中设置 expose_php = Off。phpinfo 页面会泄露服务器配置、路径和扩展信息，有利于攻击者侦察。"},
	// directory listing
	{nameKeyword: "directory listing", zhName: "目录列表暴露", remediation: "关闭 Web 服务器的目录列表功能。在 Nginx 中设置 autoindex off;，在 Apache 中设置 Options -Indexes。确保 Web 根目录有默认索引文件（index.html）。"},
	// XSS
	{cwe: "cwe-79", zhName: "跨站脚本攻击（XSS）", remediation: "对所有用户输入和输出进行严格的编码和转义。使用框架内置的 XSS 防护（如 Vue 的自动转义），或引入 CSP（内容安全策略）头。设置 HttpOnly 和 Secure 标志的 Cookie 属性。"},
	// SQL injection
	{cwe: "cwe-89", zhName: "SQL 注入", remediation: "使用参数化查询（Prepared Statements）替代字符串拼接 SQL。使用 ORM 框架的查询构建器，对用户输入进行严格的类型校验和过滤。部署 WAF 规则作为补充防护。"},
	// RCE
	{cwe: "cwe-94", zhName: "远程代码执行（RCE）", remediation: "严禁将用户输入传入代码执行函数（eval、exec 等）。使用白名单机制限制可执行的命令，对所有用户输入进行严格的过滤和转义。升级到不受影响的版本。"},
	// SSRF
	{cwe: "cwe-918", zhName: "服务端请求伪造（SSRF）", remediation: "对应用发起的外部请求进行严格的 URL 校验和白名单限制。禁止访问内部网络地址（127.0.0.1、10.x、172.16-31.x、192.168.x）。禁用不必要的协议（file://、gopher://）。"},
	// LFI/RFI
	{cwe: "cwe-98", zhName: "文件包含漏洞", remediation: "避免将用户输入直接传入文件包含函数。使用白名单机制限制可包含的文件路径，关闭 allow_url_include 和 allow_url_fopen（PHP）。将包含文件放在安全目录下。"},
	// Open redirect
	{cwe: "cwe-601", zhName: "开放重定向", remediation: "对重定向目标 URL 进行白名单校验，不直接使用用户提供的 URL 作为重定向目标。使用相对路径或内部路由替代外部 URL。"},
	// Default credentials
	{nameKeyword: "default credential", zhName: "默认凭据", remediation: "立即更改所有默认密码和凭据。使用强密码策略，启用双因素认证。删除不必要的默认账户，确保所有管理界面使用唯一且强健的凭据。"},
	{nameKeyword: "default password", zhName: "默认密码", remediation: "立即更改所有默认密码。使用强密码策略（至少12位、含大小写字母数字和特殊字符），启用双因素认证。定期轮换密码。"},
	// Tech detection / fingerprint
	{nameKeyword: "detect", zhName: "技术栈指纹识别", remediation: "隐藏服务器版本信息。在 Nginx 中设置 server_tokens off;，移除 X-Powered-By 响应头，关闭不必要的 banner 信息。这不会直接修复漏洞但减少攻击面。"},
	// CORS
	{nameKeyword: "cors", zhName: "CORS 跨域配置不当", remediation: "严格限制 CORS 策略：1）不要使用 Access-Control-Allow-Origin: * 配合凭据；2）使用白名单校验 Origin；3）最小化 Access-Control-Allow-Methods 和 Headers。"},
	// TLS/SSL
	{nameKeyword: "tls", zhName: "TLS/SSL 配置问题", remediation: "升级到 TLS 1.2+，禁用 SSLv3/TLS 1.0/1.1。使用强密码套件，启用 HSTS 头（Strict-Transport-Security）。定期检查证书有效期并自动续期。"},
	{nameKeyword: "ssl", zhName: "SSL 配置问题", remediation: "升级到 TLS 1.2+，禁用弱密码套件。启用 HSTS，确保证书链完整。使用 SSL Labs 等工具定期检查 SSL 配置评级。"},
}

// translateVulnName returns a Chinese name for a vulnerability if a match is
// found in the knowledge base; otherwise it returns the original English name.
// Matching is done in priority order: exact templateID first, then CWE, then
// name keyword — so a precise template-specific translation always wins over a
// broad CWE-based one.
func translateVulnName(v model.Vulnerability) string {
	if t := matchTranslation(v); t != nil {
		return t.zhName
	}
	return v.Name
}

// defaultRemediation returns a remediation suggestion: the template's own
// remediation if present, otherwise a match from the knowledge base, otherwise
// a generic suggestion.
func defaultRemediation(v model.Vulnerability) string {
	if v.Remediation != "" {
		return v.Remediation
	}
	if t := matchTranslation(v); t != nil && t.remediation != "" {
		return t.remediation
	}
	return "建议排查该漏洞的影响范围，及时修补或升级受影响组件。参考相关 CVE/CWE 信息获取详细修复指导。"
}

// matchTranslation finds the best translation entry for a vulnerability using
// three-stage priority: exact templateID, then CWE, then name keyword.
func matchTranslation(v model.Vulnerability) *vulnTranslation {
	// Stage 1: exact template ID.
	for i := range vulnTranslations {
		t := &vulnTranslations[i]
		if t.templateID != "" && v.TemplateID == t.templateID {
			return t
		}
	}
	// Stage 2: CWE match.
	for i := range vulnTranslations {
		t := &vulnTranslations[i]
		if t.cwe != "" {
			for _, cwe := range v.CWE {
				if strings.EqualFold(cwe, t.cwe) {
					return t
				}
			}
		}
	}
	// Stage 3: name keyword match.
	lower := strings.ToLower(v.Name + " " + v.TemplateID)
	for i := range vulnTranslations {
		t := &vulnTranslations[i]
		if t.nameKeyword != "" && strings.Contains(lower, strings.ToLower(t.nameKeyword)) {
			return t
		}
	}
	return nil
}
