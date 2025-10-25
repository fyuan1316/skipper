package parser

import (
	"embed"
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// gitlab v4 restful api define
//
//go:embed gitlab_v4.yaml
var configFS embed.FS

type ResourceMapping struct {
	ResourceType string
	Pattern      *regexp.Regexp
	Template     string
}

type RawConfig struct {
	Mappings []struct {
		Scope     string `yaml:"scope"`
		Resources []struct {
			ResourceType string   `yaml:"resource_type_name"`
			URLs         []string `yaml:"urls"`
		} `yaml:"resources"`
	} `yaml:"mappings"`
}

var generatedResourceMappings []ResourceMapping
var rawConfigData RawConfig

func extractTrueSuffix(urlTemplate string) string {
	// 查找 ":id/" 作为分隔符
	separator := ":id/"
	index := strings.Index(urlTemplate, separator)

	if index == -1 {
		// 如果未找到 :id/ 分隔符，则返回空
		return ""
	}

	// 真正的后缀从 ":id/" 之后开始
	suffix := urlTemplate[index+len(separator):]

	// 清理可能存在的尾部斜杠或多余空格
	return strings.Trim(suffix, "/ ")
}

func initResourceMappings() {
	generatedResourceMappings = nil

	// 用于替换 :id 的捕获组
	//idCaptureGroup := "(\\d+)"
	idCaptureGroup := "([^/]+)"

	for _, mappingEntry := range rawConfigData.Mappings {
		scopeContext := mappingEntry.Scope

		var apiPrefix string // 完整的 API 版本前缀 (如 /api/v4/ 或 /api/)

		// 1. 确定 API 前缀
		switch scopeContext {
		case "project", "user":
			apiPrefix = "/api/v4/"
		case "graphql":
			apiPrefix = "/api/"
		case "group":
			apiPrefix = "/api/v4/"
		default:
			continue
		}

		// 2. 遍历资源和 URL
		for _, res := range mappingEntry.Resources {
			for _, urlTemplate := range res.URLs {

				// 核心逻辑: 构建正则表达式
				var patternString string

				// 基础正则开始：^ + API_PREFIX
				patternString = "^" + regexp.QuoteMeta(apiPrefix)

				// 3. 构建 URL 正则模式
				if strings.Contains(urlTemplate, ":id") {
					// --- 包含 ID 的路径 (e.g., /projects/:id/tags, /users/:id) ---

					// a. 提取 :id 之前的路径 (e.g., /projects)
					parts := strings.Split(urlTemplate, ":id")
					prefixPath := strings.Trim(parts[0], "/")

					// b. 提取 :id 之后的后缀 (e.g., /repository/tags 或 "")
					actualSuffix := ""
					if len(parts) > 1 {
						actualSuffix = strings.Trim(parts[1], "/")
					}

					// c. 拼接 API前缀 + ID路径段 + 捕获组 + 后缀

					// 拼接路径段 (e.g., projects)
					patternString += regexp.QuoteMeta(prefixPath)

					// 拼接 ID 捕获组
					patternString += "/" + idCaptureGroup

					if actualSuffix != "" {
						// 如果有后缀，添加分隔符和后缀
						patternString += "/" + regexp.QuoteMeta(actualSuffix)
					}

				} else {
					// --- 不含 ID 的路径 (e.g., /projects, /) ---

					actualSuffix := strings.Trim(urlTemplate, "/")

					if scopeContext == "graphql" && urlTemplate == "/" {
						// 特殊处理：graphql scope下的 / 对应 /api/graphql
						// 我们只需要匹配 /api/graphql 本身
						patternString += regexp.QuoteMeta("graphql")
					} else {
						// 其他无ID路径 (e.g., /projects)
						patternString += regexp.QuoteMeta(actualSuffix)
					}
				}

				// --- 关键修正：统一处理尾部斜杠和末尾锚点 ---
				// 允许匹配 0 次或 1 次斜杠，然后是字符串的结束。
				patternString += "/?$"

				// 4. 编译和存储
				re, err := regexp.Compile(patternString)
				if err != nil {
					panic(fmt.Sprintf("Failed to compile regex for %s URL %s: %v", res.ResourceType, urlTemplate, err))
				}

				mapping := ResourceMapping{
					ResourceType: res.ResourceType,
					Pattern:      re,
					// 模板使用完整的 URL 模板
					Template: urlTemplate,
				}
				generatedResourceMappings = append(generatedResourceMappings, mapping)
			}
		}
	}
}

func PreprocessURLStrongBinding(fullURL string) (string, error) {
	knownPrefixes := []string{"/api/v4/", "/api/graphql"}

	for _, prefix := range knownPrefixes {
		if strings.Contains(fullURL, prefix) {
			idx := strings.Index(fullURL, prefix)
			// 返回从 /api/... 起始的字符串
			return fullURL[idx:], nil
		}
	}

	return "", fmt.Errorf("未找到预期的 API 前缀")
}

func ParseResourceType(fullURL string) (string, string, error) {
	corePath, err := PreprocessURLStrongBinding(fullURL)
	if err != nil {
		return "", "", err
	}

	for _, mapping := range generatedResourceMappings {
		matches := mapping.Pattern.FindStringSubmatch(corePath)

		if len(matches) > 0 {
			resourceID := ""
			// 只有当有捕获组时，我们才认为是 ID。由于我们只在 ID 处插入 (\d+)，matches[1] 总是主 ID。
			if mapping.Pattern.NumSubexp() > 0 {
				resourceID = matches[1]
			}

			return mapping.ResourceType, resourceID, nil
		}
	}

	return "", "", fmt.Errorf("未找到匹配的资源类型定义 (核心路径: %s)", corePath)
}

func init() {
	data, err := configFS.ReadFile("gitlab_v4.yaml")
	if err != nil {
		panic(fmt.Sprintf("Failed to read embedded gitlab_v4.yaml: %v", err))
	}

	err = yaml.Unmarshal(data, &rawConfigData)
	if err != nil {
		panic(fmt.Sprintf("Failed to unmarshal embedded YAML: %v", err))
	}

	initResourceMappings()
}
