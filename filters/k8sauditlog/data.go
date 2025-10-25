package k8sauditlog

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
)

type LogChannel chan RawLogData

const (
	maxUserAgentLength      = 256
	userAgentTruncateSuffix = "..."
	anonymousUser           = "system:anonymous"
)

type RawLogData struct {
	Level          string           // 默认 RequestResponse, 支持: Metadata, Request
	Stage          string           // 默认 ResponseComplete
	RequestURI     string           // 对应 req.URL.RequestURI()
	UserAgent      string           // 对应 maybeTruncateUserAgent(req)
	RequestObject  string           // empty
	ResponseObject string           // empty
	ResponseStatus *metav1.Status   // .Status 和 .Code
	ReceivedAt     metav1.MicroTime // 请求接收时间
	StageTimestamp metav1.MicroTime // event 创建时的时间
	AuditIDHeader  string           // header("Audit-ID") 获取 或 创建
	SourceIPs      []string         // 对应 Event.SourceIPs
	User           UserInfo         // 记录 .Username, UID, Groups, fallback= system:anonymous
	Verb           string           // req.Method
	ObjectRef      *auditinternal.ObjectReference
}

type UserInfo struct {
	Username string
	UID      string
	Groups   []string
}

// maybeTruncateUserAgent
func maybeTruncateUserAgent(ua string) string {
	if len(ua) > maxUserAgentLength {
		return ua[:maxUserAgentLength] + userAgentTruncateSuffix
	}
	return ua
}
