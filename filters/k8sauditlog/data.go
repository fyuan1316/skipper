package k8sauditlog

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

type LogChannel chan RawLogData

const (
	AuthUserKey             = "auth-user"
	AuthRejectReasonKey     = "auth-reject-reason"
	maxUserAgentLength      = 256
	userAgentTruncateSuffix = "..."
)

type RawLogData struct {
	Method     string
	RequestURI string // 对应 Event.RequestURI
	Verb       string // 对应 Event.Verb (HTTP Method)
	Status     int    // 对应 Event.ResponseStatus.Code
	UserAgent  string // 对应 Event.UserAgent

	SourceIPs []string // 对应 Event.SourceIPs

	// --- Auth & Context ---
	Username     string // 对应 Event.User.Username
	RejectReason string // Skipper 内部拒绝理由

	// --- Body & Time ---
	RequestBody string           // 缓冲后的请求体 (对应 RequestObject)
	ReceivedAt  metav1.MicroTime // 请求接收时间

	AuditIDHeader string // 用于从 Filter 阶段传递审计 ID
}
