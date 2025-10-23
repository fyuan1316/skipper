package k8sauditlog

import (
	"encoding/json"
	"github.com/google/uuid"
	"io"
	authnv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"os"
	"time"
)

const (
	statusSuccess = "Success" // 它被定义在这里
	statusFailure = "Failure"
)

// StartLogCollector 启动一个专用 Goroutine 来处理日志 I/O 和 K8s 结构转换
func StartLogCollector(ch LogChannel, k8sAuditOutput io.Writer, done chan struct{}) {
	// 1. 确保在函数退出时通知主程序我们已完成
	defer close(done)
	if k8sAuditOutput == nil {
		return
	}
	var closer io.Closer
	if c, ok := k8sAuditOutput.(io.Closer); ok {
		closer = c
	}
	defer func() {
		// 尝试 Sync (只针对 *os.File)
		if f, ok := k8sAuditOutput.(*os.File); ok {
			// log.Println("Log collector: Syncing...")
			f.Sync()
		}

		// 尝试 Close (只在 closer 存在时执行)
		if closer != nil {
			// log.Println("Log collector: Closing output stream.")
			closer.Close()
		}
	}()

	for rawData := range ch {
		// ... (4a, 4b JSON 编码) ...
		ev := buildK8sAuditEvent(rawData)
		data, err := json.Marshal(ev)
		// ... (错误处理) ...
		data = append(data, '\n')

		// 4c. 写入 (I/O 密集型)
		_, err = k8sAuditOutput.Write(data)
		if err != nil {
			// log.Printf("Log collector: Failed to write K8s Audit Log: %v", err)
		}

		// 4d. Sync (只针对 *os.File)
		if f, ok := k8sAuditOutput.(*os.File); ok {
			f.Sync()
		}
	}
}

// buildK8sAuditEvent 负责将轻量级结构转换为完整的 K8s Audit Event
func buildK8sAuditEvent(data RawLogData) *auditinternal.Event {
	auditIDStr := data.AuditIDHeader
	if auditIDStr == "" {
		auditIDStr = uuid.New().String()
	}

	ev := &auditinternal.Event{
		Level:                    auditinternal.LevelRequestResponse,
		Stage:                    auditinternal.StageResponseComplete,
		RequestURI:               data.RequestURI,
		UserAgent:                maybeTruncateUserAgent(data.UserAgent), // 需要确保 UserAgent 在 RawLogData 中
		RequestReceivedTimestamp: data.ReceivedAt,
		StageTimestamp:           metav1.NewMicroTime(time.Now()),

		AuditID: types.UID(auditIDStr),
	}

	// 填充响应状态
	status := statusSuccess
	if data.Status >= 400 {
		status = statusFailure
	}
	ev.ResponseStatus = &metav1.Status{
		Status: status,
		Code:   int32(data.Status),
	}

	// 填充 User 信息 (这里需要更复杂的映射，简化处理)
	if data.Username != "" {
		ev.User = authnv1.UserInfo{
			Username: data.Username,
			// 其他字段（如UID, Groups）需要从 StateBag 中获取并在 Filter 阶段传入
		}
	}

	if data.RequestBody != "" {
		// 验证 RequestBody 是否为有效的 JSON
		if json.Valid([]byte(data.RequestBody)) {
			// 如果是有效的 JSON，我们将其作为原始字节存储在 runtime.Unknown 中
			ev.RequestObject = &runtime.Unknown{
				Raw:         []byte(data.RequestBody),
				ContentType: "application/json",
			}
		}
	}

	// ResponseObject 在 Filter 阶段难以获取，通常留空或依赖 ResponseBody 拦截器

	return ev
}

// maybeTruncateUserAgent
func maybeTruncateUserAgent(ua string) string {
	if len(ua) > maxUserAgentLength {
		return ua[:maxUserAgentLength] + userAgentTruncateSuffix
	}
	return ua
}
