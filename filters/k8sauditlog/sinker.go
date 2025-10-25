package k8sauditlog

import (
	"context"
	"encoding/json"
	"io"
	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"os"
)

//-k8s-audit-log=/Users/yuan/Dev/lab/test-skipper/gitlab.log -inline-routes 'r: * -> gitlabAuditLog() -> inlineContent("Hello world!") -> status(200) -> <shunt>'
//-k8s-audit-log=/Users/yuan/Dev/lab/test-skipper/gitlab.log
//-inline-routes
//'r:
//Path("/gitlab/namespaces/:namespace/*path")
//->
//gitlabAuditLog()
//->
//inlineContent("Hello world!")
//->
//status(200)
//->
//<shunt>'

const (
	statusSuccess = "Success"
	statusFailure = "Failure"
)

// StartLogSinker 启动一个专用 Goroutine 来处理日志
func StartLogSinker(ctx context.Context, ch LogChannel, k8sAuditOutput io.Writer, done chan struct{}) {
	defer close(done)
	if k8sAuditOutput == nil {
		return
	}
	var closer io.Closer
	if c, ok := k8sAuditOutput.(io.Closer); ok {
		closer = c
	}
	defer func() {
		if f, ok := k8sAuditOutput.(*os.File); ok {
			// log.Println("Log collector: Syncing...")
			f.Sync()
		}

		if closer != nil {
			closer.Close()
		}
	}()

	for {
		select {
		case rawData, ok := <-ch:
			if !ok {
				// 输入通道关闭，退出循环，准备执行 defer 清理
				//log("Log Collector: Input channel closed. Finishing processing.")
				return
			}

			ev := buildK8sAuditEvent(rawData)
			data, err := json.Marshal(ev)
			if err != nil {
				//log("Log Collector: JSON Marshal error:", err)
				continue
			}
			data = append(data, '\n')

			_, err = k8sAuditOutput.Write(data)
			if err != nil {
				//log("Log Collector: Failed to write K8s Audit Log:", err)
			}

			// Sync (保持 I/O 密集型操作，因为 Context 还没有被取消)
			if f, ok := k8sAuditOutput.(*os.File); ok {
				f.Sync()
			}

		case <-ctx.Done():
			// 接收到主程序的取消信号
			//log("Log Collector: Received main context cancel signal. Stopping input reading.")
			return
		}
	}
}

// buildK8sAuditEvent 转换完整的 K8s Audit Event
func buildK8sAuditEvent(data RawLogData) *auditinternal.Event {
	ev := &auditinternal.Event{
		Level:      auditinternal.Level(data.Level),
		Stage:      auditinternal.Stage(data.Stage),
		RequestURI: data.RequestURI,
		UserAgent:  data.UserAgent,
		// RequestObject: ""  // handle it later
		// ResponseObject: "" // not record
		ResponseStatus:           data.ResponseStatus,
		RequestReceivedTimestamp: data.ReceivedAt,
		StageTimestamp:           data.StageTimestamp,
		AuditID:                  types.UID(data.AuditIDHeader),
		SourceIPs:                data.SourceIPs,
		User: authnv1.UserInfo{
			Username: data.User.Username,
			UID:      data.User.UID,
			Groups:   data.User.Groups,
		},
		Verb:      data.Verb,
		ObjectRef: data.ObjectRef,
	}

	if data.RequestObject != "" {
		if json.Valid([]byte(data.RequestObject)) {
			ev.RequestObject = &runtime.Unknown{
				Raw:         []byte(data.RequestObject),
				ContentType: "application/json",
			}
		}
	}

	return ev
}
