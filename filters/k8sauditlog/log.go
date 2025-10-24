package k8sauditlog

import (
	"bytes"
	"github.com/zalando/skipper/filters"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	"time"
)

type asyncAuditLogFilter struct {
	logCh      LogChannel
	maxBodyLog int
}

func NewK8sAuditLog(ch LogChannel, maxBody int) filters.Spec {
	return &asyncAuditLogFilter{
		logCh:      ch,
		maxBodyLog: maxBody,
	}
}

func (a asyncAuditLogFilter) Name() string {
	return "k8sAuditLog"
}

func (a asyncAuditLogFilter) CreateFilter(args []interface{}) (filters.Filter, error) {
	if len(args) != 0 {
		return nil, filters.ErrInvalidFilterParameters
	}

	return &asyncAuditLogFilter{logCh: a.logCh, maxBodyLog: a.maxBodyLog}, nil
}

func (a asyncAuditLogFilter) Request(ctx filters.FilterContext) {
	req := ctx.Request()

	ctx.StateBag()["requestRecievedTimestamp"] = metav1.NewMicroTime(time.Now())

	ua := req.Header.Get("User-Agent")
	ctx.StateBag()["userAgent"] = ua

	ips := utilnet.SourceIPs(req)
	sourceIPs := make([]string, len(ips))
	for i := range ips {
		sourceIPs[i] = ips[i].String()
	}
	ctx.StateBag()["sourceIPs"] = sourceIPs

	if a.maxBodyLog > 0 {
		ctx.Request().Body = newTeeBody(ctx.Request().Body, a.maxBodyLog)
	}
}

func (a asyncAuditLogFilter) Response(ctx filters.FilterContext) {
	req := ctx.Request()
	rsp := ctx.Response()
	sb := ctx.StateBag()

	reqTimeVal := sb["requestRecievedTimestamp"].(metav1.MicroTime)
	user, _ := sb[AuthUserKey].(string)
	reason, _ := sb[AuthRejectReasonKey].(string)

	userAgent, _ := sb["userAgent"].(string)
	sourceIPs, _ := sb["sourceIPs"].([]string)

	reqBodyStr := ""
	if tb, ok := req.Body.(*teeBody); ok {
		if tb.buffer.Len() > 0 {
			reqBodyStr = tb.buffer.String()
		}
	}

	rawData := RawLogData{
		Method:       req.Method,
		RequestURI:   req.URL.RequestURI(),
		Status:       rsp.StatusCode,
		UserAgent:    userAgent,
		SourceIPs:    sourceIPs,
		Username:     user,
		RejectReason: reason,
		RequestBody:  reqBodyStr,
		ReceivedAt:   reqTimeVal,
	}

	select {
	case a.logCh <- rawData:
	default:

	}
}

func newTeeBody(rc io.ReadCloser, maxTee int) io.ReadCloser {
	b := bytes.NewBuffer(nil)
	tb := &teeBody{
		body:   rc,
		buffer: b,
		maxTee: maxTee}
	tb.teeReader = io.TeeReader(rc, tb)
	return tb
}

type teeBody struct {
	body      io.ReadCloser
	buffer    *bytes.Buffer
	teeReader io.Reader
	maxTee    int
}

func (tb *teeBody) Read(b []byte) (int, error) { return tb.teeReader.Read(b) }
func (tb *teeBody) Close() error               { return tb.body.Close() }

func (tb *teeBody) Write(b []byte) (int, error) {
	if tb.maxTee < 0 {
		return tb.buffer.Write(b)
	}

	wl := len(b)
	if wl >= tb.maxTee {
		wl = tb.maxTee
	}

	n, err := tb.buffer.Write(b[:wl])
	if err != nil {
		return n, err
	}

	tb.maxTee -= n

	// lie to avoid short write
	return len(b), nil
}
