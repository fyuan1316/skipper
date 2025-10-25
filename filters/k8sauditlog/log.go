package k8sauditlog

import (
	"bytes"
	"context"
	"github.com/google/uuid"
	"github.com/zalando/skipper/eskip"
	"github.com/zalando/skipper/filters"
	"github.com/zalando/skipper/filters/k8sauditlog/internal/parser"
	"io"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilnet "k8s.io/apimachinery/pkg/util/net"
	auditinternal "k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"net/http"
	"strings"
	"time"
)

const (
	NameSpace    = "p_bag_namespace"
	ReqTs        = "p_bag_req_ts"
	ResourceKind = "p_bag_resource_kind"
	ResourceName = "p_bag_resource_name"
	UserAgent    = "p_bag_user_agent"
	SourceIPs    = "p_bag_source_ips"

	NameSpaceTPL   = "${namespace}"
	FakeApiGroup   = "gitlab.io"
	FakeApiVersion = "v4"
)

type asyncAuditLogFilter struct {
	logCh      LogChannel
	maxBodyLog int

	tokenParser  authenticator.Token
	namespaceTpl *eskip.Template
}

func NewK8sAuditLog(ch LogChannel, maxBody int) filters.Spec {
	return &asyncAuditLogFilter{
		logCh:        ch,
		maxBodyLog:   maxBody,
		tokenParser:  NewOIDCTokenParser(),
		namespaceTpl: eskip.NewTemplate(NameSpaceTPL),
	}
}

func (a *asyncAuditLogFilter) Name() string {
	return "gitlabAuditLog"
}

func (a *asyncAuditLogFilter) CreateFilter(args []interface{}) (filters.Filter, error) {
	if len(args) != 0 {
		return nil, filters.ErrInvalidFilterParameters
	}

	return &asyncAuditLogFilter{
		logCh: a.logCh, maxBodyLog: a.maxBodyLog, tokenParser: a.tokenParser, namespaceTpl: a.namespaceTpl,
	}, nil
}

func (a *asyncAuditLogFilter) Request(ctx filters.FilterContext) {
	req := ctx.Request()

	if resourceType, _, err := parser.ParseResourceType(req.RequestURI); err == nil {
		ctx.StateBag()[ResourceKind] = resourceType
	}
	if resourceName, err := parser.PreprocessURLStrongBinding(req.RequestURI); err == nil {
		ctx.StateBag()[ResourceName] = resourceName
	}
	if ns, ok := a.namespaceTpl.ApplyContext(ctx); ok {
		ctx.StateBag()[NameSpace] = ns
	}
	ctx.StateBag()[ReqTs] = metav1.NewMicroTime(time.Now())

	ua := req.Header.Get("User-Agent")
	ctx.StateBag()[UserAgent] = ua

	ips := utilnet.SourceIPs(req)
	sourceIPs := make([]string, len(ips))
	for i := range ips {
		sourceIPs[i] = ips[i].String()
	}
	ctx.StateBag()[SourceIPs] = sourceIPs

	if a.maxBodyLog > 0 {
		ctx.Request().Body = newTeeBody(ctx.Request().Body, a.maxBodyLog)
	}
}

func (a *asyncAuditLogFilter) Response(ctx filters.FilterContext) {
	req := ctx.Request()
	rsp := ctx.Response()
	sb := ctx.StateBag()

	reqTimeVal := sb[ReqTs].(metav1.MicroTime)
	userAgent, _ := sb[UserAgent].(string)
	sourceIPs, _ := sb[SourceIPs].([]string)

	var resKind, resName, ns string
	resKind = sb[ResourceKind].(string)
	resName = sb[ResourceName].(string)
	ns = sb[NameSpace].(string)

	reqBodyStr := ""
	if tb, ok := req.Body.(*teeBody); ok {
		if tb.buffer.Len() > 0 {
			reqBodyStr = tb.buffer.String()
		}
	}

	ids := req.Header.Get(auditinternal.HeaderAuditID)
	if ids == "" {
		ids = uuid.New().String()
	}

	statusCode := int32(rsp.StatusCode)
	status := statusSuccess
	if statusCode >= 400 {
		status = statusFailure
	}
	rawData := RawLogData{
		Level:          string(auditinternal.LevelMetadata),
		Stage:          string(auditinternal.StageResponseComplete),
		RequestURI:     req.URL.RequestURI(),
		UserAgent:      maybeTruncateUserAgent(userAgent),
		RequestObject:  reqBodyStr,
		ResponseObject: "",
		ResponseStatus: &metav1.Status{Status: status, Code: statusCode},
		ReceivedAt:     reqTimeVal,
		StageTimestamp: metav1.NewMicroTime(time.Now()),
		AuditIDHeader:  ids,
		SourceIPs:      sourceIPs,
		Verb:           req.Method,
		ObjectRef: &auditinternal.ObjectReference{
			APIGroup:   FakeApiGroup,
			APIVersion: FakeApiVersion,
			Resource:   resKind,
			Namespace:  ns,
			Name:       resName,
		},
	}
	ProcessUserInfo(a.tokenParser, &rawData, req)

	select {
	case a.logCh <- rawData:
	default:

	}
}

func ProcessUserInfo(tokenParser authenticator.Token, data *RawLogData, req *http.Request) {
	data.User = UserInfo{
		Username: anonymousUser,
	}

	token := GetToken(req)
	if token == "" {
		return
	}

	userResp, _, err := tokenParser.AuthenticateToken(context.TODO(), token)
	if err != nil {
		return
	}
	data.User = UserInfo{
		Username: userResp.User.GetName(),
		UID:      userResp.User.GetUID(),
		Groups:   userResp.User.GetGroups(),
	}
}

const (
	// AuthorizationHeader authorization header for http requests
	AuthorizationHeader = "Authorization"
	// BearerPrefix bearer token prefix for token
	BearerPrefix = "Bearer "

	// QueryParameterTokenName authorization token for http requests
	QueryParameterTokenName = "token"
)

func GetToken(req *http.Request) (token string) {
	authHeader := req.Header.Get(AuthorizationHeader)

	if authHeader != "" && strings.HasPrefix(authHeader, BearerPrefix) && strings.TrimPrefix(authHeader, BearerPrefix) != "" {
		token = strings.TrimPrefix(authHeader, BearerPrefix)
		return
	}

	token = req.FormValue(QueryParameterTokenName)
	return
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
