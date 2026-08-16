// Package httpapi 提供 RBAC 权限规则求值引擎的 HTTP 接口。
// 服务持有内存状态（角色定义与用户授权），并发安全。
package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"task027-rbac/internal/rbac"
)

// ErrBadJSON 表示请求体不是单个合法 JSON 对象。
var ErrBadJSON = errors.New("请求体不是合法的单个 JSON 对象")

// API 是 RBAC 服务的 HTTP 接口实现，内含一份权限存储。
type API struct {
	store *rbac.Store
}

// New 创建服务实例，自带空的权限存储。
func New() *API { return &API{store: rbac.New()} }

// Handler 返回 HTTP 路由。
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", a.health)
	mux.HandleFunc("POST /roles", a.putRole)
	mux.HandleFunc("POST /grant", a.grant)
	mux.HandleFunc("POST /check", a.check)
	mux.HandleFunc("POST /permissions", a.permissions)
	return mux
}

// decodeJSON 解码单个 JSON 对象，拒绝多段 JSON 与未知字段。
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return ErrBadJSON
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("%w: %v", ErrBadJSON, err)
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return ErrBadJSON
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// roleRequest 是创建/更新角色的请求体。
type roleRequest struct {
	ID      string   `json:"id"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
	Parents []string `json:"parents"`
}

// outcome 是写操作端点的统一回应。
type outcome struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (a *API) putRole(w http.ResponseWriter, r *http.Request) {
	var req roleRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, outcome{OK: false, Error: err.Error()})
		return
	}
	if err := a.store.PutRole(rbac.Role{
		ID:      req.ID,
		Allow:   req.Allow,
		Deny:    req.Deny,
		Parents: req.Parents,
	}); err != nil {
		writeJSON(w, http.StatusBadRequest, outcome{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, outcome{OK: true})
}

// grantRequest 是授予角色的请求体。
type grantRequest struct {
	User string `json:"user"`
	Role string `json:"role"`
}

func (a *API) grant(w http.ResponseWriter, r *http.Request) {
	var req grantRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, outcome{OK: false, Error: err.Error()})
		return
	}
	if err := a.store.GrantRole(req.User, req.Role); err != nil {
		writeJSON(w, http.StatusBadRequest, outcome{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, outcome{OK: true})
}

// checkRequest 是权限判定的请求体。
type checkRequest struct {
	User       string `json:"user"`
	Permission string `json:"permission"`
}

// checkResponse 是权限判定的回应。
type checkResponse struct {
	Decision string `json:"decision"`
	Error    string `json:"error,omitempty"`
}

func (a *API) check(w http.ResponseWriter, r *http.Request) {
	var req checkRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, checkResponse{Error: err.Error()})
		return
	}
	d, err := a.store.Check(req.User, req.Permission)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, checkResponse{Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, checkResponse{Decision: string(d)})
}

// permissionsRequest 是查询用户全部可达权限的请求体。
type permissionsRequest struct {
	User string `json:"user"`
}

// permissionsResponse 返回去重并排序后的 allow 与 deny 清单。
type permissionsResponse struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

func (a *API) permissions(w http.ResponseWriter, r *http.Request) {
	var req permissionsRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, permissionsResponse{})
		return
	}
	allow, deny := a.store.EffectivePermissions(req.User)
	if allow == nil {
		allow = []string{}
	}
	if deny == nil {
		deny = []string{}
	}
	writeJSON(w, http.StatusOK, permissionsResponse{Allow: allow, Deny: deny})
}
