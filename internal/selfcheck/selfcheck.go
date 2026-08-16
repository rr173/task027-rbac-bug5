// Package selfcheck 提供无需外部依赖的自检：通过 httptest 启动真实 HTTP
// 服务，覆盖角色创建、授权、判定、拒绝优先、循环继承被拒、未知角色被拒、
// 格式非法被拒、传递继承合并、覆盖更新生效等路径。成功返回 0，任一失败返回 1。
package selfcheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"

	"task027-rbac/internal/httpapi"
)

// Run 执行自检并返回退出码。
func Run() int {
	passed, failed := 0, 0
	check := func(name string, fn func() error) {
		if err := fn(); err != nil {
			failed++
			fmt.Printf("FAIL %-36s %v\n", name, err)
		} else {
			passed++
			fmt.Printf("PASS %s\n", name)
		}
	}

	srv := httptest.NewServer(httpapi.New().Handler())
	defer srv.Close()

	do := func(method, path, body string) (*http.Response, []byte, error) {
		var r io.Reader
		if body != "" {
			r = bytes.NewReader([]byte(body))
		}
		req, err := http.NewRequest(method, srv.URL+path, r)
		if err != nil {
			return nil, nil, err
		}
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, nil, err
		}
		data, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, data, readErr
	}
	marshal := func(m map[string]any) string {
		b, _ := json.Marshal(m)
		return string(b)
	}
	role := func(id string, allow, deny, parents []string) string {
		return marshal(map[string]any{
			"id":      id,
			"allow":   allow,
			"deny":    deny,
			"parents": parents,
		})
	}

	// 端点封装。
	putRole := func(body string) (int, bool, string, error) {
		resp, data, err := do(http.MethodPost, "/roles", body)
		if err != nil {
			return 0, false, "", err
		}
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out.OK, out.Error, nil
	}
	grant := func(user, roleID string) (int, bool, string, error) {
		resp, data, err := do(http.MethodPost, "/grant", marshal(map[string]any{"user": user, "role": roleID}))
		if err != nil {
			return 0, false, "", err
		}
		var out struct {
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out.OK, out.Error, nil
	}
	checkPerm := func(user, perm string) (int, string, string, error) {
		resp, data, err := do(http.MethodPost, "/check", marshal(map[string]any{"user": user, "permission": perm}))
		if err != nil {
			return 0, "", "", err
		}
		var out struct {
			Decision string `json:"decision"`
			Error    string `json:"error"`
		}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out.Decision, out.Error, nil
	}
	permissions := func(user string) (int, []string, []string, error) {
		resp, data, err := do(http.MethodPost, "/permissions", marshal(map[string]any{"user": user}))
		if err != nil {
			return 0, nil, nil, err
		}
		var out struct {
			Allow []string `json:"allow"`
			Deny  []string `json:"deny"`
		}
		_ = json.Unmarshal(data, &out)
		return resp.StatusCode, out.Allow, out.Deny, nil
	}

	// ---- 健康检查 ----
	check("健康检查", func() error {
		resp, _, err := do(http.MethodGet, "/healthz", "")
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status=%d", resp.StatusCode)
		}
		return nil
	})

	// ---- 正常授权路径 ----
	check("创建角色", func() error {
		status, ok, errStr, err := putRole(role("admin", []string{"doc:read", "doc:write"}, nil, nil))
		if err != nil {
			return err
		}
		if status != http.StatusOK || !ok {
			return fmt.Errorf("status=%d ok=%v err=%s", status, ok, errStr)
		}
		return nil
	})

	check("授予角色并判定 allow", func() error {
		if _, _, _, err := putRole(role("reader", []string{"doc:read"}, nil, nil)); err != nil {
			return err
		}
		status, ok, _, err := grant("alice", "reader")
		if err != nil {
			return err
		}
		if status != http.StatusOK || !ok {
			return fmt.Errorf("grant status=%d ok=%v", status, ok)
		}
		status, dec, _, err := checkPerm("alice", "doc:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "allow" {
			return fmt.Errorf("check status=%d dec=%q want allow", status, dec)
		}
		return nil
	})

	check("未授权权限返回 undefined", func() error {
		status, dec, _, err := checkPerm("alice", "doc:delete")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "undefined" {
			return fmt.Errorf("status=%d dec=%q want undefined", status, dec)
		}
		return nil
	})

	check("未创建用户返回 undefined", func() error {
		status, dec, _, err := checkPerm("nobody", "doc:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "undefined" {
			return fmt.Errorf("status=%d dec=%q want undefined", status, dec)
		}
		return nil
	})

	check("已创建无角色用户返回 undefined", func() error {
		// grant 一个角色给 bob 之前先创建角色，但不授予 bob 任何角色。
		if _, _, _, err := putRole(role("viewer", []string{"img:read"}, nil, nil)); err != nil {
			return err
		}
		status, dec, _, err := checkPerm("bob", "img:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "undefined" {
			return fmt.Errorf("status=%d dec=%q want undefined", status, dec)
		}
		return nil
	})

	// ---- 拒绝优先 ----
	check("拒绝优先(deny-overrides)", func() error {
		if _, _, _, err := putRole(role("denier", nil, []string{"doc:read"}, nil)); err != nil {
			return err
		}
		// alice 已有 reader(doc:read allow)，再授予 denier(doc:read deny)。
		if _, _, _, err := grant("alice", "denier"); err != nil {
			return err
		}
		status, dec, _, err := checkPerm("alice", "doc:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "deny" {
			return fmt.Errorf("status=%d dec=%q want deny", status, dec)
		}
		return nil
	})

	// ---- 传递继承合并 ----
	check("传递继承合并权限", func() error {
		// base <- mid <- top
		if _, _, _, err := putRole(role("base", []string{"doc:read"}, nil, nil)); err != nil {
			return err
		}
		if _, _, _, err := putRole(role("mid", []string{"img:read"}, nil, []string{"base"})); err != nil {
			return err
		}
		if _, _, _, err := putRole(role("top", nil, []string{"doc:delete"}, []string{"mid"})); err != nil {
			return err
		}
		if _, _, _, err := grant("carol", "top"); err != nil {
			return err
		}
		for _, p := range []string{"doc:read", "img:read"} {
			status, dec, _, err := checkPerm("carol", p)
			if err != nil {
				return err
			}
			if status != http.StatusOK || dec != "allow" {
				return fmt.Errorf("inherited %s: status=%d dec=%q want allow", p, status, dec)
			}
		}
		status, dec, _, err := checkPerm("carol", "doc:delete")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "deny" {
			return fmt.Errorf("inherited deny: status=%d dec=%q want deny", status, dec)
		}
		return nil
	})

	// ---- 覆盖更新生效 ----
	check("覆盖更新替换旧 allow", func() error {
		// 重新创建 reader 只含 img:write，doc:read 应消失。
		if _, _, _, err := putRole(role("reader", []string{"img:write"}, nil, nil)); err != nil {
			return err
		}
		status, dec, _, err := checkPerm("alice", "doc:read")
		if err != nil {
			return err
		}
		// alice 仍有 denier 的 deny，doc:read 应为 deny。
		if status != http.StatusOK || dec != "deny" {
			return fmt.Errorf("status=%d dec=%q want deny (denier still active)", status, dec)
		}
		status, dec, _, err = checkPerm("alice", "img:write")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "allow" {
			return fmt.Errorf("status=%d dec=%q want allow (new allow)", status, dec)
		}
		return nil
	})

	check("父角色更新后子用户实时反映", func() error {
		// 新建独立角色链避免与其他用例耦合。
		if _, _, _, err := putRole(role("p-upd", []string{"x:read"}, nil, nil)); err != nil {
			return err
		}
		if _, _, _, err := putRole(role("c-upd", nil, nil, []string{"p-upd"})); err != nil {
			return err
		}
		if _, _, _, err := grant("dave", "c-upd"); err != nil {
			return err
		}
		status, dec, _, err := checkPerm("dave", "x:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "allow" {
			return fmt.Errorf("before parent update: status=%d dec=%q want allow", status, dec)
		}
		// 父角色新增 deny。
		if _, _, _, err := putRole(role("p-upd", nil, []string{"x:read"}, nil)); err != nil {
			return err
		}
		status, dec, _, err = checkPerm("dave", "x:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "deny" {
			return fmt.Errorf("after parent deny: status=%d dec=%q want deny", status, dec)
		}
		return nil
	})

	// ---- 循环继承被拒 ----
	check("循环继承被拒且不破坏状态", func() error {
		// x -> y 已存在，令 y -> x 形成环。
		if _, _, _, err := putRole(role("cyc-x", nil, nil, nil)); err != nil {
			return err
		}
		if _, _, _, err := putRole(role("cyc-y", nil, nil, []string{"cyc-x"})); err != nil {
			return err
		}
		status, ok, errStr, err := putRole(role("cyc-y", nil, nil, []string{"cyc-x", "cyc-y"}))
		// 令 y 的 parents 含 y 自身（自引用环）。
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest || ok {
			return fmt.Errorf("self-cycle: status=%d ok=%v want 400/false", status, ok)
		}
		if !strings.Contains(errStr, "循环继承") {
			return fmt.Errorf("error should mention 循环继承, got: %q", errStr)
		}
		// 现有 cyc-y 仍只继承 cyc-x（未被破坏）：授予 dave2 后 cyc-y 无 allow/deny。
		if _, _, _, err := grant("erin", "cyc-y"); err != nil {
			return err
		}
		status, dec, _, err := checkPerm("erin", "doc:read")
		if err != nil {
			return err
		}
		if status != http.StatusOK || dec != "undefined" {
			return fmt.Errorf("state corrupted after rejected put: dec=%q want undefined", dec)
		}
		// 构造 x -> y, y -> x 的二角色环：更新 cyc-x 继承 cyc-y。
		status, ok, errStr, err = putRole(role("cyc-x", nil, nil, []string{"cyc-y"}))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest || ok {
			return fmt.Errorf("two-node cycle: status=%d ok=%v want 400/false", status, ok)
		}
		if !strings.Contains(errStr, "循环继承") {
			return fmt.Errorf("two-node cycle error should mention 循环继承, got: %q", errStr)
		}
		return nil
	})

	// ---- 未知角色引用被拒 ----
	check("未知父角色被拒", func() error {
		status, ok, errStr, err := putRole(role("orphan", nil, nil, []string{"ghost"}))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest || ok {
			return fmt.Errorf("unknown parent: status=%d ok=%v want 400/false", status, ok)
		}
		if !strings.Contains(errStr, "未知角色") {
			return fmt.Errorf("error should mention 未知角色, got: %q", errStr)
		}
		return nil
	})

	check("授予未知角色被拒", func() error {
		status, ok, errStr, err := grant("frank", "nope")
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest || ok {
			return fmt.Errorf("grant unknown role: status=%d ok=%v want 400/false", status, ok)
		}
		if !strings.Contains(errStr, "未知角色") {
			return fmt.Errorf("error should mention 未知角色, got: %q", errStr)
		}
		return nil
	})

	// ---- 格式非法被拒 ----
	check("权限点格式非法被拒", func() error {
		status, ok, errStr, err := putRole(role("badperm", []string{"doc"}, nil, nil))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest || ok {
			return fmt.Errorf("bad perm: status=%d ok=%v want 400/false", status, ok)
		}
		if !strings.Contains(errStr, "权限点格式非法") {
			return fmt.Errorf("error should mention 权限点格式非法, got: %q", errStr)
		}
		return nil
	})

	check("判定时权限点格式非法返回 400", func() error {
		status, dec, errStr, err := checkPerm("alice", "not-a-perm")
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		if dec != "" {
			return fmt.Errorf("decision should be empty on error, got %q", dec)
		}
		if !strings.Contains(errStr, "权限点格式非法") {
			return fmt.Errorf("error should mention 权限点格式非法, got: %q", errStr)
		}
		return nil
	})

	check("空角色 ID 被拒", func() error {
		status, ok, _, err := putRole(role("", []string{"doc:read"}, nil, nil))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest || ok {
			return fmt.Errorf("empty id: status=%d ok=%v want 400/false", status, ok)
		}
		return nil
	})

	// ---- 非法 JSON / 多段 / 未知字段 ----
	check("非法 JSON 被拒(400)", func() error {
		status, _, _, err := putRole("{not json")
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("多段 JSON 被拒(400)", func() error {
		status, _, _, err := putRole(role("a", []string{"doc:read"}, nil, nil) + role("b", []string{"doc:read"}, nil, nil))
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	check("未知字段被拒(400)", func() error {
		body := marshal(map[string]any{"id": "z", "allow": []string{"doc:read"}, "extra": 1})
		status, _, _, err := putRole(body)
		if err != nil {
			return err
		}
		if status != http.StatusBadRequest {
			return fmt.Errorf("status=%d want 400", status)
		}
		return nil
	})

	// ---- 权限清单端点 ----
	check("权限清单去重排序", func() error {
		// dave 拥有 c-upd -> p-upd(x:read deny)。
		status, allow, deny, err := permissions("dave")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d want 200", status)
		}
		if len(allow) != 0 {
			return fmt.Errorf("dave allow=%v want []", allow)
		}
		if len(deny) != 1 || deny[0] != "x:read" {
			return fmt.Errorf("dave deny=%v want [x:read]", deny)
		}
		// 未知用户返回空数组（非 null）。
		status, allow, deny, err = permissions("ghost-user")
		if err != nil {
			return err
		}
		if status != http.StatusOK {
			return fmt.Errorf("status=%d want 200", status)
		}
		if allow == nil || deny == nil {
			return fmt.Errorf("empty lists must be [] not null: allow=%v deny=%v", allow, deny)
		}
		return nil
	})

	// ---- 重复授予幂等 ----
	check("重复授予同一角色幂等", func() error {
		for i := 0; i < 3; i++ {
			status, ok, _, err := grant("alice", "reader")
			if err != nil {
				return err
			}
			if status != http.StatusOK || !ok {
				return fmt.Errorf("idempotent grant #%d: status=%d ok=%v", i, status, ok)
			}
		}
		return nil
	})

	fmt.Printf("\n%d passed, %d failed\n", passed, failed)
	if failed > 0 {
		return 1
	}
	return 0
}
