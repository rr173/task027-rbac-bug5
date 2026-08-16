// Package rbac 实现基于角色的访问控制权限规则求值引擎。
//
// 维护角色定义与用户-角色授权关系，支持角色多继承（parents）、
// 权限点授权（allow）与显式拒绝（deny），求值时采用拒绝优先（deny-overrides）策略。
// 所有方法并发安全。
package rbac

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Decision 是权限判定的结果。
type Decision string

const (
	// Allow 表示用户可达的某角色授权了该权限点，且无任何角色拒绝它。
	Allow Decision = "allow"
	// Deny 表示用户可达的任意角色显式拒绝了该权限点。
	Deny Decision = "deny"
	// Undefined 表示用户可达的所有角色既未授权也未拒绝该权限点。
	Undefined Decision = "undefined"
)

// Role 是一份角色定义。创建或更新时若 ID 已存在则整体覆盖。
type Role struct {
	ID      string   `json:"id"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
	Parents []string `json:"parents"`
}

// permRe 校验权限点格式：资源:动作，二者均为非空、仅含小写字母/数字/连字符且以字母开头。
var permRe = regexp.MustCompile(`^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$`)

// idRe 校验角色 ID：非空、仅含字母/数字/下划线/连字符。
var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ValidPerm 报告权限点是否符合「资源:动作」格式。
func ValidPerm(p string) bool { return permRe.MatchString(p) }

// Store 持有全部角色定义与用户-角色授权关系。
type Store struct {
	mu    sync.RWMutex
	roles map[string]*Role          // roleID -> role
	users map[string]map[string]struct{} // user -> set of roleID
}

// New 创建一个空的权限存储。
func New() *Store {
	return &Store{
		roles: make(map[string]*Role),
		users: make(map[string]map[string]struct{}),
	}
}

// PutRole 创建或更新角色定义。
// 校验顺序：ID 非空且合法 → 权限点格式 → 父角色存在性 → 循环继承。
// 任一校验失败都返回错误且不修改任何已有状态。
func (s *Store) PutRole(r Role) error {
	if r.ID == "" {
		return fmt.Errorf("角色 ID 不能为空")
	}
	if !idRe.MatchString(r.ID) {
		return fmt.Errorf("角色 ID 格式非法: %q", r.ID)
	}
	for _, p := range r.Allow {
		if !ValidPerm(p) {
			return fmt.Errorf("权限点格式非法: %q", p)
		}
	}
	for _, p := range r.Deny {
		if !ValidPerm(p) {
			return fmt.Errorf("权限点格式非法: %q", p)
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 去重 parents，并保留输入顺序。
	seen := make(map[string]bool, len(r.Parents))
	parents := make([]string, 0, len(r.Parents))
	for _, p := range r.Parents {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		parents = append(parents, p)
	}
	// 父角色必须已存在（自引用留待循环检测处理）。
	for _, p := range parents {
		if p == r.ID {
			continue
		}
		if _, ok := s.roles[p]; !ok {
			return fmt.Errorf("未知角色: %q", p)
		}
	}

	// 循环继承检测：以新 parents 构造临时图，检查 r.ID 是否能经 parents 闭包回到自身。
	if cycle := s.detectCycle(r.ID, parents); cycle != "" {
		return fmt.Errorf("检测到循环继承: %s", cycle)
	}

	// 提交：拷贝切片避免外部修改。
	cp := Role{ID: r.ID, Parents: parents}
	cp.Allow = append([]string(nil), r.Allow...)
	cp.Deny = append([]string(nil), r.Deny...)
	s.roles[r.ID] = &cp
	return nil
}

// detectCycle 在「现有角色 + 待写入角色的新 parents」构成的临时图上，
// 从 id 出发沿 parents 边做 DFS，返回首个能回到 id 的环路径（如 "a -> b -> a"），
// 无环返回空串。仅当现有角色图已是无环时（由 PutRole 不变量保证），
// 新增环必然经过 id，故从 id 出发即可覆盖。
func (s *Store) detectCycle(id string, newParents []string) string {
	adj := make(map[string][]string, len(s.roles)+1)
	for rid, r := range s.roles {
		if rid == id {
			continue
		}
		adj[rid] = r.Parents
	}
	adj[id] = newParents

	path := []string{id}
	visited := map[string]bool{id: true}
	var dfs func(node string) string
	dfs = func(node string) string {
		for _, p := range adj[node] {
			if p == id {
				return strings.Join(append(path, id), " -> ")
			}
			if visited[p] {
				continue
			}
			visited[p] = true
			path = append(path, p)
			if got := dfs(p); got != "" {
				return got
			}
			path = path[:len(path)-1]
		}
		return ""
	}
	return dfs(id)
}

// GrantRole 给用户授予一个角色，重复授予同一角色幂等。
// 角色必须已存在，否则返回错误且不写入。
func (s *Store) GrantRole(user, roleID string) error {
	if user == "" {
		return fmt.Errorf("用户名不能为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.roles[roleID]; !ok {
		return fmt.Errorf("未知角色: %q", roleID)
	}
	set, ok := s.users[user]
	if !ok {
		set = make(map[string]struct{})
		s.users[user] = set
	}
	set[roleID] = struct{}{}
	return nil
}

// reachableRoles 返回从用户已授予角色出发、沿 parents 传递闭包展开的全部角色 ID。
func (s *Store) reachableRoles(user string) map[string]*Role {
	out := make(map[string]*Role)
	granted := s.users[user]
	var visit func(string)
	visit = func(rid string) {
		if _, done := out[rid]; done {
			return
		}
		r, ok := s.roles[rid]
		if !ok {
			return // 悬空引用，忽略（不应发生）
		}
		out[rid] = r
		for _, p := range r.Parents {
			visit(p)
		}
	}
	for rid := range granted {
		visit(rid)
	}
	return out
}

// Check 对给定用户与权限点求值，返回 allow/deny/undefined。
// 权限点格式非法返回错误。用户不存在或无角色返回 undefined。
// 求值实时读取当前角色定义，不缓存。
func (s *Store) Check(user, permission string) (Decision, error) {
	if !ValidPerm(permission) {
		return Undefined, fmt.Errorf("权限点格式非法: %q", permission)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	allowSet := make(map[string]bool)
	denySet := make(map[string]bool)
	for _, r := range s.reachableRoles(user) {
		for _, p := range r.Allow {
			allowSet[p] = true
		}
		for _, p := range r.Deny {
			denySet[p] = true
		}
	}
	// 拒绝优先。
	if denySet[permission] {
		return Deny, nil
	}
	if allowSet[permission] {
		return Allow, nil
	}
	return Undefined, nil
}

// EffectivePermissions 返回用户全部可达权限点的 allow 与 deny 清单（去重并按字典序排序）。
func (s *Store) EffectivePermissions(user string) (allow, deny []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allowSet := make(map[string]bool)
	denySet := make(map[string]bool)
	for _, r := range s.reachableRoles(user) {
		for _, p := range r.Allow {
			allowSet[p] = true
		}
		for _, p := range r.Deny {
			denySet[p] = true
		}
	}
	allow = sortedKeys(allowSet)
	deny = sortedKeys(denySet)
	return allow, deny
}

// HasRole 报告角色 ID 是否已存在（仅用于自检与诊断）。
func (s *Store) HasRole(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.roles[id]
	return ok
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
