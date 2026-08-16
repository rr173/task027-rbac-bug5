package rbac

import (
	"strings"
	"testing"
)

// TestPutRoleBasic 覆盖角色创建与覆盖更新。
func TestPutRoleBasic(t *testing.T) {
	s := New()
	if err := s.PutRole(Role{ID: "admin", Allow: []string{"doc:read", "doc:write"}}); err != nil {
		t.Fatalf("put admin: %v", err)
	}
	if !s.HasRole("admin") {
		t.Fatal("admin should exist")
	}
	// 覆盖更新：旧 allow 完全替换。
	if err := s.PutRole(Role{ID: "admin", Allow: []string{"img:read"}}); err != nil {
		t.Fatalf("overwrite admin: %v", err)
	}
	d, err := s.Check("u", "doc:read")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if d != Undefined {
		t.Errorf("after overwrite doc:read should be undefined, got %s", d)
	}
	d, _ = s.Check("u", "img:read")
	if d != Undefined {
		t.Errorf("ungranted user should be undefined, got %s", d)
	}
}

// TestPermissionFormat 校验权限点格式约束。
func TestPermissionFormat(t *testing.T) {
	s := New()
	bad := []string{"doc", ":read", "doc:", "DOC:read", "doc: read", "doc:read ", "1doc:read", "doc:_read"}
	for _, p := range bad {
		err := s.PutRole(Role{ID: "r", Allow: []string{p}})
		if err == nil {
			t.Errorf("perm %q should be rejected", p)
		} else if !strings.Contains(err.Error(), "权限点格式非法") {
			t.Errorf("perm %q wrong error: %v", p, err)
		}
	}
	if s.HasRole("r") {
		t.Fatal("rejected role must not be stored")
	}
	// 合法格式。
	if err := s.PutRole(Role{ID: "r", Allow: []string{"doc-1:read", "img-2:write"}}); err != nil {
		t.Fatalf("valid perms rejected: %v", err)
	}
}

// TestUnknownParent 校验父角色必须存在。
func TestUnknownParent(t *testing.T) {
	s := New()
	if err := s.PutRole(Role{ID: "child", Parents: []string{"ghost"}}); err == nil {
		t.Fatal("unknown parent should be rejected")
	}
	if s.HasRole("child") {
		t.Fatal("rejected role must not be stored")
	}
	if err := s.PutRole(Role{ID: "parent", Allow: []string{"doc:read"}}); err != nil {
		t.Fatalf("create parent: %v", err)
	}
	if err := s.PutRole(Role{ID: "child", Parents: []string{"parent"}}); err != nil {
		t.Fatalf("create child with existing parent: %v", err)
	}
}

// TestCycleDetection 校验循环继承被拒且不破坏现有图。
func TestCycleDetection(t *testing.T) {
	s := New()
	mustPut := func(r Role) {
		t.Helper()
		if err := s.PutRole(r); err != nil {
			t.Fatalf("put %s: %v", r.ID, err)
		}
	}
	mustPut(Role{ID: "a", Parents: []string{}})
	mustPut(Role{ID: "b", Parents: []string{"a"}})
	// b -> a，现令 a -> b，形成 a -> b -> a 环。
	err := s.PutRole(Role{ID: "a", Parents: []string{"b"}})
	if err == nil {
		t.Fatal("cycle a->b->a should be rejected")
	}
	if !strings.Contains(err.Error(), "循环继承") {
		t.Errorf("wrong error: %v", err)
	}
	// 现有 a 仍应无 parents（未被破坏）。
	d, _ := s.Check("u", "doc:read")
	if d != Undefined {
		t.Errorf("state should be unchanged, got %s", d)
	}
	// 自引用也是环。
	if err := s.PutRole(Role{ID: "c", Parents: []string{"c"}}); err == nil {
		t.Fatal("self-cycle should be rejected")
	}
}

// TestDenyOverrides 校验拒绝优先于授权。
func TestDenyOverrides(t *testing.T) {
	s := New()
	mustPut := func(r Role) {
		t.Helper()
		if err := s.PutRole(r); err != nil {
			t.Fatalf("put %s: %v", r.ID, err)
		}
	}
	mustPut(Role{ID: "allower", Allow: []string{"doc:read"}})
	mustPut(Role{ID: "denier", Deny: []string{"doc:read"}})
	mustGrant := func(u, r string) {
		t.Helper()
		if err := s.GrantRole(u, r); err != nil {
			t.Fatalf("grant %s=%s: %v", u, r, err)
		}
	}
	mustGrant("u1", "allower")
	mustGrant("u1", "denier")

	d, _ := s.Check("u1", "doc:read")
	if d != Deny {
		t.Errorf("deny-overrides: want deny, got %s", d)
	}
	// 仅授权用户。
	mustGrant("u2", "allower")
	d, _ = s.Check("u2", "doc:read")
	if d != Allow {
		t.Errorf("plain allow: want allow, got %s", d)
	}
	// 既未授权也未拒绝。
	d, _ = s.Check("u2", "doc:write")
	if d != Undefined {
		t.Errorf("missing perm: want undefined, got %s", d)
	}
}

// TestInheritance 校验多级继承的权限合并。
func TestInheritance(t *testing.T) {
	s := New()
	mustPut := func(r Role) {
		t.Helper()
		if err := s.PutRole(r); err != nil {
			t.Fatalf("put %s: %v", r.ID, err)
		}
	}
	// grandparent -> parent -> child（child 继承 parent，parent 继承 grandparent）。
	mustPut(Role{ID: "grandparent", Allow: []string{"doc:read"}})
	mustPut(Role{ID: "parent", Parents: []string{"grandparent"}, Allow: []string{"img:read"}})
	mustPut(Role{ID: "child", Parents: []string{"parent"}, Deny: []string{"doc:delete"}})
	if err := s.GrantRole("u", "child"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	for _, p := range []string{"doc:read", "img:read"} {
		d, _ := s.Check("u", p)
		if d != Allow {
			t.Errorf("inherited %s: want allow, got %s", p, d)
		}
	}
	d, _ := s.Check("u", "doc:delete")
	if d != Deny {
		t.Errorf("inherited deny: want deny, got %s", d)
	}
}

// TestParentUpdateReflects 校验父角色更新后子用户判定实时反映。
func TestParentUpdateReflects(t *testing.T) {
	s := New()
	if err := s.PutRole(Role{ID: "base", Allow: []string{"doc:read"}}); err != nil {
		t.Fatalf("put base: %v", err)
	}
	if err := s.PutRole(Role{ID: "derived", Parents: []string{"base"}}); err != nil {
		t.Fatalf("put derived: %v", err)
	}
	if err := s.GrantRole("u", "derived"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	d, _ := s.Check("u", "doc:read")
	if d != Allow {
		t.Fatalf("before update: want allow, got %s", d)
	}
	// 更新 base 新增 deny。
	if err := s.PutRole(Role{ID: "base", Deny: []string{"doc:read"}}); err != nil {
		t.Fatalf("update base: %v", err)
	}
	d, _ = s.Check("u", "doc:read")
	if d != Deny {
		t.Errorf("after parent deny: want deny, got %s", d)
	}
}

// TestGrantIdempotent 校验重复授予同一角色幂等。
func TestGrantIdempotent(t *testing.T) {
	s := New()
	if err := s.PutRole(Role{ID: "r", Allow: []string{"doc:read"}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.GrantRole("u", "r"); err != nil {
			t.Fatalf("grant #%d: %v", i, err)
		}
	}
	allow, deny := s.EffectivePermissions("u")
	if len(allow) != 1 || allow[0] != "doc:read" {
		t.Errorf("allow=%v want [doc:read]", allow)
	}
	if len(deny) != 0 {
		t.Errorf("deny=%v want []", deny)
	}
}

// TestEffectivePermissionsSorted 校验清单去重与排序。
func TestEffectivePermissionsSorted(t *testing.T) {
	s := New()
	if err := s.PutRole(Role{ID: "r", Allow: []string{"z:z", "a:a", "a:a", "m:m"}, Deny: []string{"b:b", "b:b"}}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := s.GrantRole("u", "r"); err != nil {
		t.Fatalf("grant: %v", err)
	}
	allow, deny := s.EffectivePermissions("u")
	if got, want := join(allow), "a:a m:m z:z"; got != want {
		t.Errorf("allow=%q want %q", got, want)
	}
	if got, want := join(deny), "b:b"; got != want {
		t.Errorf("deny=%q want %q", got, want)
	}
}

func join(ss []string) string {
	return strings.Join(ss, " ")
}
