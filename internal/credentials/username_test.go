package credentials

import "testing"

func TestResolverUsernameDoesNotPromptOrCache(t *testing.T) {
	env := map[string]string{"NETCONFIG_USERNAME": "global-env", "NETCONFIG_LAB_USERNAME": "lab-env"}
	r := &Resolver{
		DotEnv:    map[string]string{"NETCONFIG_CORE_USERNAME": "core-file"},
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Prompter:  &fakePrompter{user: "prompted", pass: "x"},
	}
	cases := map[string]string{
		"core":  "core-file", // .env tier, group specific
		"lab":   "lab-env",   // environment tier, group specific
		"other": "global-env",
	}
	for group, want := range cases {
		if got := r.Username(group); got != want {
			t.Errorf("Username(%q) = %q, want %q", group, got, want)
		}
	}
	if p := r.Prompter.(*fakePrompter); p.userCalls != 0 || p.passCalls != 0 {
		t.Fatalf("Username must never prompt: %+v", p)
	}
	delete(env, "NETCONFIG_USERNAME")
	if got := r.Username("other"); got != "" {
		t.Fatalf("an unconfigured group yields \"\" (the lint then assumes the worst), got %q", got)
	}
	if got := (&Resolver{}).Username("x"); got != "" {
		t.Fatalf("zero Resolver: %q", got)
	}
}
