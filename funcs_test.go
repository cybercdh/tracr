package main

import "testing"

func TestHasAtLeastTwoDots(t *testing.T) {
	cases := map[string]bool{
		"example.com":       true,
		"sub.example.com":   true,
		"example.com.":      true, // trailing dot ignored -> one dot
		"com":               false,
		"com.":              false,
		"a.b.c.example.com": true,
		"":                  false,
	}
	for in, want := range cases {
		if got := hasAtLeastTwoDots(in); got != want {
			t.Errorf("hasAtLeastTwoDots(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestMarkSeen(t *testing.T) {
	c := Container{seen: make(map[string]bool)}
	if !c.markSeen("example.com") {
		t.Fatal("first markSeen should be new")
	}
	if c.markSeen("example.com") {
		t.Fatal("second markSeen should report already seen")
	}
}
