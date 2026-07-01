package ports

import (
	"reflect"
	"testing"
)

func TestParseListSingleAndMixed(t *testing.T) {
	got, err := ParseList("22,80,443")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 443}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseListHyphenRange(t *testing.T) {
	got, err := ParseList("80-83")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{80, 81, 82, 83}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseListUnderscoreRange(t *testing.T) {
	got, err := ParseList("2000_2002")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{2000, 2001, 2002}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseListMixedRange(t *testing.T) {
	got, err := ParseList("22,80-82,8080")
	if err != nil {
		t.Fatal(err)
	}
	want := []uint16{22, 80, 81, 82, 8080}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseListInvalidRange(t *testing.T) {
	_, err := ParseList("443-80")
	if err == nil {
		t.Fatal("expected error for reversed range")
	}
}

func TestParseListEmpty(t *testing.T) {
	got, err := ParseList("  ")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}

func TestFormatList(t *testing.T) {
	if got := FormatList([]uint16{22, 80, 443}); got != "22,80,443" {
		t.Fatalf("FormatList() = %q", got)
	}
}
