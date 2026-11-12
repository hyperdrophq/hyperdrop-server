package sharefs

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestAddRangeMergesOverlapsAndTouchingRanges(t *testing.T) {
	for _, tc := range []struct {
		name string
		have []Range
		add  Range
		want []Range
	}{
		{"into nothing", nil, Range{5, 10}, []Range{{5, 10}}},
		{"before", []Range{{20, 30}}, Range{0, 10}, []Range{{0, 10}, {20, 30}}},
		{"after", []Range{{0, 10}}, Range{20, 30}, []Range{{0, 10}, {20, 30}}},
		{"touching on the left", []Range{{10, 20}}, Range{0, 10}, []Range{{0, 20}}},
		{"touching on the right", []Range{{0, 10}}, Range{10, 20}, []Range{{0, 20}}},
		{"bridging two", []Range{{0, 10}, {20, 30}}, Range{5, 25}, []Range{{0, 30}}},
		{"inside one", []Range{{0, 30}}, Range{5, 6}, []Range{{0, 30}}},
		{"empty adds nothing", []Range{{0, 10}}, Range{4, 4}, []Range{{0, 10}}},
	} {
		if got := addRange(tc.have, tc.add); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: addRange(%v, %v) = %v, want %v", tc.name, tc.have, tc.add, got, tc.want)
		}
	}
}

func TestMissingRangesIsTheComplement(t *testing.T) {
	for _, tc := range []struct {
		have  []Range
		total int64
		want  []Range
	}{
		{nil, 10, []Range{{0, 10}}},
		{[]Range{{0, 10}}, 10, []Range{}},
		{[]Range{{2, 4}, {6, 8}}, 10, []Range{{0, 2}, {4, 6}, {8, 10}}},
		{[]Range{{0, 4}}, 10, []Range{{4, 10}}},
	} {
		if got := missingRanges(tc.have, tc.total); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("missingRanges(%v, %d) = %v, want %v", tc.have, tc.total, got, tc.want)
		}
	}
}

func TestARangeIsAPairOnTheWire(t *testing.T) {
	b, err := json.Marshal([]Range{{0, 5}, {9, 12}})
	if err != nil || string(b) != "[[0,5],[9,12]]" {
		t.Fatalf("marshal = %s %v", b, err)
	}
	var back []Range
	if err := json.Unmarshal(b, &back); err != nil || !reflect.DeepEqual(back, []Range{{0, 5}, {9, 12}}) {
		t.Fatalf("unmarshal = %v %v", back, err)
	}
}
