package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"hyperdrop/server/internal/metadb"
)

func TestAPublishConflictAnswersItsPathsUnderConflicts(t *testing.T) {
	w := httptest.NewRecorder()
	writeRefusal(w, &metadb.ErrPublishConflict{Conflicts: []string{"a.txt", "b/c.txt"}})
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d", w.Code)
	}
	var got struct {
		Code      string   `json:"code"`
		Conflicts []string `json:"conflicts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Code != "publish-conflict" || !reflect.DeepEqual(got.Conflicts, []string{"a.txt", "b/c.txt"}) {
		t.Fatalf("body = %s", w.Body)
	}
}
