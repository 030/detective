package detective

import (
	"os"
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestBli(t *testing.T) {
	b, err := os.ReadFile("../../../test/testdata/trivy/trivy.json")
	if err != nil {
		log.Fatal(err)
	}
	// assert equality
	// a := gjson.Result{Str: "utrecht/n3dr:6.2.0 (alpine 3.15.0)"}

	expectedSlice := []string{"utrecht/n3dr:6.2.0 (alpine 3.15.0)", "usr/local/bin/n3dr"}
	actualSlice, _ := ResultTargets(b)
	assert.ElementsMatch(t, actualSlice, expectedSlice)

	// // assert inequality
	// assert.NotEqual(t, 123, 456, "they should not be equal")

	// // assert for nil (good for errors)
	// assert.Nil(t, object)

	// // assert for not nil (good when you expect something)
	// if assert.NotNil(t, object) {
	// 	// now we know that object isn't nil, we are safe to make
	// 	// further assertions without causing any errors
	// 	assert.Equal(t, "Something", object.Value)
	// }
}

func TestBliErr(t *testing.T) {
	b, err := os.ReadFile("../../../test/testdata/trivy/blaErr.json")
	if err != nil {
		t.Error(err)
	}
	// assert equality
	// a := gjson.Result{Str: "utrecht/n3dr:6.2.0 (alpine 3.15.0)"}

	expectedError := "key: 'Results.#.Target' does not exist in JSON"
	_, actualError := ResultTargets(b)
	assert.EqualError(t, actualError, expectedError)

	// // assert inequality
	// assert.NotEqual(t, 123, 456, "they should not be equal")

	// // assert for nil (good for errors)
	// assert.Nil(t, object)

	// // assert for not nil (good when you expect something)
	// if assert.NotNil(t, object) {
	// 	// now we know that object isn't nil, we are safe to make
	// 	// further assertions without causing any errors
	// 	assert.Equal(t, "Something", object.Value)
	// }
}

// func TestTrivy(t *testing.T) {
// 	// assert equality
// 	assert.Equal(t, "boo", Trivy())

// 	// // assert inequality
// 	// assert.NotEqual(t, 123, 456, "they should not be equal")

// 	// // assert for nil (good for errors)
// 	// assert.Nil(t, object)

// 	// // assert for not nil (good when you expect something)
// 	// if assert.NotNil(t, object) {
// 	// 	// now we know that object isn't nil, we are safe to make
// 	// 	// further assertions without causing any errors
// 	// 	assert.Equal(t, "Something", object.Value)
// 	// }
// }
