package detective

import (
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

type severities struct {
	Criticals, Highs, Mediums, Lows, Unknowns int
}

// find binaries and docker image in the Trivy report
func ResultTargets(b []byte) ([]string, error) {
	// resultsTargetKey := `Results.#.Target`
	resultsTargetKey := `.Target`
	resultsTargetValues := gjson.GetBytes(b, resultsTargetKey)
	log.Info("====>", string(b))
	if !resultsTargetValues.Exists() {
		// return nil, fmt.Errorf("key: '%s' does not exist in JSON: '%s'", resultsTargetKey, string(b))
		return nil, fmt.Errorf("key: '%s' does not exist in JSON", resultsTargetKey)
	}
	log.Debugf("resultsTargetValues: '%s':", resultsTargetValues)
	resultsTargetStringValues := []string{}
	for _, resultsTargetValue := range resultsTargetValues.Array() {
		resultsTargetStringValues = append(resultsTargetStringValues, resultsTargetValue.String())
	}

	return resultsTargetStringValues, nil
}

func Trivy() severities {
	//
	// trivy
	//
	// b, err := os.ReadFile("../../../test/testdata/trivy.json")
	// b, err := os.ReadFile("./test/testdata/trivy.json")
	b, err := os.ReadFile("../../test/testdata/trivy/bla.json")
	if err != nil {
		log.Fatal(err)
	}

	value2 := gjson.GetBytes(b, `Results.#.Target`)
	value2.Exists()
	log.Info(value2)

	value42 := gjson.GetBytes(b, `Results.#(Target=="usr/local/bin/n3dr").Vulnerabilities.#.Severity`)
	value42.Exists()
	log.Info(value42)

	value3 := gjson.GetBytes(b, `Results.#.Vulnerabilities.#.Severity`)
	// value3.Exists()
	log.Info("===================>", value3)

	// value4 := gjson.GetBytes(b, `..#(Severity="HIGH")`)
	value4 := gjson.GetBytes(b, `..#`)
	// value3.Exists()
	log.Info("===================>", value4)

	// results := gjson.GetBytes(b, "@dig:Vulnerabilities.#.Severity")
	// results := gjson.GetBytes(b, "@dig:Vulnerabilities.#(Severity==\"CRITICAL\")")

	// value := gjson.GetBytes(b, "@dig:Vulnerabilities.#.Severity")
	value := gjson.GetBytes(b, `@dig:Vulnerabilities.#.Severity`)
	value.Exists()
	boo := ""
	crit := 0
	high := 0
	medium := 0
	low := 0
	unknown := 0
	for _, bla := range value.Array() {
		log.Info("----->", bla)
		for _, bla2 := range bla.Array() {
			boo = bla2.String()

			switch boo {
			case "CRITICAL":
				crit++
			case "HIGH":
				high++
			case "MEDIUM":
				medium++
			case "LOW":
				low++
			case "UNKNOWN":
				unknown++
			default:
				// // freebsd, openbsd,
				// // plan9, windows...
				// fmt.Printf("%s.\n", os)
			}
		}
	}

	s := severities{Criticals: crit, Highs: high, Mediums: medium, Lows: low, Unknowns: unknown}
	log.Info(s)

	// results := gjson.GetBytes(b, "..#(Severity=\"CRITICAL\")")

	// results := gjson.GetBytes(b, "#.Target")

	// fmt.Println("CP", results.Array())
	// for i, bla := range results.Array() {
	// 	// boo := strings.ReplaceAll(bla.String(), ".", `\.`)
	// 	// fmt.Println(boo)
	// 	// results := gjson.GetBytes(b, `manifests.`+boo+`.@values`)
	// 	// fmt.Println("CP", results.String())
	// 	fmt.Println("->", bla)
	// 	// results = gjson.GetBytes(b, strconv.Itoa(i)+".Target")
	// 	results1 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.VulnerabilityID")

	// 	for i2 := range results1.Array() {
	// 		fmt.Println("VulnerabilityID:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".VulnerabilityID"))
	// 		fmt.Println("installedVersion:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".InstalledVersion"))
	// 		fmt.Println("FixedVersion:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".FixedVersion"))
	// 		fmt.Println("PkgName:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".PkgName"))
	// 		fmt.Println("Severity:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".Severity"))
	// 	}

	// 	// results2 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.InstalledVersion")
	// 	// results3 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.FixedVersion")
	// 	// results4 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.PkgName")
	// 	// results5 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.Severity")
	// 	// fmt.Println(results1, results2, results3, results4, results5)
	// }
	//
	// trivy end
	//
	return s
}
