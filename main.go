package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

type image struct {
	Name string `json:"name"`
	Tag  string `json:"tag"`
}

func main() {
	//
	// syft
	//
	b, err := os.ReadFile("./test/testdata/syft.json")
	if err != nil {
		log.Fatal(err)
	}
	// result := gjson.GetBytes(b, "manifests.@keys.#")
	// results := gjson.GetBytes(b, "@dig:resolved.@keys")
	results := gjson.GetBytes(b, "manifests.@keys")
	// for _, result := range results {
	fmt.Println("CP", results.Array())
	// }

	for _, bla := range results.Array() {
		fmt.Println(bla)
		boo := strings.ReplaceAll(bla.String(), ".", `\.`)
		fmt.Println(boo)
		results := gjson.GetBytes(b, `manifests.`+boo+`.@values`)
		fmt.Println("CP", results.String())
	}
	//
	// syft - end
	//

	//
	// trivy
	//
	b, err = os.ReadFile("./test/testdata/trivy.json")
	if err != nil {
		log.Fatal(err)
	}
	// results = gjson.GetBytes(b, "@dig:Vulnerabilities.#")
	results = gjson.GetBytes(b, "#.Target")
	fmt.Println("CP", results.Array())
	for i, bla := range results.Array() {
		// boo := strings.ReplaceAll(bla.String(), ".", `\.`)
		// fmt.Println(boo)
		// results := gjson.GetBytes(b, `manifests.`+boo+`.@values`)
		// fmt.Println("CP", results.String())
		fmt.Println("->", bla)
		// results = gjson.GetBytes(b, strconv.Itoa(i)+".Target")
		results1 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.VulnerabilityID")

		for i2 := range results1.Array() {
			fmt.Println("VulnerabilityID:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".VulnerabilityID"))
			fmt.Println("installedVersion:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".InstalledVersion"))
			fmt.Println("FixedVersion:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".FixedVersion"))
			fmt.Println("PkgName:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".PkgName"))
			fmt.Println("Severity:", gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities."+strconv.Itoa(i2)+".Severity"))
		}

		// results2 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.InstalledVersion")
		// results3 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.FixedVersion")
		// results4 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.PkgName")
		// results5 := gjson.GetBytes(b, strconv.Itoa(i)+".Vulnerabilities.#.Severity")
		// fmt.Println(results1, results2, results3, results4, results5)
	}
	//
	// trivy end
	//

	//
	//
	//
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	log.SetReportCaller(true)
	fmt.Println(log.GetLevel())
	log.SetLevel(6) // trace

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/", hello)
	e.POST("/", world)

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}

// Handler
func hello(c echo.Context) error {
	return c.String(http.StatusOK, "Hello, World!")
}

// Handler
func world(c echo.Context) error {
	var i image
	if err := c.Bind(&i); err != nil {
		return err
	}
	log.Debugf("image: '%s', tag: '%s'", i.Name, i.Tag)

	args := []string{"run", "python3", "docker_pull.py", i.Name + ":" + i.Tag}
	if err := command("/home/detective/.local/bin/poetry", args); err != nil {
		log.Fatal(err)
	}

	imageDir := strings.ReplaceAll(i.Name, "/", "_")
	imageTar := imageDir + ".tar"
	args = []string{imageTar, "--output", "github-json", "--file", "/tmp/" + imageDir + "-syft.json"}
	if err := command("syft", args); err != nil {
		log.Fatal(err)
	}

	args = []string{"image", "--input", imageTar, "--format", "json", "--output", "/tmp/" + imageDir + "-trivy.json"}
	if err := command("trivy", args); err != nil {
		log.Fatal(err)
	}

	return c.String(http.StatusOK, "Hello, World!")
}

func command(app string, args []string) error {
	cmd := exec.Command(app, args...)
	out, err := cmd.CombinedOutput()
	outString := string(out)
	if err != nil {
		return fmt.Errorf("Error: '%s'", outString)
	}
	fmt.Println(outString)
	return nil
}
