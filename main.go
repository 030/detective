package main

import "github.com/030/detective/internal/app/detective"

func main() {
	detective.Trivy()
}

// type image struct {
// 	Name string `json:"name"`
// 	Tag  string `json:"tag"`
// }

// func main() {
// 	//
// 	// syft
// 	//
// 	b, err := os.ReadFile("./test/testdata/syft.json")
// 	if err != nil {
// 		log.Fatal(err)
// 	}
// 	// result := gjson.GetBytes(b, "manifests.@keys.#")
// 	// results := gjson.GetBytes(b, "@dig:resolved.@keys")
// 	results := gjson.GetBytes(b, "manifests.@keys")
// 	// for _, result := range results {
// 	fmt.Println("CP", results.Array())
// 	// }

// 	for _, bla := range results.Array() {
// 		fmt.Println(bla)
// 		boo := strings.ReplaceAll(bla.String(), ".", `\.`)
// 		fmt.Println(boo)
// 		results := gjson.GetBytes(b, `manifests.`+boo+`.@values`)
// 		fmt.Println("CP", results.String())
// 	}
// 	//
// 	// syft - end
// 	//

// 	//
// 	//
// 	//
// 	log.SetFormatter(&log.TextFormatter{
// 		DisableColors: true,
// 		FullTimestamp: true,
// 	})
// 	log.SetReportCaller(true)
// 	fmt.Println(log.GetLevel())
// 	log.SetLevel(6) // trace

// 	// Echo instance
// 	e := echo.New()

// 	// Middleware
// 	e.Use(middleware.Logger())
// 	e.Use(middleware.Recover())

// 	// Routes
// 	e.GET("/", hello)
// 	e.POST("/", world)

// 	// Start server
// 	e.Logger.Fatal(e.Start(":1323"))
// }

// // Handler
// func hello(c echo.Context) error {
// 	return c.String(http.StatusOK, "Hello, World!")
// }

// // Handler
// func world(c echo.Context) error {
// 	var i image
// 	if err := c.Bind(&i); err != nil {
// 		return err
// 	}
// 	log.Debugf("image: '%s', tag: '%s'", i.Name, i.Tag)

// 	args := []string{"run", "python3", "docker_pull.py", i.Name + ":" + i.Tag}
// 	if err := command("/home/detective/.local/bin/poetry", args); err != nil {
// 		log.Fatal(err)
// 	}

// 	imageDir := strings.ReplaceAll(i.Name, "/", "_")
// 	imageTar := imageDir + ".tar"
// 	args = []string{imageTar, "--output", "github-json", "--file", "/tmp/" + imageDir + "-syft.json"}
// 	if err := command("syft", args); err != nil {
// 		log.Fatal(err)
// 	}

// 	args = []string{"image", "--input", imageTar, "--format", "json", "--output", "/tmp/" + imageDir + "-trivy.json"}
// 	if err := command("trivy", args); err != nil {
// 		log.Fatal(err)
// 	}

// 	return c.String(http.StatusOK, "Hello, World!")
// }

// func command(app string, args []string) error {
// 	cmd := exec.Command(app, args...)
// 	out, err := cmd.CombinedOutput()
// 	outString := string(out)
// 	if err != nil {
// 		return fmt.Errorf("Error: '%s'", outString)
// 	}
// 	fmt.Println(outString)
// 	return nil
// }
