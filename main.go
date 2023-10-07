package main

import (
	"fmt"
	"net/http"
	"os/exec"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

func main() {
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

type (
	b struct {
		Image string `json:"image"`
		Tag   string `json:"tag"`
	}
)

// Handler
func world(c echo.Context) error {
	var book b
	if err := c.Bind(&book); err != nil {
		return err
	}
	fmt.Println(book.Image)
	fmt.Println(book.Tag)

	cmd := exec.Command("/root/.local/bin/poetry", "run", "python3", "docker_pull.py", book.Image+":"+book.Tag)
	stdout, err := cmd.Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(stdout))

	str := strings.ReplaceAll(book.Image, "/", "_")
	fmt.Println(str)
	cmd2 := exec.Command("/blabla/syft", str+".tar")
	stdout2, err := cmd2.Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(stdout2))

	cmd3 := exec.Command("trivy", "image", "--input", str+".tar")
	stdout3, err := cmd3.Output()
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(stdout3))

	return c.String(http.StatusOK, "Hello, World!")
}
