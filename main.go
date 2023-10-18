package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	log "github.com/sirupsen/logrus"
)

var tmpl = `
{{- $critical := 0 }}
{{- $high := 0 }}
{{- $medium := 0 }}
{{- $low := 0 }}
{{- $unknown := 0 }}
{{- range . }}
	{{- range .Vulnerabilities }}
		{{- if  eq .Severity "CRITICAL" }}
			{{- $critical = add $critical 1 }}
		{{- end }}
		{{- if  eq .Severity "HIGH" }}
			{{- $high = add $high 1 }}
		{{- end }}
		{{- if  eq .Severity "MEDIUM" }}
			{{- $medium = add $medium 1 }}
		{{- end }}
		{{- if  eq .Severity "LOW" }}
			{{- $low = add $low 1 }}
		{{- end }}
		{{- if  eq .Severity "UNKNOWN" }}
			{{- $unknown = add $unknown 1 }}
		{{- end }}		
	{{- end }}
{{- end }}

c:{{ $critical }},h:{{ $high }},m:{{ $medium }},l:{{ $low }},u:{{ $unknown }}
`

type image struct {
	Name string `json:"name" validate:"required"`
	Tag  string `json:"tag" validate:"required"`
}

type report struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

func main() {
	logging()

	// Echo instance
	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())

	// Routes
	e.GET("/api/v1/scan/results", results)
	e.POST("/api/v1/scan/metrics", metrics)

	// Start server
	e.Logger.Fatal(e.Start(":1323"))
}

// Handler
func results(c echo.Context) error {
	name := c.QueryParam("name")
	tag := c.QueryParam("tag")
	if name == "" || tag == "" {
		return fmt.Errorf("neither name, nor tag should be empty")
	}

	args := []string{"image", name + ":" + tag, "--format", "template", "--template", tmpl}
	out, err := command("trivy", args)
	if err != nil {
		log.Error(err)
		return err
	}
	i := image{Name: name, Tag: tag}
	report, err := i.generator(out)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("Report for image: '%s' with tag: '%s': '%v'", i.Name, i.Tag, report)

	b, err := json.Marshal(report)
	if err != nil {
		log.Error(err)
		return err
	}

	if !json.Valid(b) {
		err := fmt.Errorf("report json is invalid")
		log.Error(err)
		return err
	}

	return c.String(http.StatusOK, string(b))
}

// Handler
func metrics(c echo.Context) error {
	var i image
	if err := c.Bind(&i); err != nil {
		return err
	}
	if err := validator.New().Struct(i); err != nil {
		return err
	}
	log.Infof("image: '%s', tag: '%s'", i.Name, i.Tag)

	args := []string{"image", i.Name + ":" + i.Tag, "--format", "template", "--template", tmpl}
	out, err := command("trivy", args)
	if err != nil {
		log.Error(err)
		return err
	}
	report, err := i.generator(out)
	if err != nil {
		log.Error(err)
		return err
	}
	log.Infof("Report for image: '%s' with tag: '%s': '%v'", i.Name, i.Tag, report)

	report.metrics()

	return c.String(http.StatusOK, "image: '"+i.Name+"' with tag: '"+i.Tag+"' has been scanned and metrics have been sent")
}

func logging() {
	log.SetFormatter(&log.TextFormatter{
		DisableColors: true,
		FullTimestamp: true,
	})
	log.SetReportCaller(true)
}

func (i *image) generator(input []byte) (report, error) {
	re := regexp.MustCompile(`c:(?P<Critical>\d+),h:(?P<High>\d+),m:(?P<Medium>\d+),l:(?P<Low>\d+),u:(?P<Unknown>\d+)`)
	if !re.Match(input) {
		return report{}, fmt.Errorf("input: '%s' does not match regex", input)
	}

	matches := re.FindSubmatch(input)
	criticalIndex := re.SubexpIndex("Critical")
	highIndex := re.SubexpIndex("High")
	mediumIndex := re.SubexpIndex("Medium")
	lowIndex := re.SubexpIndex("Low")
	unknownIndex := re.SubexpIndex("Unknown")
	criticalString := string(matches[criticalIndex])
	highString := string(matches[highIndex])
	mediumString := string(matches[mediumIndex])
	lowString := string(matches[lowIndex])
	unknownString := string(matches[unknownIndex])

	critical, err := strconv.Atoi(criticalString)
	if err != nil {
		return report{}, err
	}
	high, err := strconv.Atoi(highString)
	if err != nil {
		return report{}, err
	}
	medium, err := strconv.Atoi(mediumString)
	if err != nil {
		return report{}, err
	}
	low, err := strconv.Atoi(lowString)
	if err != nil {
		return report{}, err
	}
	unknown, err := strconv.Atoi(unknownString)
	if err != nil {
		return report{}, err
	}
	r := report{critical, high, medium, low, unknown}

	return r, nil
}

func (r *report) metrics() {
	metricCustomer1 := "detective.company.customer1.critical{image:nginx,tag:1.25.3,team:someteam1,cluster:xyz} = " + strconv.Itoa(r.Critical)
	log.Info(metricCustomer1)
	metricCustomer2 := "detective.company.customer2.unknown{image:nginx,tag:1.25.3,team:someteam2,cluster:xyz} = " + strconv.Itoa(r.Unknown)
	log.Info(metricCustomer2)
	metricCustomer3 := "detective.company.customer3.medium{image:nginx,tag:1.25.3,team:someteam3,cluster:xyz} = " + strconv.Itoa(r.Medium)
	log.Info(metricCustomer3)
	metricCustomer4 := "detective.company.customer4.low{image:nginx,tag:1.25.3,team:someteam2,cluster:xyz} = " + strconv.Itoa(r.Low)
	log.Info(metricCustomer4)
	metricCustomer5 := "detective.company.customer5.high{image:nginx,tag:1.25.3,team:someteam3,cluster:xyz} = " + strconv.Itoa(r.High)
	log.Info(metricCustomer5)
}

func command(app string, args []string) ([]byte, error) {
	cmd := exec.Command(app, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("Error: '%s'", string(out))
	}

	return out, nil
}
