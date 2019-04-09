package main

import (
  "flag"
  "net/http"
  "fmt"
  "os"
  "github.com/prometheus/client_golang/prometheus"
  "github.com/prometheus/client_golang/prometheus/promhttp"
  "github.com/prometheus/common/log"
  "time"
  "strings"
  "regexp"
//  "io/ioutil"
  "encoding/hex"
  "crypto/md5"
//  "strconv"
  "bufio"
  "io"
)

var (
  ListenAddr = flag.String("listenaddr", ":9509", "filexporter_exporter listen address")
  MetricsPath = flag.String("metricspath", "/metrics", "URL path for surfacing collected metrics")
  token = flag.String("token", "0000000000", "Absolute path for OpenVPN server log")
)

var (
  md5file = prometheus.NewGauge(prometheus.GaugeOpts{
    Name: "file_md5",
    Help: "Current md5 checksum of file",
  })
  filematchregex = prometheus.NewGauge(prometheus.GaugeOpts{
                Name: "file_match_regex",
                Help: "boolean output for regex input for file",
  })
)

const (
  time_layout = "Mon Jan _2 15:04:05 2006"
)

func init() {
  prometheus.MustRegister(md5file)
  prometheus.MustRegister(filematchregex)
}

func main() {
  flag.Parse()
  if *token == "" { log.Fatal("You should to set your secret token") }
  var landingPage = []byte(`<html><head><title>file_exporter exporter</title></head><body><h1>File stats exporter</h1><p><a href='` + *MetricsPath + `'>Metrics</a></p></body></html>`)
  http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { w.Write(landingPage) } )
  http.HandleFunc("/probe", probehandler)
  http.Handle(*MetricsPath, promhttp.Handler())
  log.Info("Listening on: ", *ListenAddr)
  log.Fatal(http.ListenAndServe(*ListenAddr, nil))
  go func() {
    for {
      time.Sleep(time.Duration(1000 * time.Millisecond))
    }
  }()
}

func time_convert(times string) time.Time {
        t2, _ := time.Parse(time_layout, times)
        return t2
}

func MatchStringFile(file string, matchstring string) (string) {
  var ret string
  var s []int
  fh, _  := os.Open(file)
  scanner := bufio.NewScanner(fh)
  for scanner.Scan() {
    matched, _ := regexp.MatchString(matchstring, scanner.Text())
    if matched == true {
      s = append(s, 1)
    }
  }
  if len(s) == 0 { ret = "0" }
  if len(s) > 0 { ret = "1" }
  if matchstring == "none" { ret = "-1" }
  return ret
}

func MD5SumFile(file string) (string) {
  var returnMD5String string
  fh, _  := os.Open(file)
  hash := md5.New()
  if _, err := io.Copy(hash, fh); err != nil {
    return returnMD5String
  }
  hashInBytes := hash.Sum(nil)[:16]
  returnMD5String = hex.EncodeToString(hashInBytes)
  return returnMD5String
}


func probehandler (w http.ResponseWriter, r *http.Request) {
  var regexp string
  params := r.URL.Query()
  tokenget := params.Get("token")
  clientip := strings.Split(r.RemoteAddr,":")[0] 
  if params.Get("regexp") != "" {
    regexp = params.Get("regexp")
  }  else {
    regexp = "none"
  }
  if tokenget != *token { 
    f, err := os.OpenFile("/var/log/token_error.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
    if err != nil {
      log.Fatalf("error opening file", err)
    }
    fmt.Println("Error token from IP: " + clientip)
    f.WriteString("Error token from IP: " + clientip + "\n")
    defer f.Close()
    http.Error(w, "Target parameter is missing", http.StatusBadRequest)
    return
  }
  if params.Get("target") == "" {  http.Error(w, "file param is missing", http.StatusBadRequest) }
//  if params.Get("regexp") == "" { http.Error(w, "regexp param is missing", http.StatusBadRequest) }
  if regexp == "" { http.Error(w, "regexp param is missing", http.StatusBadRequest) }
  fmt.Fprintf(w, "file_match_regex: " + MatchStringFile(params.Get("target"), regexp) + "\n")
  fmt.Fprintf(w, "file_md5: " + MD5SumFile(params.Get("target")))
  fmt.Println(params.Get("token"))
}

