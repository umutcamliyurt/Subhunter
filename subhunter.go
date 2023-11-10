// Created by Nemesis
// Contact: nemesisuks@protonmail.com

package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/common-nighthawk/go-figure"
	"github.com/parnurzeal/gorequest"
)

// ANSI Color Codes
const (
	Reset = "\x1b[0m"
	Red   = "\x1b[31;1m"
	Green = "\x1b[32;1m"
	Blue  = "\x1b[34;1m"
)

// Prints a result message with the specified color
func PrintResult(colorCode, resultMessage string) {
	result := fmt.Sprintf("[%s+%s]%s %s%s", colorCode, Reset, colorCode, resultMessage, Reset)
	fmt.Println(result)
}

// Structure of fingerprint.json
type FingerprintData struct {
	Name        string      `json:"service"`
	Cname       []string    `json:"cname"`
	Fingerprint interface{} `json:"fingerprint"`
	Response    []string    `json:"response"`
}

var Fingerprints []FingerprintData

var Targets []string

var (
	HostsList  string
	Threads    int
	All        bool
	Verbose    bool
	Timeout    int
	OutputFile string
)

var VulnerableResults []string
var NotVulnerableResults []string

// User agents
func getRandomUserAgent() string {
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36 Edg/117.0.2045.43",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.3",
	}

	rand.Seed(time.Now().UnixNano())
	return userAgents[rand.Intn(len(userAgents))]
}

func InitializeFingerprints() {
	currentDir, err := os.Getwd()
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	filePath := filepath.Join(currentDir, "fingerprint.json")

	// Checks if the file exists, if not downloads it
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		fmt.Println("Downloading fingerprint.json...")
		if err := downloadFile(filePath, "https://raw.githubusercontent.com/Nemesis0U/Subhunter/main/fingerprint.json"); err != nil {
			fmt.Printf("Error downloading fingerprint.json: %s\n", err)
			os.Exit(1)
		}
		fmt.Println("Download complete.")
	}

	raw, err := ioutil.ReadFile(filePath)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}

	err = json.Unmarshal(raw, &Fingerprints)
	if err != nil {
		fmt.Printf("%s", err)
		os.Exit(1)
	}
}

// Downloads a file from the URL and saves it to the local path
func downloadFile(filepath string, url string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP request failed with status code: %d", resp.StatusCode)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func ReadFile(file string) (lines []string, err error) {
	fileHandle, err := os.Open(file)
	if err != nil {
		return lines, err
	}

	defer fileHandle.Close()
	fileScanner := bufio.NewScanner(fileHandle)

	for fileScanner.Scan() {
		lines = append(lines, fileScanner.Text())
	}

	return lines, nil
}

func Get(url string, timeout int) (resp gorequest.Response, body string, errs []error) {
	url = fmt.Sprintf("https://%s/", url) // Uses https

	userAgent := getRandomUserAgent()

	resp, body, errs = gorequest.New().TLSClientConfig(&tls.Config{InsecureSkipVerify: true}).
		Timeout(time.Duration(timeout)*time.Second).Get(url).
		Set("User-Agent", userAgent). // Sets random user agent
		End()

	return resp, body, errs
}

func ParseArguments() {
	flag.StringVar(&HostsList, "l", "", "File including a list of hosts to scan")
	flag.IntVar(&Timeout, "timeout", 20, "Timeout in seconds")
	flag.StringVar(&OutputFile, "o", "", "File to save results")
	flag.IntVar(&Threads, "t", 50, "Number of threads for scanning")

	flag.Parse()
}

func CNAMEExists(key string) bool {
	for _, fingerprint := range Fingerprints {
		for _, cname := range fingerprint.Cname {
			if strings.Contains(key, cname) {
				return true
			}
		}
	}

	return false
}

func Check(target string, TargetCNAME string) {
	_, body, errs := Get(target, Timeout)
	if len(errs) == 0 {
		if TargetCNAME == "All" {
			for _, fingerprint := range Fingerprints {
				for _, response := range fingerprint.Response {
					if strings.Contains(body, response) {
						resultMessage := fmt.Sprintf("%s: Possible takeover found at %s: Vulnerable", fingerprint.Name, target)
						PrintResult(Green, resultMessage)
						VulnerableResults = append(VulnerableResults, resultMessage)
						return
					}
				}
			}
			resultMessage := fmt.Sprintf("Nothing found at %s: Not Vulnerable", target)
			PrintResult(Blue, resultMessage)
			NotVulnerableResults = append(NotVulnerableResults, resultMessage)
		} else {
			for _, fingerprint := range Fingerprints {
				for _, cname := range fingerprint.Cname {
					if strings.Contains(TargetCNAME, cname) {
						for _, response := range fingerprint.Response {
							if strings.Contains(body, response) {
								if fingerprint.Name == "cloudfront" {
									_, body2, _ := Get(target, 120)
									if strings.Contains(body2, response) {
										resultMessage := fmt.Sprintf("%s: Possible takeover found at %s: Vulnerable", fingerprint.Name, target)
										PrintResult(Green, resultMessage)
										VulnerableResults = append(VulnerableResults, resultMessage)
									}
								} else {
									resultMessage := fmt.Sprintf("%s: Possible takeover found at %s with CNAME record %s: Vulnerable", fingerprint.Name, target, TargetCNAME)
									PrintResult(Green, resultMessage)
									VulnerableResults = append(VulnerableResults, resultMessage)
								}
							}
							return
						}
					}
				}
			}
			resultMessage := fmt.Sprintf("Nothing found at %s with CNAME record %s: Not Vulnerable", target, TargetCNAME)
			PrintResult(Blue, resultMessage)
			NotVulnerableResults = append(NotVulnerableResults, resultMessage)
		}
	} else {
		if Verbose {
			log.Printf("(Error) Get: %s => %v", target, errs)
		}
		resultMessage := fmt.Sprintf("Failed to check %s: Error", target)
		PrintResult(Red, resultMessage)
		NotVulnerableResults = append(NotVulnerableResults, resultMessage)
	}
}

var CheckedTargetsMutex sync.Mutex         // Declares the mutex globally
var CheckedTargets = make(map[string]bool) // Declares CheckedTargets globally

func Checker(target string) {
	TargetCNAME, err := net.LookupCNAME(target)
	if err != nil {
		return
	}

	CheckedTargetsMutex.Lock() // Locks the mutex
	if All != true && CNAMEExists(TargetCNAME) == true {
		if Verbose == true {
			log.Printf("(CNAME Selected) %s => %s", target, TargetCNAME)
		}
		Check(target, TargetCNAME)
	} else if All == true && !CheckedTargets[target] { // Checks if the target hasn't been checked already
		CheckedTargets[target] = true // Marks the target as checked
		Check(target, "All")
	}
	CheckedTargetsMutex.Unlock() // Unlocks the mutex
}

func main() {
	All = true
	Verbose = true
	ParseArguments()

	// Initializes fingerprints before using them
	InitializeFingerprints()

	for _, Host := range Targets {
		go Checker(Host)
	}

	fmt.Println("")
	Banner := figure.NewColorFigure("Subhunter", "", "red", true)
	Banner.Print()
	fmt.Println("\n\nA fast subdomain takeover tool\n")
	fmt.Println("Created by Nemesis")
	fmt.Printf("\nLoaded %d fingerprints for current scan\n", len(Fingerprints))
	fmt.Println("\n-----------------------------------------------------------------------------\n")

	if HostsList == "" {
		fmt.Printf("Subhunter: No subdomains list specified for the scan!")
		fmt.Printf("\n\nInfo: Use -h for showing the help message\n\n")
		os.Exit(1)
	}

	Hosts, err := ReadFile(HostsList)
	if err != nil {
		fmt.Printf("\nread: %s\n", err)
		os.Exit(1)
	}

	Targets = append(Targets, Hosts...)

	hosts := make(chan string, Threads)
	processGroup := new(sync.WaitGroup)
	processGroup.Add(Threads)

	for i := 0; i < Threads; i++ {
		go func() {
			for {
				host := <-hosts
				if host == "" {
					break
				}

				Checker(host)
			}

			processGroup.Done()
		}()
	}

	for _, Host := range Targets {
		hosts <- Host
	}

	close(hosts)
	processGroup.Wait()

	fmt.Printf("\nSubhunter exiting...\n")

	// Writes the results to the output file if provided
	if OutputFile != "" {
		WriteResultsToFile(OutputFile, VulnerableResults, NotVulnerableResults)
	}
}

func WriteResultsToFile(filename string, vulnerableResults []string, notVulnerableResults []string) {
	file, err := os.Create(filename)
	if err != nil {
		log.Fatalf("Error creating output file: %v", err)
	}
	defer file.Close()

	// Writes vulnerable results
	for _, result := range vulnerableResults {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Fatalf("Error writing to output file: %v", err)
		}
	}

	// Writes other results
	for _, result := range notVulnerableResults {
		_, err := file.WriteString(result + "\n")
		if err != nil {
			log.Fatalf("Error writing to output file: %v", err)
		}
	}

	fmt.Printf("Results written to %s\n", filename)
}
