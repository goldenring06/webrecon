package main

import (
    "bytes"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
    //"strconv"
)

// Constants
const (
	MaxParallelRequests = 50
	MaxRetries         = 3
	RetryDelay         = 2 * time.Second
)

// Regex patterns
var (
	fileExtensions    = regexp.MustCompile(`(?i)\.(php|aspx|jsp|json|conf|xml|env|gz|log|bak|old|zip|rar|7z|tar|sql|db|ini|config|yml|yaml|backup|passwd|htpasswd)(\?|$)`)
	pdfSensitiveRegex = regexp.MustCompile(`(?i)(internal use only|confidential|strictly private|personal & confidential|private|restricted|internal|not for distribution|do not share|proprietary|trade secret|classified|sensitive|bank statement|invoice|salary|contract|agreement|non disclosure|passport|social security|ssn|date of birth|credit card|identity|id number|company confidential|staff only|management only|internal only)`)
	sensitiveRegex    = regexp.MustCompile(`(?i)\.(txt|log|cache|secret|db|backup|yml|json|gz|rar|zip|config)(\?|$)`)
)

// Colors
const (
	Red    = "\033[91m"
	Green  = "\033[92m"
	Yellow = "\033[93m"
	Blue   = "\033[95m"
	Cyan   = "\033[96m"
	Reset  = "\033[97m"
)

// Config holds all configuration parameters
type Config struct {
	Domain     string
	OutputDir  string
	Threads    int
	Ports      string
	MaxDepth   int
	RateLimit  int
	Timeout    int
	UserAgent  string
	Blacklist  []string
}

// ReconError provides detailed error information
type ReconError struct {
	Phase     string
	Operation string
	Err       error
}

func (e *ReconError) Error() string {
	return fmt.Sprintf("%s: %s failed - %v", e.Phase, e.Operation, e.Err)
}

// cookieJar implements http.CookieJar to store cookies between requests
type cookieJar struct {
    cookies []*http.Cookie
    sync.Mutex
}

func (j *cookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
    j.Lock()
    defer j.Unlock()
    j.cookies = cookies
}

func (j *cookieJar) Cookies(u *url.URL) []*http.Cookie {
    j.Lock()
    defer j.Unlock()
    return j.cookies
}


// Global HTTP client with sane defaults
var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	},
}

func main() {

    fmt.Println("GITHUB_TOKEN exists:", os.Getenv("GITHUB_TOKEN") != "")
    fmt.Println("SECURITYTRAILS_TOKEN exists:", os.Getenv("SECURITYTRAILS_TOKEN") != "")

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
    <-c
    fmt.Println("\n" + Yellow + "[!] Received interrupt signal, shutting down..." + Reset)
    os.Exit(1)
	}()

	fmt.Println(Blue + "========== RECON TOOL ==========" + Reset)
	fmt.Print(Blue + "[?] Enter domain (example.com): " + Reset)

	var domain string
	if _, err := fmt.Scanln(&domain); err != nil {
		log.Fatal(Red + "[!] Error reading domain: " + err.Error() + Reset)
	}

	config := initConfig(domain)
	defer printSummary(config)

	if err := checkDependencies(); err != nil {
		log.Fatal(Red + "[!] " + err.Error() + Reset)
	}



	// Phase 1: Subdomain discovery
	subdomainFile := filepath.Join(config.OutputDir, "subdomains.txt")
	if err := findSubdomains(config, subdomainFile); err != nil {
		log.Println(Yellow + "[!] Subdomain discovery failed: " + err.Error() + Reset)
	}

	// NEW PHASE: Historical analysis
    if err := runHistoricalAnalysis(config); err != nil {
        log.Println(Yellow + "[!] Historical analysis failed: " + err.Error() + Reset)
    }

	aliveFile := filepath.Join(config.OutputDir, "subdomains_alive.txt")
	if err := checkAliveSubdomains(config, subdomainFile, aliveFile); err != nil {
		log.Fatal(Red + "[!] Alive check failed: " + err.Error() + Reset)
	}

	// Phase 2: URL collection
	katanaFile := filepath.Join(config.OutputDir, "katana_urls.txt")
	gauFile := filepath.Join(config.OutputDir, "gau_urls.txt")
	waybackFile := filepath.Join(config.OutputDir, "wayback_urls.txt")

	if err := collectURLs(config, aliveFile, katanaFile, gauFile, waybackFile); err != nil {
		log.Fatal(Red + "[!] URL collection failed: " + err.Error() + Reset)
	}

	// Phase 3: Sensitive data discovery
	if err := findSensitiveData(config, katanaFile, gauFile, waybackFile); err != nil {
        log.Fatal(Red + "[!] Sensitive data discovery failed: " + err.Error() + Reset)
    }

	// Phase 4: Security checks
	if err := runSecurityChecks(config, aliveFile); err != nil {
        log.Println(Yellow + "[!] Some security checks failed: " + err.Error() + Reset)
    }

	// Phase 5: JavaScript Analysis
	if err := runJavaScriptAnalysis(config); err != nil {
        log.Println(Yellow + "[!] JavaScript analysis failed: " + err.Error() + Reset)
    }

    // Phase 6: Directory brute-forcing
    if err := runDirectoryBruteForce(config, config.Domain); err != nil {
        log.Println(Yellow + "[!] Directory brute-force failed: " + err.Error() + Reset)
    }
}

// Initialize configuration with defaults
func initConfig(domain string) *Config {
	outputDir := filepath.Join("output", domain)
	if err := os.MkdirAll(outputDir, os.ModePerm); err != nil {
		log.Fatal(Red + "[!] Failed to create output directory: " + err.Error() + Reset)
	}

	return &Config{
		Domain:    domain,
		OutputDir: outputDir,
		Threads:   50,
		Ports:     "80,443,8080,8000,8888",
		MaxDepth:  3,
		RateLimit: 10,
		Timeout:   30,
		UserAgent: "Mozilla/5.0 (compatible; ReconTool/1.0)",
		Blacklist: []string{"png", "jpg", "jpeg", "gif", "css", "svg"},
	}
}

// Check for required external tools
func checkDependencies() error {
	required := []string{"subfinder", "amass", "httpx", "katana", "gau", "nuclei"}

    if os.Getenv("GITHUB_TOKEN") != "" {
        required = append(required, "github-subdomains")
    }

	for _, cmd := range required {
		if _, err := exec.LookPath(cmd); err != nil {
			return fmt.Errorf("required tool not found: %s", cmd)
		}
	}
	return nil
}

// Setup signal handling for clean exits
func setupSignalHandling(cancel context.CancelFunc) {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\n" + Yellow + "[!] Received interrupt signal, shutting down..." + Reset)
		cancel()
		os.Exit(1)
	}()
}

func runHistoricalAnalysis(config *Config) error {
    fmt.Println(Yellow + "\n[+] Running Historical Analysis..." + Reset)
    
    // 1. Get DNS history
    historicalSubs, err := getDNSHistory(config.Domain)
    if err != nil {
        return fmt.Errorf("DNS history failed: %w", err)
    }
    
    // 2. Get Wayback data
    waybackData, err := getWaybackData(config.Domain)
    if err != nil {
        return fmt.Errorf("Wayback failed: %w", err)
    }

    dnsHistoryFile := filepath.Join(config.OutputDir, "dns_history.txt")
    if err := writeToFile(dnsHistoryFile, historicalSubs); err != nil {
        return fmt.Errorf("failed to save DNS history: %v", err)
    }
    
    waybackHistoryFile := filepath.Join(config.OutputDir, "wayback_history.txt")
    if err := writeToFile(waybackHistoryFile, waybackData); err != nil {
        return fmt.Errorf("failed to save Wayback history: %v", err)
    }
    
    // Combine with existing subdomains
    currentSubs, _ := readLines(filepath.Join(config.OutputDir, "subdomains.txt"))
    allSubs := append(currentSubs, historicalSubs...)
    allSubs = removeDuplicates(allSubs)
    
    // Write combined results
    combinedFile := filepath.Join(config.OutputDir, "subdomains_combined.txt")
    if err := writeToFile(combinedFile, allSubs); err != nil {
        return err
    }
    
    fmt.Printf(Green+"[✔] Found %d historical subdomains\n"+Reset, len(historicalSubs))
    fmt.Printf(Green+"[✔] Found %d historical URLs\n"+Reset, len(waybackData))
    return nil
}

// Run all subdomain discovery phases
func runSubdomainDiscovery(config *Config) error {
	fmt.Println(Yellow + "\n[+] Starting subdomain discovery..." + Reset)

	subdomainFile := filepath.Join(config.OutputDir, "subdomains.txt")
	if err := findSubdomains(config, subdomainFile); err != nil {
		return err
	}

	aliveFile := filepath.Join(config.OutputDir, "subdomains_alive.txt")
	if err := checkAliveSubdomains(config, subdomainFile, aliveFile); err != nil {
		return err
	}

	return nil
}

//DNSHistory
func getDNSHistory(domain string) ([]string, error) {
    fmt.Println(Yellow + "\n[+] Checking DNS History..." + Reset)
    
    var wg sync.WaitGroup
    results := make(chan string, 1000)
    errors := make(chan error, 2)
    
    // Query all DNS history services in parallel
    wg.Add(2)
    go func() {
        defer wg.Done()
        subs, err := querySecurityTrails(domain)
        if err != nil {
            errors <- fmt.Errorf("SecurityTrails: %v", err)
            return
        }
        for _, sub := range subs {
            results <- sub
        }
    }()
    
    
    go func() {
        defer wg.Done()
        subs, err := queryViewDNSInfo(domain)
        if err != nil {
            errors <- fmt.Errorf("ViewDNS: %v", err)
            return
        }
        for _, sub := range subs {
            results <- sub
        }
    }()
    
    // Close channels when done
    go func() {
        wg.Wait()
        close(results)
        close(errors)
    }()
    
    // Collect results
    subdomains := make(map[string]bool)
    for sub := range results {
        subdomains[sub] = true
    }
    
    // Check for errors
    for err := range errors {
        fmt.Printf(Red+"  [!] %v\n"+Reset, err)
    }
    
    // Convert to slice
    var uniqueSubs []string
    for sub := range subdomains {
        uniqueSubs = append(uniqueSubs, sub)
    }
    
    fmt.Printf(Green+"[✔] Found %d unique historical subdomains\n"+Reset, len(uniqueSubs))
    return uniqueSubs, nil
}

//waybackdata
func getWaybackData(domain string) ([]string, error) {
    fmt.Println(Yellow + "\n[+] Querying Wayback Machine for historical data..." + Reset)
    
    // Sensitive paths to check
    sensitivePaths := []string{
        "admin", "login", "api", "v1", "v2", "internal",
        "backup", "config", "env", "secret", "auth",
        "wp-admin", "wp-login", "console", "debug",
    }
    
    var allURLs []string
    
    // Check domain root
    urls, err := fetchWaybackURLs(domain)
    if err != nil {
        return nil, fmt.Errorf("wayback root failed: %v", err)
    }
    allURLs = append(allURLs, urls...)
    
    // Check sensitive paths
    for _, path := range sensitivePaths {
        url := fmt.Sprintf("%s/%s", domain, path)
        urls, err := fetchWaybackURLs(url)
		if err != nil {
    		return nil, err
		}
        if err != nil {
            fmt.Printf(Red+"  [!] Wayback query for %s failed: %v\n"+Reset, path, err)
            continue
        }
        allURLs = append(allURLs, urls...)
    }
    
    // Filter for interesting files
    var filtered []string
    for _, url := range allURLs {
        if strings.Contains(url, "=") ||
           sensitiveRegex.MatchString(url) || 
           strings.Contains(url, "api") || 
           strings.Contains(url, "admin") { 
            filtered = append(filtered, url)
        }
    }
    
    // Remove duplicates
    filtered = removeDuplicates(filtered)
    
    fmt.Printf(Green+"[✔] Found %d interesting historical URLs\n"+Reset, len(filtered))
    return filtered, nil
}

//historicalsubdomains
func findHistoricalSubdomains(domain string) ([]string, error) {
    
    waybackURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey", domain)
    resp, err := httpClient.Get(waybackURL)
    if err != nil {
        return nil, fmt.Errorf("archive.org request failed: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != 200 {
        return nil, fmt.Errorf("archive.org returned status %d", resp.StatusCode)
    }

    var results [][]string
    if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
        return nil, fmt.Errorf("archive.org JSON parse failed: %v", err)
    }

    subdomains := make(map[string]bool)
    for _, record := range results {
        if len(record) > 0 {
            u, err := url.Parse(record[0])
            if err == nil && u.Host != "" {
                host := u.Hostname()
                if strings.Contains(host, domain) {
                    subdomains[host] = true
                }
            }
        }
    }

    var uniqueSubs []string
    for sub := range subdomains {
        uniqueSubs = append(uniqueSubs, sub)
    }

    return uniqueSubs, nil
}


func findSubdomains(config *Config, outputFile string) error {
    fmt.Println(Yellow + "\n[+] Discovering subdomains..." + Reset)

    results := make(chan string, 10000)
    var wg sync.WaitGroup
    errors := make(chan error, 10)

    // Define tools to run
    tools := []struct {
        name   string
        method func(string, *sync.WaitGroup, chan string, chan error)
    }{
        {"Subfinder", runSubfinder},
        {"Assetfinder", runAssetfinder},
        {"GitHub Subdomains", runGithubSubdomains},
        {"crt.sh", runCrtSh},
        {"Wayback Machine", runWaybackSubdomains},
        {"SecurityTrails DNS History", runSecurityTrails},
        {"ViewDNS.info", runViewDNSInfo},
    }

    // Start all tools
    for _, tool := range tools {
        wg.Add(1)
        fmt.Printf(Cyan+"  [>] Running %s...\n"+Reset, tool.name)
        go tool.method(config.Domain, &wg, results, errors)
    }

    // Close channels when all tools are done
    go func() {
        wg.Wait()
        close(results)
        close(errors)
    }()

    // Collect results
    subdomains := make(map[string]bool)
    for sub := range results {
        if sub != "" {
            subdomains[sub] = true
        }
    }

    // Check for errors
    for err := range errors {
        if err != nil {
            fmt.Printf(Red+"  [!] Tool error: %v\n"+Reset, err)
        }
    }

    if len(subdomains) == 0 {
        return fmt.Errorf("no subdomains found")
    }

    // Check Archive.org for historical subdomains
    historicalSubs, err := findHistoricalSubdomains(config.Domain)
    if err != nil {
        fmt.Printf(Yellow+"  [!] Historical subdomain check failed: %v\n"+Reset, err)
    } else {
        fmt.Printf(Cyan+"  [i] Found %d historical subdomains from Archive.org\n"+Reset, len(historicalSubs))
        for _, sub := range historicalSubs {
            subdomains[sub] = true
        }
    }

    var uniqueSubs []string
    for sub := range subdomains {
        uniqueSubs = append(uniqueSubs, sub)
    }

    if err := writeToFile(outputFile, uniqueSubs); err != nil {
        return err
    }

    resolvedFile := filepath.Join(config.OutputDir, "resolved_subdomains.txt")
    if err := resolveSubdomains(outputFile, resolvedFile); err != nil {
        return fmt.Errorf("DNS resolution failed: %w", err)
    }

    fmt.Printf(Green+"[✔] Found %d unique subdomains (including historical)\n"+Reset, len(uniqueSubs))
    fmt.Printf(Green+"[✔] Saved to: %s\n"+Reset, outputFile)
    return nil
}


// New function that just takes a domain and returns results
func querySecurityTrails(domain string) ([]string, error) {
    results := make(chan string, 1000)
    errors := make(chan error, 1)
    var wg sync.WaitGroup
    wg.Add(1)

    // Call the original function
    go runSecurityTrails(domain, &wg, results, errors)

    // Wait for completion
    wg.Wait()
    close(results)
    close(errors)

    // Collect results
    var subs []string
    for sub := range results {
        subs = append(subs, sub)
    }

    // Check for errors
    if err := <-errors; err != nil {
        return nil, err
    }

    return subs, nil
}

// Do the same for ViewDNS

func queryViewDNSInfo(domain string) ([]string, error) {
    results := make(chan string, 1000)
    errors := make(chan error, 1)
    var wg sync.WaitGroup
    wg.Add(1)

    go runViewDNSInfo(domain, &wg, results, errors)
    wg.Wait()
    close(results)
    close(errors)

    var subs []string
    for sub := range results {
        subs = append(subs, sub)
    }

    if err := <-errors; err != nil {
        return nil, err
    }

    return subs, nil
}


// New functions for DNS history and Archive.org checks
func runSecurityTrails(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
	defer wg.Done()

	token := os.Getenv("SECURITYTRAILS_TOKEN")
	if token == "" {
		errors <- fmt.Errorf("securitytrails: no API token (set SECURITYTRAILS_TOKEN)")
		return
	}

	// Define all endpoints we want to query
	endpoints := []struct {
		url       string
		processor func(*http.Response) ([]string, error)
	}{
		// 1. Original historical DNS endpoint
		{
			fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a", domain),
			func(resp *http.Response) ([]string, error) {
				var data struct {
					Records []struct{ Hostname string `json:"host"` }
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
					return nil, err
				}
				var subs []string
				for _, r := range data.Records {
					if r.Hostname != "" {
						subs = append(subs, r.Hostname)
					}
				}
				return subs, nil
			},
		},
		// 2. Historical IPs endpoint (1st new curl command)
		{
			fmt.Sprintf("https://api.securitytrails.com/v1/history/%s/dns/a?page=1", domain),
			func(resp *http.Response) ([]string, error) {
				var data struct {
					Records []struct {
						Values []struct{ IP string `json:"ip"` }
					}
				}
				if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
					return nil, err
				}
				uniqueIPs := make(map[string]struct{})
				for _, r := range data.Records {
					for _, v := range r.Values {
						if v.IP != "" {
							uniqueIPs[v.IP] = struct{}{}
						}
					}
				}
				ips := make([]string, 0, len(uniqueIPs))
				for ip := range uniqueIPs {
					ips = append(ips, ip)
				}
				return ips, nil
			},
		},
		// 3. Subdomains endpoint (2nd new curl command)
		{
			fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", domain),
			func(resp *http.Response) ([]string, error) {
				var data struct{ Subdomains []string }
				if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
					return nil, err
				}
				subs := make([]string, 0, len(data.Subdomains))
				for _, s := range data.Subdomains {
					if s != "" {
						subs = append(subs, fmt.Sprintf("%s.%s", s, domain))
					}
				}
				return subs, nil
			},
		},
	}

	// Process all endpoints concurrently
	var (
		collectorWg sync.WaitGroup
		allResults   = make(chan []string)
	)
	for _, ep := range endpoints {
		collectorWg.Add(1)
		go func(ep struct {
			url       string
			processor func(*http.Response) ([]string, error)
		}) {
			defer collectorWg.Done()

			resp, err := makeRequest(ep.url, token)
			if err != nil {
				errors <- fmt.Errorf("securitytrails request failed (%s): %v", ep.url, err)
				return
			}
			defer resp.Body.Close()

			subs, err := ep.processor(resp)
			if err != nil {
				errors <- fmt.Errorf("securitytrails parse failed (%s): %v", ep.url, err)
				return
			}
			allResults <- subs
		}(ep)
	}

	// Close channel when all workers finish
	go func() {
		collectorWg.Wait()
		close(allResults)
	}()

	// Deduplicate and send results
	unique := make(map[string]struct{})
	count := 0
	for subs := range allResults {
		for _, s := range subs {
			if _, exists := unique[s]; !exists {
				unique[s] = struct{}{}
				results <- s
				count++
			}
		}
	}

	fmt.Printf(Green+"  [✔] SecurityTrails found %d unique items\n"+Reset, count)
}

// Helper function for HTTP requests with retries
func makeRequest(url, token string) (*http.Response, error) {
	for attempt := 1; attempt <= 3; attempt++ {
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("APIKEY", token)
		req.Header.Set("Accept", "application/json")

		resp, err := httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}
		if resp != nil {
			resp.Body.Close()
		}
		if attempt < 3 {
			time.Sleep(time.Duration(attempt) * time.Second)
		}
	}
	return nil, fmt.Errorf("max retries exceeded")
}



func runViewDNSInfo(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    
    url := fmt.Sprintf("https://viewdns.info/reverseip/?host=%s&t=1", domain)
    resp, err := httpClient.Get(url)
    if err != nil {
        errors <- fmt.Errorf("viewdns.info failed: %v", err)
        return
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        errors <- fmt.Errorf("viewdns.info read failed: %v", err)
        return
    }

    // Updated regex pattern
    tableRegex := regexp.MustCompile(`<td>([a-zA-Z0-9.-]+\.`+regexp.QuoteMeta(domain)+`)</td>`)
    matches := tableRegex.FindAllStringSubmatch(string(body), -1)

    count := 0
    for _, match := range matches {
        if len(match) > 1 {
            sub := strings.TrimSpace(match[1])
            if sub != "" {
                results <- sub
                count++
            }
        }
    }
    fmt.Printf(Green+"  [✔] ViewDNS.info found %d subdomains\n"+Reset, count)
}


func printSummary(config *Config) {
	fmt.Println(Blue + "\n========== RECON SUMMARY ==========" + Reset)
	fmt.Printf(Cyan+"[i] Domain: %s\n"+Reset, config.Domain)
	fmt.Printf(Cyan+"[i] Output Directory: %s\n"+Reset, config.OutputDir)
	fmt.Println(Blue + "==================================" + Reset)
}

/*func runSubfinder(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    //fmt.Println(Cyan + "  [>] Running Subfinder..." + Reset)
    
    cmd := exec.Command("subfinder", "-d", domain, "-all", "-recursive")
    
    // Create pipes for both stdout and stderr
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()
    
    // Start the command
    if err := cmd.Start(); err != nil {
        errors <- fmt.Errorf("subfinder failed to start: %v", err)
        return
    }
    
    // Channel to collect all output lines
    outputLines := make(chan string, 1000)
    
    // Read stdout in a goroutine
    go func() {
        scanner := bufio.NewScanner(stdoutPipe)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                fmt.Println("    " + line) // Print with indentation
                outputLines <- line
            }
        }
    }()
    
    // Read stderr in a goroutine
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()
    
    // Wait for command to complete
    err := cmd.Wait()
    close(outputLines)
    
    if err != nil {
        errors <- fmt.Errorf("subfinder execution failed: %v", err)
        return
    }
    
    // Count and send results
    count := 0
    for line := range outputLines {
        results <- line
        count++
    }
    
    fmt.Printf(Green+"  [✔] Subfinder found %d subdomains\n"+Reset, count)
}*/

func runSubfinder(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    
    cmd := exec.Command("subfinder", "-d", domain, "-all", "-recursive")
    
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()
    
    if err := cmd.Start(); err != nil {
        errors <- fmt.Errorf("subfinder failed to start: %v", err)
        return
    }
    
    outputLines := make(chan string, 1000) // Buffered channel for performance
    var scannerWg sync.WaitGroup
    
    // Read stdout in a goroutine
    scannerWg.Add(1)
    go func() {
        defer scannerWg.Done()
        scanner := bufio.NewScanner(stdoutPipe)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                fmt.Println("    " + line)
                outputLines <- line
            }
        }
    }()
    
    // Read stderr in a goroutine (no channel writes, so no sync needed)
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()
    
    // Wait for command to complete
    err := cmd.Wait()
    
    // Wait for the scanner goroutine to finish sending all lines
    scannerWg.Wait()
    close(outputLines) // Safe to close now
    
    if err != nil {
        errors <- fmt.Errorf("subfinder execution failed: %v", err)
        return
    }
    
    // Count and send results
    count := 0
    for line := range outputLines {
        results <- line
        count++
    }
    
    fmt.Printf(Green+"  [✔] Subfinder found %d subdomains\n"+Reset, count)
}

/*func runAssetfinder(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    //fmt.Println(Cyan + "  [>] Running Assetfinder..." + Reset)
    
    cmd := exec.Command("assetfinder", "--subs-only", domain)
    
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()
    
    if err := cmd.Start(); err != nil {
        errors <- fmt.Errorf("assetfinder failed to start: %v", err)
        return
    }
    
    outputLines := make(chan string, 1000)
    
    go func() {
        scanner := bufio.NewScanner(stdoutPipe)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                fmt.Println("    " + line)
                outputLines <- line
            }
        }
    }()
    
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()
    
    err := cmd.Wait()
    close(outputLines)
    
    if err != nil {
        errors <- fmt.Errorf("assetfinder execution failed: %v", err)
        return
    }
    
    count := 0
    for line := range outputLines {
        results <- line
        count++
    }
    
    fmt.Printf(Green+"  [✔] Assetfinder found %d subdomains\n"+Reset, count)
}*/

func runAssetfinder(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    
    // 1. Setup command with context for timeout control
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
    defer cancel()
    
    cmd := exec.CommandContext(ctx, "assetfinder", "--subs-only", domain)
    
    // 2. Create pipes with error handling
    stdoutPipe, err := cmd.StdoutPipe()
    if err != nil {
        errors <- fmt.Errorf("stdout pipe failed: %v", err)
        return
    }
    
    stderrPipe, err := cmd.StderrPipe()
    if err != nil {
        errors <- fmt.Errorf("stderr pipe failed: %v", err)
        return
    }

    // 3. Start process
    if err := cmd.Start(); err != nil {
        errors <- fmt.Errorf("process start failed: %v", err)
        return
    }

    // 4. Buffered channel with safe closing mechanism
    outputLines := make(chan string, 5000) // Large buffer for big scans
    var (
        outputClosed bool
        outputMutex  sync.Mutex
        scannerWg    sync.WaitGroup
    )

    // 5. Safe send function
    safeSend := func(line string) bool {
        outputMutex.Lock()
        defer outputMutex.Unlock()
        if !outputClosed {
            select {
            case outputLines <- line:
                return true
            case <-ctx.Done():
                return false
            }
        }
        return false
    }

    // 6. Stdout scanner goroutine
    scannerWg.Add(1)
    go func() {
        defer scannerWg.Done()
        scanner := bufio.NewScanner(stdoutPipe)
        
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                fmt.Println("    " + line)
                if !safeSend(line) {
                    return // Context canceled or channel closed
                }
            }
            
            // Check for context cancellation
            select {
            case <-ctx.Done():
                return
            default:
            }
        }
    }()

    // 7. Stderr handler goroutine
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()

    // 8. Wait for completion with timeout
    processDone := make(chan struct{})
    go func() {
        scannerWg.Wait()
        close(processDone)
    }()

    select {
    case <-processDone:
        // Normal completion
    case <-ctx.Done():
        errors <- fmt.Errorf("scan timed out after 10 minutes")
        cmd.Process.Kill()
        return
    }

    // 9. Safe channel closing
    outputMutex.Lock()
    if !outputClosed {
        close(outputLines)
        outputClosed = true
    }
    outputMutex.Unlock()

    // 10. Process results with cancellation support
    count := 0
    for line := range outputLines {
        select {
        case results <- line:
            count++
        case <-ctx.Done():
            fmt.Println(Yellow + "  [!] Results processing canceled" + Reset)
            return
        }
    }

    // 11. Verify process exit status
    if err := cmd.Wait(); err != nil {
        if ctx.Err() == nil { // Only report if not canceled
            errors <- fmt.Errorf("process execution failed: %v", err)
        }
        return
    }

    fmt.Printf(Green+"  [✔] Assetfinder found %d subdomains\n"+Reset, count)
}



/*func runGithubSubdomains(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    //fmt.Println(Cyan + "  [>] Running Github Subdomains..." + Reset)
    
    token := os.Getenv("GITHUB_TOKEN")
    if token == "" {
        msg := "github-subdomains skipped: no token provided (set GITHUB_TOKEN environment variable)"
        fmt.Println(Yellow + "  [!] " + msg + Reset)
        errors <- fmt.Errorf(msg)
        return
    }
    
    cmd := exec.Command("github-subdomains", "-d", domain, "-t", token)
    
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()
    
    if err := cmd.Start(); err != nil {
        errors <- fmt.Errorf("github-subdomains failed to start: %v", err)
        return
    }
    
    outputLines := make(chan string, 1000)
    
    go func() {
        scanner := bufio.NewScanner(stdoutPipe)
        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line != "" {
                fmt.Println("    " + line)
                outputLines <- line
            }
        }
    }()
    
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()
    
    err := cmd.Wait()
    close(outputLines)
    
    if err != nil {
        errors <- fmt.Errorf("github-subdomains execution failed: %v", err)
        return
    }
    
    count := 0
    for line := range outputLines {
        results <- line
        count++
    }
    
    fmt.Printf(Green+"  [✔] Github Subdomains found %d subdomains\n"+Reset, count)
}*/

func runGithubSubdomains(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    
    token := os.Getenv("GITHUB_TOKEN")
    if token == "" {
        errors <- fmt.Errorf("missing GITHUB_TOKEN")
        return
    }

    cmd := exec.Command("github-subdomains", "-d", domain, "-t", token)
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        errors <- fmt.Errorf("failed to start: %v", err)
        return
    }

    // Channel with timeout
    outputLines := make(chan string, 1000)
    var scannerWg sync.WaitGroup
    scannerWg.Add(1)

    // Stdout scanner with timeout
    go func() {
        defer scannerWg.Done()
        defer close(outputLines)
        
        scanner := bufio.NewScanner(stdoutPipe)
        lastActive := time.Now()

        for scanner.Scan() {
            line := strings.TrimSpace(scanner.Text())
            if line == "" {
                continue
            }

            // Detect empty results
            if strings.Contains(line, "\"total_count\": 0") {
                fmt.Println("    [i] No more results")
                return
            }

            fmt.Println("    " + line)
            outputLines <- line
            lastActive = time.Now()
            
            // Timeout check
            if time.Since(lastActive) > 20*time.Second {
                fmt.Println(Yellow+"  [!] Timeout waiting for data"+Reset)
                return
            }
        }
    }()

    // Stderr handler (unchanged)
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()

    // Process timeout
    done := make(chan error)
    go func() { done <- cmd.Wait() }()

    select {
    case err := <-done:
        if err != nil {
            errors <- fmt.Errorf("execution failed: %v", err)
        }
    case <-time.After(5 * time.Minute):
        cmd.Process.Kill()
        errors <- fmt.Errorf("timeout after 5 minutes")
    }

    scannerWg.Wait()
    
    // Process results (unchanged)
    count := 0
    for line := range outputLines {
        results <- line
        count++
    }
    fmt.Printf(Green+"  [✔] Found %d subdomains\n"+Reset, count)
}

func runCrtSh(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    
    url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
    
    // Create the request
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        errors <- fmt.Errorf("crt.sh request creation failed: %v", err)
        return
    }
    
    // Set headers
    req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    req.Header.Set("Accept", "application/json")

    // Make the request
    resp, err := httpClient.Do(req)
    if err != nil {
        errors <- fmt.Errorf("crt.sh request failed: %v", err)
        return
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        errors <- fmt.Errorf("crt.sh returned status %d", resp.StatusCode)
        return
    }

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        errors <- fmt.Errorf("crt.sh read failed: %v", err)
        return
    }

    var certs []struct {
        NameValue string `json:"name_value"`
    }
    if err := json.Unmarshal(body, &certs); err != nil {
        errors <- fmt.Errorf("crt.sh JSON parse failed: %v", err)
        return
    }

    // Create a map to store unique subdomains
    uniqueSubs := make(map[string]struct{})
    count := 0

    for _, cert := range certs {
        for _, sub := range strings.Split(cert.NameValue, "\n") {
            // Trim whitespace, remove quotes, and remove wildcard prefix
            sub = strings.TrimSpace(sub)
            sub = strings.TrimPrefix(sub, "*.")
            sub = strings.Trim(sub, "\"")
            
            // Validate the subdomain matches the pattern
            matched, _ := regexp.MatchString(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`, sub)
            if matched && strings.HasSuffix(sub, domain) {
                if _, exists := uniqueSubs[sub]; !exists {
                    uniqueSubs[sub] = struct{}{}
                    fmt.Println("    " + sub)
                    results <- sub
                    count++
                }
            }
        }
    }
    
    fmt.Printf(Green+"  [✔] crt.sh found %d subdomains\n"+Reset, count)
}

func runWaybackSubdomains(domain string, wg *sync.WaitGroup, results chan string, errors chan error) {
    defer wg.Done()
    //fmt.Println(Cyan + "  [>] Running Wayback Machine..." + Reset)
    
    waybackURL := fmt.Sprintf("http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)
    resp, err := http.Get(waybackURL)
    if err != nil {
        errors <- fmt.Errorf("wayback machine failed: %v", err)
        return
    }
    defer resp.Body.Close()

    count := 0
    scanner := bufio.NewScanner(resp.Body)
    for scanner.Scan() {
        line := strings.TrimSpace(scanner.Text())
        if line != "" && strings.HasPrefix(line, "http") {
            if u, err := url.Parse(line); err == nil {
                host := u.Hostname()
                if strings.HasSuffix(host, domain) {
                    //fmt.Println("    " + host)
                    results <- host
                    count++
                }
            }
        }
    }
    
    if err := scanner.Err(); err != nil {
        errors <- fmt.Errorf("wayback scan failed: %v", err)
    }
    
    fmt.Printf(Green+"  [✔] Wayback Machine found %d subdomains\n"+Reset, count)
}



func resolveSubdomains(inputFile, outputFile string) error {
    fmt.Println(Cyan + "  [>] Running DNSx for resolution..." + Reset)
    
    cmd := exec.Command("dnsx", "-l", inputFile, "-o", outputFile)
    
    stdoutPipe, _ := cmd.StdoutPipe()
    stderrPipe, _ := cmd.StderrPipe()
    
    if err := cmd.Start(); err != nil {
        return fmt.Errorf("dnsx failed to start: %v", err)
    }
    
    go func() {
        scanner := bufio.NewScanner(stdoutPipe)
        for scanner.Scan() {
            fmt.Println("    " + scanner.Text())
        }
    }()
    
    go func() {
        scanner := bufio.NewScanner(stderrPipe)
        for scanner.Scan() {
            fmt.Println(Red + "            " + scanner.Text() + Reset)
        }
    }()
    
    return cmd.Wait()
}



func checkAliveSubdomains(config *Config, inputFile, outputFile string) error {
    fmt.Println(Yellow + "\n[+] Checking alive subdomains..." + Reset)
    
    cmd := exec.Command(
        "httpx-toolkit",
        "-l", inputFile,
        "-ports", config.Ports,
        "-threads", fmt.Sprintf("%d", config.Threads),
        //"-sc",
        //"-title",
        //"-server",
        //"-no-color",
        "-silent",
        "-o", outputFile,
    )

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("httpx failed: %w", err)
    }

    alive, err := readLines(outputFile)
    if err != nil {
        return err
    }

    if len(alive) == 0 {
        return fmt.Errorf("no alive subdomains found")
    }

    fmt.Printf(Green+"[✔] Found %d alive subdomains\n"+Reset, len(alive))
    fmt.Printf(Green+"[✔] Saved to: %s\n"+Reset, outputFile)
    return nil
}
func countLines(filename string) (int, error) {
	file, err := os.Open(filename)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	count := 0
	for scanner.Scan() {
		count++
	}
	return count, scanner.Err()
}

func collectURLs(config *Config, aliveFile, katanaFile, gauFile, waybackFile string) error {
    fmt.Println(Yellow + "\n[+] Collecting URLs from multiple sources..." + Reset)

    var wg sync.WaitGroup
    errChan := make(chan error, 3) // Buffer for all possible errors

    // Launch Katana
    wg.Add(1)
    go func() {
        defer wg.Done()
        fmt.Println(Yellow + "  [>] Running Katana..." + Reset)
        cmd := exec.Command(
            "katana",
            "-list", aliveFile,
            "-d", fmt.Sprintf("%d", config.MaxDepth),
            "-jc",
            "-kf",
            "-silent",
            "-o", katanaFile,
        )
        if err := cmd.Run(); err != nil {
            errChan <- fmt.Errorf("katana failed: %w", err)
        }
    }()

    // Launch GAU
    wg.Add(1)
    go func() {
        defer wg.Done()
        fmt.Println(Yellow + "  [>] Running GAU..." + Reset)
        cmd := exec.Command(
            "gau",
            "--threads", fmt.Sprintf("%d", config.Threads),
            "--subs",
            "--blacklist", "png,jpg,jpeg,gif,css,svg,woff,woff2,ico",
            config.Domain,
        )
        file, err := os.Create(gauFile)
        if err != nil {
            errChan <- fmt.Errorf("failed to create GAU output file: %w", err)
            return
        }
        defer file.Close()

        cmd.Stdout = file
        if err := cmd.Run(); err != nil {
            errChan <- fmt.Errorf("gau failed: %w", err)
        }
    }()

    // Launch Wayback
    wg.Add(1)
    go func() {
        defer wg.Done()
        fmt.Println(Yellow + "  [>] Querying Wayback Machine..." + Reset)
        urls, err := fetchWaybackURLs(config.Domain)
        if err != nil {
            errChan <- fmt.Errorf("wayback failed: %w", err)
            return
        }
        if err := writeToFile(waybackFile, urls); err != nil {
            errChan <- fmt.Errorf("failed to write wayback urls: %w", err)
        }
    }()

    // Wait for all goroutines to complete
    go func() {
        wg.Wait()
        close(errChan)
    }()

    // Collect errors
    for err := range errChan {
        if err != nil {
            return err
        }
    }

    fmt.Println(Green + "[✔] URL collection completed" + Reset)
    return nil
}

func findSensitiveData(config *Config, katanaFile, gauFile, waybackFile string) error {
	fmt.Println(Yellow + "\n[+] Analyzing for sensitive data..." + Reset)

	katanaURLs, _ := readLines(katanaFile)
	gauURLs, _ := readLines(gauFile)
	waybackURLs, _ := readLines(waybackFile)

	allURLs := append(katanaURLs, gauURLs...)
	allURLs = append(allURLs, waybackURLs...)
	allURLs = removeDuplicates(allURLs)

	allURLsFile := filepath.Join(config.OutputDir, "all_urls.txt")
	if err := writeToFile(allURLsFile, allURLs); err != nil {
		return err
	}

	var sensitiveFiles, jsFiles []string
	for _, url := range allURLs {
		if sensitiveRegex.MatchString(url) {
			sensitiveFiles = append(sensitiveFiles, url)
		}
		if strings.HasSuffix(strings.ToLower(url), ".js") {
			jsFiles = append(jsFiles, url)
		}
	}

	sensitiveFile := filepath.Join(config.OutputDir, "sensitive_files.txt")
	if err := writeToFile(sensitiveFile, sensitiveFiles); err != nil {
		return err
	}

	jsFile := filepath.Join(config.OutputDir, "js_files.txt")
	if err := writeToFile(jsFile, jsFiles); err != nil {
		return err
	}

	fmt.Printf(Green+"[✔] Found %d sensitive files\n"+Reset, len(sensitiveFiles))
	fmt.Printf(Green+"[✔] Found %d JavaScript files\n"+Reset, len(jsFiles))

	if err := checkOpenRedirects(config, allURLsFile); err != nil {
		fmt.Printf(Red+"[!] Open redirect check failed: %v\n"+Reset, err)
	}

	return nil
}

func runSecurityChecks(config *Config, aliveFile string) error {
	fmt.Println(Yellow + "\n[+] Running security checks..." + Reset)

   // cleanFile := filepath.Join(config.OutputDir, "subdomains_alive_clean.txt")

	var wg sync.WaitGroup
	wg.Add(4)
	errChan := make(chan error, 4)

	go func() {
		defer wg.Done()
		fmt.Println(Yellow + "  [>] Checking for subdomain takeovers..." + Reset)
		cmd := exec.Command(
			"subzy",
			"run",
			"--targets", aliveFile,
			"--verify_ssl",
			"--hide_fails",
			"--output", filepath.Join(config.OutputDir, "subzy_results.json"),
		)
		if err := cmd.Run(); err != nil {
			errChan <- fmt.Errorf("subzy failed: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		fmt.Println(Yellow + "  [>] Checking for CORS misconfigurations..." + Reset)
		cmd := exec.Command(
			"nuclei",
			"-l", aliveFile,
			"-t", "/home/kali/mangaldeep-templates/cors.yaml",
			"-c", fmt.Sprintf("%d", config.Threads),
			"-silent",
			"-o", filepath.Join(config.OutputDir, "cors_results.txt"),
		)
		if err := cmd.Run(); err != nil {
			errChan <- fmt.Errorf("nuclei failed: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		fmt.Println(Yellow + "  [>] Checking for CRLF injection vulnerabilities..." + Reset)
		cmd := exec.Command(
			"sh", "-c",
			fmt.Sprintf("cat %s | nuclei -t /home/kali/mangaldeep-templates/cRlf.yaml -v -o %s",
				aliveFile,
				filepath.Join(config.OutputDir, "crlf_results.txt")),
		)
		if err := cmd.Run(); err != nil {
			errChan <- fmt.Errorf("nuclei CRLF check failed: %w", err)
		}
	}()

	go func() {
		defer wg.Done()
		fmt.Println(Yellow + "  [>] Checking Wayback for sensitive files..." + Reset)
		outputFile := filepath.Join(config.OutputDir, "wayback_sensitive.txt")
		_, err := fetchWaybackSensitive(config.Domain, outputFile)
		if err != nil {
			errChan <- fmt.Errorf("wayback failed: %w", err)
		}
	}()

	wg.Wait()
	close(errChan)

	for err := range errChan {
		if err != nil {
			return err
		}
	}

	return nil
}

func verifyJSAnalysis(config *Config) error {
	fmt.Println(Yellow + "\n[+] Verifying JavaScript analysis pipeline..." + Reset)

	jsFile := filepath.Join(config.OutputDir, "js_files.txt")
	jsUrls, err := readLines(jsFile)
	if err != nil {
		return fmt.Errorf("failed to read js_files.txt: %w", err)
	}
	if len(jsUrls) == 0 {
		return fmt.Errorf("no JS files found in js_files.txt")
	}

	fmt.Printf(Cyan+"  [i] Found %d JS files in js_files.txt\n"+Reset, len(jsUrls))
	fmt.Println(Cyan + "  [i] Sample JS files:" + Reset)
	for i := 0; i < min(5, len(jsUrls)); i++ {
		fmt.Printf("  - %s\n", jsUrls[i])
	}

	testURL := jsUrls[0]
	fmt.Printf(Yellow+"  [>] Testing fetch of %s ...\n"+Reset, testURL)

	var resp *http.Response
	for i := 0; i < MaxRetries; i++ {
		resp, err = http.Get(testURL)
		if err != nil {
			fmt.Printf(Yellow+"  [!] Attempt %d: %v\n"+Reset, i+1, err)
			time.Sleep(2 * time.Second)
			continue
		}
		defer resp.Body.Close()
		break
	}

	if resp == nil {
		return fmt.Errorf("failed to fetch JS file after %d attempts", MaxRetries)
	}

	fmt.Printf(Cyan+"  [i] Response status: %d\n"+Reset, resp.StatusCode)
	if resp.StatusCode != 200 {
		fmt.Println(Yellow + "  [!] JS file not accessible (non-200 status)" + Reset)
		fmt.Println(Yellow + "  [!] Continuing analysis with all JS files (may get partial results)" + Reset)
		return nil
	}

	fmt.Println(Green + "  [✔] JS file accessible" + Reset)
	return nil
}

func runJavaScriptAnalysis(config *Config) error {
    fmt.Println(Yellow + "\n[+] Running JavaScript analysis..." + Reset)

    jsDir := filepath.Join(config.OutputDir, "js_analysis")
    if err := os.MkdirAll(jsDir, os.ModePerm); err != nil {
        return fmt.Errorf("failed to create js_analysis directory: %w", err)
    }

    jsFile := filepath.Join(config.OutputDir, "js_files.txt")
    jsUrls, err := readLines(jsFile)
    if err != nil {
        return fmt.Errorf("failed to read js_files.txt: %w", err)
    }
    if len(jsUrls) == 0 {
        return fmt.Errorf("no JavaScript files found in js_files.txt")
    }
    fmt.Printf(Cyan+"  [i] Found %d JS files to analyze\n"+Reset, len(jsUrls))

    liveJS := filepath.Join(jsDir, "live_js.txt")
    fmt.Println(Yellow + "  [>] Filtering live JS files with httpx..." + Reset)

    if err := os.WriteFile(liveJS, []byte{}, 0644); err != nil {
        return fmt.Errorf("failed to create live_js.txt: %w", err)
    }

    httpxPath, err := exec.LookPath("httpx-toolkit")
    if err != nil {
        return fmt.Errorf("httpx-toolkit not found in PATH: %w", err)
    }

    cmd := exec.Command(
        httpxPath,
        "-l", jsFile,
        "-mc", "200",
        "-o", liveJS,
        "-silent",
        "-rate-limit", "10",
        "-retries", "2",
        "-timeout", "10",
    )

    if output, err := cmd.CombinedOutput(); err != nil {
        fmt.Printf(Yellow+"  [!] httpx command failed: %v\nOutput: %s\n"+Reset, err, string(output))
        fmt.Println(Yellow + "  [!] Falling back to using all JS files" + Reset)
        if err := writeToFile(liveJS, jsUrls); err != nil {
            return fmt.Errorf("failed to create fallback JS file: %w", err)
        }
    }

    liveUrls, err := readLines(liveJS)
    if err != nil {
        return fmt.Errorf("failed to read live_js.txt: %w", err)
    }
    if len(liveUrls) == 0 {
        return fmt.Errorf("no live JS files found (empty live_js.txt)")
    }
    fmt.Printf(Cyan+"  [i] Found %d live JS files\n"+Reset, len(liveUrls))

    fmt.Println(Yellow + "  [>] Adding delay to avoid rate limiting..." + Reset)
    time.Sleep(5 * time.Second)

    credsResults := filepath.Join(jsDir, "credentials_results.txt")
    fmt.Println(Yellow + "  [>] Checking for credentials disclosure using Nuclei..." + Reset)

    cmd = exec.Command(
        "bash", "-c",
        fmt.Sprintf("cat %s | nuclei -t /home/kali/mangaldeep-templates/credentials-disclosure-all.yaml -c 30 > %s",
            liveJS,
            credsResults),
    )
    if output, err := cmd.CombinedOutput(); err != nil {
        return fmt.Errorf("nuclei credentials check failed: %v\nOutput: %s", err, string(output))
    }

    if info, err := os.Stat(credsResults); err != nil || info.Size() == 0 {
        fmt.Println(Yellow + "  [!] No credentials found (empty output file)" + Reset)
    } else {
        fmt.Println(Green + "  [✔] Credentials check completed" + Reset)
    }

    fmt.Println(Green + "[✔] JavaScript analysis completed" + Reset)
    return nil
}

func fetchWaybackURLs(domain string) ([]string, error) {
	waybackURL := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey", domain)

	client := &http.Client{Timeout: 30 * time.Second}
	var urls []string

	for i := 0; i < MaxRetries; i++ {
		resp, err := client.Get(waybackURL)
		if err != nil {
			log.Printf(Yellow+"[!] Wayback request failed (attempt %d/%d): %v"+Reset, i+1, MaxRetries, err)
			time.Sleep(RetryDelay)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			log.Printf(Yellow+"[!] Wayback returned status %d (attempt %d/%d)"+Reset, resp.StatusCode, i+1, MaxRetries)
			time.Sleep(RetryDelay)
			continue
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				urls = append(urls, url)
			}
		}
		resp.Body.Close()
		break
	}

	return urls, nil
}

func fetchWaybackSensitive(domain, outputFile string) ([]string, error) {
	filter := `.*\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|git|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|env|apk|msi|dmg|tmp|crt|pem|key|pub|asc)$`
	api := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&collapse=urlkey&output=text&fl=original&filter=original:%s", domain, filter)

	resp, err := http.Get(api)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var matches []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		url := scanner.Text()
		if url != "" {
			matches = append(matches, url)
		}
	}

	if err := writeToFile(outputFile, matches); err != nil {
		return nil, err
	}

	return matches, scanner.Err()
}

/*func checkOpenRedirects(config *Config, allURLsFile string) error {
	fmt.Println(Yellow + "\n[+] Finding redirect parameters..." + Reset)

	redirectDir := filepath.Join(config.OutputDir, "redirect_checks")
	if err := os.MkdirAll(redirectDir, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create redirect directory: %w", err)
	}

	redirectParamsFile := filepath.Join(redirectDir, "redirect_params.txt")

	cmd := exec.Command(
		"bash", "-c",
		fmt.Sprintf("cat %s | gf redirect | uro | sort -u | tee %s",
			allURLsFile,
			redirectParamsFile),
	)
	if err := cmd.Run(); err != nil {
		fmt.Println(Yellow + "  [!] gf redirect failed, trying alternative methods..." + Reset)
	}

	params, err := readLines(redirectParamsFile)
	if err != nil {
		return fmt.Errorf("failed to read redirect params file: %w", err)
	}

	if len(params) == 0 {
		fmt.Println(Yellow + "  [i] No redirect parameters found with gf, checking common parameter names..." + Reset)

		commonParams := []string{
			"redirect=", "redir=", "url=", "return=", "returnTo=",
			"return_to=", "next=", "continue=", "destination=",
			"rurl=", "redirect_uri=", "redirect_url=", "callback=",
			"location=", "goto=", "exit=", "target=", "image_url=",
		}

		patternFile := filepath.Join(redirectDir, "redirect_patterns.txt")
		if err := writeToFile(patternFile, commonParams); err != nil {
			return fmt.Errorf("failed to create redirect patterns file: %w", err)
		}

		cmd = exec.Command(
			"bash", "-c",
			fmt.Sprintf("cat %s | grep -E -f %s | uro | sort -u | tee %s",
				allURLsFile,
				patternFile,
				redirectParamsFile),
		)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("failed to find redirect parameters with common names: %w", err)
		}

		params, err = readLines(redirectParamsFile)
		if err != nil {
			return fmt.Errorf("failed to read redirect params file: %w", err)
		}
	}

	if len(params) == 0 {
		fmt.Println(Yellow + "  [i] No redirect parameters found in any URLs" + Reset)
		return nil
	}

	fmt.Printf(Green+"  [✔] Found %d redirect parameters\n"+Reset, len(params))
	fmt.Printf(Green+"  [✔] Parameters saved to: %s\n"+Reset, redirectParamsFile)

	maxToShow := 5
	if len(params) < maxToShow {
		maxToShow = len(params)
	}
	fmt.Println(Cyan + "  [i] Sample redirect parameters:" + Reset)
	for i := 0; i < maxToShow; i++ {
		fmt.Printf("  - %s\n", params[i])
	}
	if len(params) > maxToShow {
		fmt.Printf(Cyan+"  [i] ... and %d more\n"+Reset, len(params)-maxToShow)
	}

	return nil
}*/

func checkOpenRedirects(config *Config, allURLsFile string) error {
    fmt.Println(Yellow + "\n[+] Finding redirect parameters..." + Reset)

    // 1. Verify input file exists and has content
    if _, err := os.Stat(allURLsFile); os.IsNotExist(err) {
        return fmt.Errorf("input file does not exist: %s", allURLsFile)
    }

    // 2. Create output directory
    redirectDir := filepath.Join(config.OutputDir, "redirect_checks")
    if err := os.MkdirAll(redirectDir, 0755); err != nil {
        return fmt.Errorf("failed to create redirect directory: %w", err)
    }

    redirectParamsFile := filepath.Join(redirectDir, "redirect_params.txt")

    // 3. Execute the gf/uro pipeline (same as manual command)
    if err := runGFUROPipeline(allURLsFile, redirectParamsFile); err != nil {
        fmt.Println(Yellow + "  [!] gf/uro pipeline failed, falling back to regex method..." + Reset)
        return findRedirectsWithRegex(allURLsFile, redirectParamsFile)
    }

    // 4. Read and process results
    matches, err := readLines(redirectParamsFile)
    if err != nil {
        return fmt.Errorf("failed to read results: %w", err)
    }

    // 5. Output results
    if len(matches) == 0 {
        fmt.Println(Yellow + "  [i] No redirect parameters found" + Reset)
        return nil
    }

    fmt.Printf(Green+"  [✔] Found %d redirect parameters\n"+Reset, len(matches))
    fmt.Printf(Green+"  [✔] Saved to: %s\n"+Reset, redirectParamsFile)

    printSampleResults(matches, 5)
    return nil
}

func runGFUROPipeline(inputFile, outputFile string) error {
    gfCmd := exec.Command("gf", "redirect")
    uroCmd := exec.Command("uro")
    sortCmd := exec.Command("sort", "-u")
    
    // Set up pipeline: gf -> uro -> sort -> tee
    input, err := os.Open(inputFile)
    if err != nil {
        return fmt.Errorf("failed to open input file: %w", err)
    }
    defer input.Close()

    output, err := os.Create(outputFile)
    if err != nil {
        return fmt.Errorf("failed to create output file: %w", err)
    }
    defer output.Close()

    // Chain the commands together
    gfCmd.Stdin = input
    uroCmd.Stdin, _ = gfCmd.StdoutPipe()
    sortCmd.Stdin, _ = uroCmd.StdoutPipe()
    sortCmd.Stdout = output

    // Start all commands
    if err := gfCmd.Start(); err != nil {
        return fmt.Errorf("gf failed to start: %w", err)
    }
    if err := uroCmd.Start(); err != nil {
        return fmt.Errorf("uro failed to start: %w", err)
    }
    if err := sortCmd.Start(); err != nil {
        return fmt.Errorf("sort failed to start: %w", err)
    }

    // Wait for commands to complete
    if err := gfCmd.Wait(); err != nil {
        return fmt.Errorf("gf failed: %w", err)
    }
    if err := uroCmd.Wait(); err != nil {
        return fmt.Errorf("uro failed: %w", err)
    }
    if err := sortCmd.Wait(); err != nil {
        return fmt.Errorf("sort failed: %w", err)
    }

    return nil
}

func findRedirectsWithRegex(inputFile, outputFile string) error {
    urls, err := readLines(inputFile)
    if err != nil {
        return fmt.Errorf("failed to read input file: %w", err)
    }

    var matches []string
    paramPattern := regexp.MustCompile(`(?i)(\?|&)(redirect|redir|url|return|next|continue|dest|rurl|uri|callback|location|goto|exit|target|image_url|file|download|path|include|load|doc|document|view|retrieve|data)\b`)

    for _, url := range urls {
        if paramPattern.MatchString(url) {
            matches = append(matches, url)
        }
    }

    matches = removeDuplicateMatches(matches)
    return writeToFile(outputFile, matches)
}

func removeDuplicateMatches(matches []string) []string {
    seen := make(map[string]bool)
    var result []string
    for _, match := range matches {
        if !seen[match] {
            seen[match] = true
            result = append(result, match)
        }
    }
    return result
}

func printSampleResults(results []string, max int) {
    if len(results) == 0 {
        return
    }
    if len(results) < max {
        max = len(results)
    }
    fmt.Println(Cyan + "  [i] Sample redirect parameters:" + Reset)
    for i := 0; i < max; i++ {
        fmt.Printf("  - %s\n", results[i])
    }
    if len(results) > max {
        fmt.Printf(Cyan+"  [i] ... and %d more\n"+Reset, len(results)-max)
    }
}


func runDirectoryBruteForce(config *Config, domain string) error {
    startTime := time.Now() // Capture start time
    fmt.Println("\n[+] Running directory brute-force...")
    
    outputFile := filepath.Join(config.OutputDir, "dirsearch_results.txt")
    interestingFile := filepath.Join(config.OutputDir, "dirsearch_interesting.txt")

    extensions := "conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js.,.json"

    cmd := exec.Command(
        "dirsearch",
        "-u", domain,
        "-e", extensions,
        "-O", "plain",
        "-o", outputFile,
        "-t", fmt.Sprintf("%d", config.Threads),
        "--full-url",
        "--no-color",
        // Removed -q to see real-time progress but keep output clean
    )

    // Create multi-writer to capture output and show progress
    var out bytes.Buffer
    mw := io.MultiWriter(os.Stdout, &out)

    cmd.Stdout = mw
    cmd.Stderr = os.Stderr

    if err := cmd.Run(); err != nil {
        return fmt.Errorf("dirsearch failed: %v", err)
    }

    // Calculate and print duration
    duration := time.Since(startTime)
    fmt.Printf("\n[+] Scan completed in %v\n", duration.Round(time.Second))

    // Process results
    results, err := readLines(outputFile)
    if err != nil {
        return fmt.Errorf("failed to read results: %v", err)
    }

    if len(results) == 0 {
        fmt.Println("[!] No directories/files found")
        return nil
    }
    
    // Filter interesting results (200, 301, 302, 403, etc.)
    var interesting []string
    interestingStatusCodes := map[string]bool{
        "200": true, // OK
        "301": true, // Moved Permanently
        "302": true, // Found (Moved Temporarily)
        "403": true, // Forbidden (often indicates protected resources)
        "401": true, // Unauthorized (often indicates auth required)
        "500": true, // Server Error (might indicate interesting behavior)
    }
    
    for _, line := range results {
        // Extract status code from line (dirsearch format: [STATUS] PATH [SIZE] [REDIRECT])
        if matches := regexp.MustCompile(`\[(\d{3})\]`).FindStringSubmatch(line); len(matches) > 1 {
            statusCode := matches[1]
            if interestingStatusCodes[statusCode] {
                interesting = append(interesting, line)
            }
        }
    }
    
    if len(interesting) > 0 {
        if err := writeToFile(interestingFile, interesting); err != nil {
            return fmt.Errorf("failed to save interesting dirsearch results: %v", err)
        }
        fmt.Printf(Green+"  [✔] Found %d interesting directories/files\n"+Reset, len(interesting))
        fmt.Printf(Green+"  [✔] Saved to: %s\n"+Reset, interestingFile)
        
        // Print summary of interesting findings
        fmt.Println(Cyan + "\n  [i] Interesting findings summary:" + Reset)
        maxToShow := 10
        if len(interesting) < maxToShow {
            maxToShow = len(interesting)
        }
        for i := 0; i < maxToShow; i++ {
            fmt.Printf("    - %s\n", interesting[i])
        }
        if len(interesting) > maxToShow {
            fmt.Printf(Cyan+"    ... and %d more\n"+Reset, len(interesting)-maxToShow)
        }
    } else {
        fmt.Println(Yellow + "  [!] No interesting directories/files found" + Reset)
    }
    
    return nil
}


func writeToFile(filename string, lines []string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func readLines(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, strings.TrimSpace(scanner.Text()))
	}
	return lines, scanner.Err()
}

func removeDuplicates(lines []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, line := range lines {
		if line != "" && !seen[line] {
			seen[line] = true
			result = append(result, line)
		}
	}
	return result
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
