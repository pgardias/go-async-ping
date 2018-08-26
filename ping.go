package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"github.com/joeguo/tldextract"
	"io"
)

// Optionally user-defined parameters
var INPUT_CSV_FILE string // Name of input csv file
var MAX_PROCESSES int     // Max number of concurrent goroutines
var MAX_SEMAPHORES int    // Max number of semaphores (goroutine locks)
var URL_CHUNK_SIZE int    // Maximum urls to process at during runtime (for small set testing purposes)
var CONN_TIMEOUT int      // Timeout for client, transport, handshake, and header read
var REQUEST_TIMEOUT int
var IDLE_CONN_TIMEOUT int
var RESP_HEADER_TIMEOUT int
var TLS_HANDSHAKE_TIMEOUT int

// Other connection and request parameters
var MAX_REDIRECTS = 50   // Maximum number of redirect hops to follow to prevent redirect loops
var KEEP_ALIVE_TIME = 10 // Packet keep alive time

// Detected website column
var URL_COL int

// Name of tldextract cache file
var tldextractCache = "tld.cache"

// Stored header of input csv to write to output csv
var savedHeader []string

// List of top 500 hosts for cross referencing purposes
var hosts []string

// HTTP Response custom type for piping to output
type HttpResponse struct {
	data     []string // Row data from csv
	response *http.Response
	err      error
	time     float64
}

// Thread safe int64 dictionary
type SafeCounterInt64 struct {
	val map[string]int64
	mux sync.Mutex
}

// Thread safe float64 dictionary
type SafeCounterFloat64 struct {
	val map[string]float64
	mux sync.Mutex
}

// Thread safe counter declarations, expandable through key references below
var uintCounter = SafeCounterInt64{val: make(map[string]int64)}
var floatCounter = SafeCounterFloat64{val: make(map[string]float64)}

// Keys for counter reference
const (
	TOTAL_CONN_TIME string = "TOTAL_CONN_TIME"
	FAILED_URL      string = "FAILED_URL"
)

// Statistical global variables
var INIT_RUNTIME time.Time
var TOTAL_URL uint64 = 0
var VALIDATED_URL uint64 = 0
var REDIRECTED_URL uint64 = 0

// Thread safe data type helpers
func (ctr *SafeCounterInt64) Increment(key string) {
	ctr.mux.Lock()
	ctr.val[key]++
	ctr.mux.Unlock()
}

func (ctr *SafeCounterInt64) Value(key string) int64 {
	ctr.mux.Lock()
	defer ctr.mux.Unlock()
	return ctr.val[key]
}

func (ctr *SafeCounterFloat64) Add(key string, amount float64) {
	ctr.mux.Lock()
	ctr.val[key] += amount
	ctr.mux.Unlock()
}

func (ctr *SafeCounterFloat64) Value(key string) float64 {
	ctr.mux.Lock()
	defer ctr.mux.Unlock()
	return ctr.val[key]
}

/*
 * Return a standard formatted tldextract instance of url generated
 * from an tldextract result instance.
 */
func formatUrl(extract *tldextract.TLDExtract, url string) string {
	result := extract.Extract(url)
	return result.Root + "." + result.Tld
}

/*
 * Grabs hosts from hosts file in runtime directory and reads
 * to memory.
 */
func getHosts() {
	extract, err := tldextract.New(tldextractCache, false)
	if err != nil {
		log.Fatal(err)
	}
	f, err := os.Open("hosts")
	defer f.Close()
	if err != nil {
		log.Fatal("Unable to get hosts from \"hosts\":", err)
	}
	scanner := bufio.NewScanner(f)
	scanner.Split(bufio.ScanLines)
	for scanner.Scan() {
		// Reformatting host to ensure matching in future comparison
		text := scanner.Text()
		hosts = append(hosts, formatUrl(extract, text))
	}
}

/*
 * For informational purposes, gets goroutine ID from stack information.
 * Returns goroutine ID.
 */
func getGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("Goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

/*
 * Takes a url and returns iy with valid schema, defaulting to HTTP.
 */
func validateUrlSchema(url string) string {
	// Check if either schema exists in url
	if !strings.Contains(url, "http://") && !(strings.Contains(url, "https://")) {
		// In case of missing schema apply HTTP by default
		return "http://" + url
	} else {
		return url
	}
}

/*
 * Takes results array and handles the content by determining if the
 * response status code corresponds to a redirect code and whether the
 * redirect is to the same domain and different index location (i.e.
 * redirecting "google.com" to "google.com/"). Uses the list of hosts
 * found in "hosts" to identify if url redirects to a domain hosting
 * provider, and if so notes this down to write to the output file. This
 * function relies on tldextract and it's corresponding cache file to
 * format urls for comparison and will fail if tldextract is unable to
 * setup properly.
 */
func output(results []*HttpResponse) {
	// Create tldextract instance
	extract, err := tldextract.New(tldextractCache, false)
	if err != nil {
		log.Fatal(err)
	}

	// Lambda function definition for generic redirect output handling, used in switch case below
	redirect := func(result *HttpResponse, writer *csv.Writer) {

		// Get redirect location from header and reconstruct
		rUrl, _ := result.response.Location()
		redirectUrl := rUrl.String()

		// Get url from result data
		url := result.data[URL_COL]
		fmt.Printf("\t[ %s ] %s redirects to %s\n", result.response.Status, url, redirectUrl)

		// Exclude inter-root domain redirects
		if extract.Extract(url).Root != extract.Extract(redirectUrl).Root && url != "" {
			// Concatenate data for csv writing
			output := append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status, redirectUrl)

			// Cross referencing host providers
		hosts:
			for _, host := range hosts {
				/*
				 * The following tldextract usage and re-assembly is necessary
				 * due to the nuances in how tldextract functions when attempting
				 * to discern from root and tld. For our purposes, this is necessary
				 * to prevent missed matches, although domains should be treated
				 * similarly if they are to be matched in the first place. This
				 * same process if applied to hosts when first fetched into memory.
				 */
				fmtUrl := formatUrl(extract, redirectUrl)

				// If correctly identified a host provider, note this for output
				if fmtUrl == host {
					note := fmt.Sprintf("Redirects to %s, which is a host domain", host)
					output = append(output, note)
					break hosts
				}
			}

			// Write output to csv
			writer.Write(output)
			REDIRECTED_URL++
		} else {
			note := fmt.Sprintf("%s was identified to be on the same root as %s", url, redirectUrl)
			writer.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status, redirectUrl, note))
		}
	}

	// Open or create output file
	f, err := os.OpenFile("output_"+INPUT_CSV_FILE, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatal(err)
	}

	// Init output csv instance
	csvWriter := csv.NewWriter(bufio.NewWriter(f))

	// Construct and write output file header
	csvWriter.Write(append(savedHeader, "Status Code", "Status", "Redirect Website", "Notes"))

	// Iterate over results, calling redirect() on appropriate redirect codes to write to csv
	for i, result := range results {

		if result.err != nil { // Handle errors by adding them to the notes
			csvWriter.Write(append(result.data, "ERROR", "", "", "ERROR: "+result.err.Error()))
		} else { // Ignore empty responses
			fmt.Printf("[ %d ] %s status code: %s\n", i, result.data[URL_COL], result.response.Status)

			// Status code-based switch case
			switch result.response.StatusCode {
			case http.StatusOK: // 200 OK
				VALIDATED_URL++
				csvWriter.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status))
			case http.StatusMultipleChoices: // 300 Multiple Choices
				redirect(result, csvWriter)
			case http.StatusMovedPermanently: // 301 Moved Permanently
				redirect(result, csvWriter)
			case http.StatusFound: // 302 Found
				redirect(result, csvWriter)
			case http.StatusSeeOther: // 303 See Other
				redirect(result, csvWriter)
			case http.StatusTemporaryRedirect: // 307 Temporary Redirect
				redirect(result, csvWriter)
			case http.StatusPermanentRedirect: // 308 Permanent Redirect
				redirect(result, csvWriter)
			case http.StatusBadRequest: // 400 Bad Request
				// Note that this response may indicate that there is a problem with the request that was sent by the program
				csvWriter.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status, "", "Server was not able to understand request, may indicate a failure in request construction process"))
			case http.StatusNotFound: // 404 Not Found
				// Note that the page was not found
				csvWriter.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status, "", "Page not found"))
			case http.StatusServiceUnavailable: // 503 Service Unavailable
				// Note of implied service unavailability for a period of time
				if result.response.Status == strconv.Itoa(http.StatusServiceUnavailable) + " Service Temporarily Unavailable" {
					csvWriter.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status, "", fmt.Sprintf("Implied that service is temporary unavailable, retrying after some delay may resolve this")))
				} else {
					csvWriter.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status))
				}
			default: // Handle all other status codes that do not have a specific case
				csvWriter.Write(append(result.data, strconv.Itoa(result.response.StatusCode), result.response.Status))
			}
		}
	}
	f.Close()

	// Print out statistical results
	fmt.Printf("\n\nURLs checked:\t\t\t%d\nValidated URLs:\t\t\t%d\nRedirected URLs:\t\t%d\nAverage fetch "+
		"time:\t\t%.2f s\n", TOTAL_URL, VALIDATED_URL, REDIRECTED_URL, floatCounter.Value(TOTAL_CONN_TIME)/float64(TOTAL_URL))
	fmt.Printf("Total runtime:\t\t\t%.2f s\n", time.Since(INIT_RUNTIME).Seconds())
}

/*
 * Handles channel creation/monitoring and increments WaitGroup to ensure
 * that goroutines are able to terminate appropriately. Created goroutines
 * to send request asynchronously through a pre-built client. Uses context
 * for goroutine timeouts. Goroutine lambda is explained further in-depth
 * below, above function declaration.
 *
 * Resources referenced:
 * https://matt.aimonetti.net/posts/2012/11/27/real-life-concurrency-in-go/
 * https://gist.github.com/mattetti/3798173
 */
func asyncHttpGets(urls [][]string) []*HttpResponse {
	// Semaphores channel to limit max goroutines
	semaphores := make(chan struct{}, MAX_SEMAPHORES)

	// Generic channel for piping to select cases
	channel := make(chan *HttpResponse, len(urls))

	// Results channel for piping out status from select case
	results := make(chan *HttpResponse, len(urls))

	// Init WaitGroup instance
	var wg sync.WaitGroup

	// Increment WaitGroup appropriately
	wg.Add(len(urls))

	// Construct client with appropriate timeouts in dialer and transport
	var client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			Dial: (&net.Dialer{
				Timeout:   time.Duration(REQUEST_TIMEOUT) * time.Second, // Timeout for establishing connection
				KeepAlive: time.Duration(KEEP_ALIVE_TIME) * time.Second,
			}).Dial,
			TLSHandshakeTimeout:   time.Duration(TLS_HANDSHAKE_TIMEOUT) * time.Second, // Timeout for TLS handshake
			IdleConnTimeout:       time.Duration(IDLE_CONN_TIMEOUT) * time.Second,     // Timeout for idle connection
			ResponseHeaderTimeout: time.Duration(RESP_HEADER_TIMEOUT) * time.Second,   // Timeout for reading response header
			DisableKeepAlives:     true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Prevent automatic redirect following, handled manually below
		},
		Timeout: time.Duration(CONN_TIMEOUT) * time.Second,
	}

	// Goroutine creation
	for i, j := range urls {
		// Prevent iteration variable reuse by local scope variable declaration
		data := j
		index := i

		// Init context for thread timeout signal
		ctx, _ := context.WithTimeout(context.Background(), time.Duration(CONN_TIMEOUT)*time.Second)

		// Goroutines must acquire semaphore before being created
		semaphores <- struct{}{}

		/*
		 * Creates request and pipes response through the default channel to the
		 * awaiting select statement which handles the context timeout. Redirect
		 * handling is done through catching a UseLastResponse error returned from
		 * the client's CheckRedirect lambda function.
		 */
		go func(data []string, index int, ctx context.Context, wg *sync.WaitGroup) {
			// Called on exit condition
			release := func() { <-semaphores; wg.Done() }
			//release := func() { <-semaphores; wg.Done(); fmt.Printf("Released semaphore for GID %d, %d/%d used ( %s )\n", getGID(), len(semaphores), cap(semaphores), url) }
			defer release()

			// Validate url
			url := validateUrlSchema(data[URL_COL])

			// Construct request
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				fmt.Println(err)
				return
			}
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36")

			//fmt.Printf("Acquired semaphore for GID %d, %d/%d used [ %s ]\n", getGID(), len(semaphores), cap(semaphores), url)
			start := time.Now()

			// Send request
			resp, err := client.Do(req)

			// Response error handling
			if err != nil && err != http.ErrUseLastResponse {
				fmt.Println(err)
				channel <- &HttpResponse{data, nil, err, time.Since(start).Seconds()}
			} else if err == http.ErrUseLastResponse { // Handle redirect
				nextResp := resp

				// Follow the redirects up until MAX_REDIRECTS
			redirect:
				for i := 1; ; i++ {

					// Modify request
					req.URL, _ = nextResp.Location()

					// Send modified request with new url to follow
					nextResp, err := client.Do(req)
					if err != nil {
						fmt.Println(err)
					}

					// Reached final url without redirect response
					if nextResp.StatusCode == http.StatusOK {
						channel <- &HttpResponse{data, nextResp, err, time.Since(start).Seconds()}
					}

					// Break condition
					if i == MAX_REDIRECTS {
						channel <- &HttpResponse{data, nil, err, time.Since(start).Seconds()}
						fmt.Printf("Maximum redirects (%d) reached for %s", MAX_REDIRECTS, url)
						break redirect
					}
				}
			} else {
				defer resp.Body.Close()
				channel <- &HttpResponse{data, resp, err, time.Since(start).Seconds()}
			}

			// Timeout implementation through switch waits
			select {
			case r := <-channel:
				if r.response != nil && r.err == nil {
					floatCounter.Add(TOTAL_CONN_TIME, r.time)
					fmt.Printf("SUCCESS [ %d ]: %s was fetched with status code %d ( %.2f s )\n", index, url, r.response.StatusCode, r.time)
					results <- r
					return
				} else {
					uintCounter.Increment(FAILED_URL)
					fmt.Printf("FAILURE [ %d ]: %s was not able to be fetched ( %.2f s )\n", index, url, r.time)
					results <- r
					return
				}
			case <-ctx.Done():
				fmt.Printf("TIMEOUT [ %d ]: no response from %s ( %.2f s )\n", index, url, time.Since(start).Seconds())
				return
			}
		}(data, index, ctx, &wg)
	}

	// Wait on WaitGroup before acquiring remaining semaphores and closing channels
	wg.Wait()

	// Grab all semaphores to make sure they are all released
	for i := 0; i < cap(semaphores); i++ {
		semaphores <- struct{}{}
	}

	// Close channels
	close(semaphores)
	close(channel)
	close(results)

	// Read channel items into results
	res := []*HttpResponse{}
	for result := range results {
		res = append(res, result)
	}
	return res
}

/*
 * Handles CLAs and sets runtime variables.
 */
func initialize() {
	// Set runtime start
	INIT_RUNTIME = time.Now()

	// Handle flags
	flag.StringVar(&INPUT_CSV_FILE, "input", "accounts.csv", "Name of input csv file")
	flag.IntVar(&MAX_PROCESSES, "maxprocs", 750, "Maximum allowed concurrent goroutines")
	flag.IntVar(&CONN_TIMEOUT, "timeout", 10, "HTTP request timeout")
	flag.IntVar(&URL_CHUNK_SIZE, "maxurl", 0xffffffff, "Number of urls to process")
	flag.Parse()

	// Set redundant globals
	MAX_SEMAPHORES = MAX_PROCESSES
	REQUEST_TIMEOUT = CONN_TIMEOUT
	IDLE_CONN_TIMEOUT = CONN_TIMEOUT
	RESP_HEADER_TIMEOUT = CONN_TIMEOUT
	TLS_HANDSHAKE_TIMEOUT = CONN_TIMEOUT

	// Terminate on unknown flags
	if len(flag.Args()) != 0 {
		log.Fatal("Tailing flags detected, terminating. Use --help or -h for info on correct flag usage.")
	}

	// Set maximum goroutines
	runtime.GOMAXPROCS(MAX_PROCESSES)
}

/*
 * Initializes runtime configuration, handles getting required information such
 * as domain host data, Salesforce reports, etc. Handles headers and footers
 * appropriately, depending on SFDC_MODE and HEADER_EXISTS flags. Reads url data
 * and initalizes goroutine spawner with the input data. Wraps up runtime by
 * calling output handler.
 */
func main() {
	// Init function
	initialize()

	// Read input file
	f, err := os.OpenFile(INPUT_CSV_FILE, os.O_RDONLY, 0666)
	if err != nil {
		if err == os.ErrNotExist {
			fmt.Println("File not found: ", err)
		} else {
			fmt.Println("Unable to read input csv file. Use --help or -h for info on correct flag usage.", err)
			return
		}
	}

	// Init input csv reader instance
	csvReader := csv.NewReader(bufio.NewReader(f))

	// Save header for future copying and auto-detect website column
	savedHeader, _ = csvReader.Read()

	// Range over header to find website column
	for i, header := range savedHeader {
		if strings.EqualFold(header, "Website") { // Ignore case comparison
			URL_COL = i
		}
	}

	// Get domain hosting providers list
	getHosts()

	// Input file data 2D array containing urls
	var urls [][]string

	// Grab row data into memory
	for i := 0; i < URL_CHUNK_SIZE; i++ {
		TOTAL_URL++
		row, err := csvReader.Read()

		// End of file and error handling
		if err == io.EOF {
			break
		} else if err != nil {
			fmt.Println(err)
		} else {
			urls = append(urls, row)
		}
	}
	f.Close()

	// Call goroutine spawner, passing in csv data to process
	results := asyncHttpGets(urls)

	// Handle output
	output(results)
}
