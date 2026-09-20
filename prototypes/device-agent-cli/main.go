// Prototype only: this explores Device-agent UX, not production architecture.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type deviceState struct {
	enrolled      bool
	serverName    string
	serverAddress string
	fingerprint   string
	policy        string
	running       bool
	paused        bool
	securityLock  bool
	status        string
	connections   int
	carriedMB     int
	earningsSats  int
	update        string
}

func initialState() deviceState {
	return deviceState{
		status: "Not enrolled",
		update: "Current (prototype 0.1.0)",
	}
}

func main() {
	in := bufio.NewReader(os.Stdin)
	state := initialState()

	fmt.Println("Boltlane Device agent - UX prototype")
	fmt.Println("Nothing in this demo connects to a network or writes to disk.")
	fmt.Println()
	fmt.Println("Question: can setup establish informed trust while daily operation stays quiet,")
	fmt.Println("obvious, and safe on a computer that someone is actively using?")

	for {
		printState(state)
		printActions(state)
		choice := prompt(in, "Choose an action")

		switch choice {
		case "1":
			if !state.enrolled {
				state = enroll(in, state)
			} else {
				state = simulateTraffic(state)
			}
		case "2":
			if !state.enrolled {
				state = headlessPreview(in, state)
			} else if state.securityLock {
				fmt.Println("\nSharing cannot resume after an identity mismatch. Forget this Server and enroll again.")
			} else if state.paused {
				state.paused = false
				state.running = true
				state.status = "Available"
				fmt.Println("\nSharing resumed. New connections may now use this Device.")
			} else {
				state.paused = true
				state.running = false
				state.status = "Paused by you"
				state.connections = 0
				fmt.Println("\nPaused. Existing connections were drained; no new traffic is accepted.")
			}
		case "3":
			if state.enrolled {
				if state.securityLock {
					fmt.Println("\nLimits may not be changed while this Device is security-locked.")
				} else {
					state = changeLimits(in, state)
				}
			}
		case "4":
			if state.enrolled {
				state = updateAgent(in, state)
			}
		case "5":
			if state.enrolled {
				state = identityMismatch(in, state)
			}
		case "6":
			if state.enrolled {
				state = uninstall(in, state)
			}
		case "q", "quit", "exit":
			fmt.Println("\nPrototype closed. No changes were saved.")
			return
		default:
			fmt.Println("\nThat action is not available.")
		}
	}
}

func printState(s deviceState) {
	fmt.Println("\n------------------------------------------------------------")
	if !s.enrolled {
		fmt.Println("DEVICE   This computer")
		fmt.Printf("STATUS   %s\n", s.status)
		fmt.Println("SERVER   None")
		fmt.Println("POLICY   Deny all traffic")
		return
	}

	sharing := "Off"
	if s.running && !s.paused {
		sharing = "On"
	}
	fmt.Printf("STATUS   %s       SHARING  %s\n", s.status, sharing)
	fmt.Printf("SERVER   %s (%s)\n", s.serverName, s.serverAddress)
	fmt.Printf("PIN      %s\n", s.fingerprint)
	fmt.Printf("POLICY   %s\n", s.policy)
	fmt.Printf("NOW      %d active connection(s)\n", s.connections)
	fmt.Printf("TODAY    %d MB carried | %d sats estimated\n", s.carriedMB, s.earningsSats)
	fmt.Printf("UPDATE   %s\n", s.update)
}

func printActions(s deviceState) {
	fmt.Println("------------------------------------------------------------")
	if !s.enrolled {
		fmt.Println("1  Enroll with an invitation")
		fmt.Println("2  Preview headless enrollment")
		fmt.Println("q  Quit")
		return
	}

	fmt.Println("1  Simulate ten minutes of traffic")
	if s.securityLock {
		fmt.Println("2  Resume unavailable; re-enrollment required")
	} else if s.paused {
		fmt.Println("2  Resume sharing")
	} else {
		fmt.Println("2  Pause sharing")
	}
	fmt.Println("3  Change work-computer limits")
	fmt.Println("4  Preview an update")
	fmt.Println("5  Simulate Server identity mismatch")
	fmt.Println("6  Uninstall / forget this Server")
	fmt.Println("q  Quit")
}

func enroll(in *bufio.Reader, s deviceState) deviceState {
	fmt.Println("\nInvitation inspected")
	fmt.Println("  Server:      CitePulse dogfood")
	fmt.Println("  Address:     proxy.citepulse.test:443")
	fmt.Println("  Identity:    BOLT-LANE-7K3P-9Q2F")
	fmt.Println("  Invitation:  expires in 12 minutes; usable once")
	fmt.Println()
	fmt.Println("Confirm this identity with the person who invited you.")
	fmt.Println("The address and TLS certificate may change later; this identity may not.")
	if !confirm(in, "Pin this Server identity? [y/N]") {
		fmt.Println("\nEnrollment cancelled. This Device still denies all traffic.")
		return s
	}

	fmt.Println("\nChoose what this work computer may carry:")
	fmt.Println("1  Web fetches only; 5 Mbps; 2 connections; pause while on battery")
	fmt.Println("2  Deny all for now; configure before sharing")
	policyChoice := prompt(in, "Policy")
	policy := "Deny all traffic (setup incomplete)"
	running := false
	status := "Policy approval required"
	if policyChoice == "1" {
		policy = "Web fetches | 5 Mbps | 2 connections | pause on battery"
		running = true
		status = "Available"
	}

	fmt.Println("\nDevice key created in the operating-system key store.")
	fmt.Println("Enrollment complete. Boltlane will run in the background after sign-in.")
	s.enrolled = true
	s.serverName = "CitePulse dogfood"
	s.serverAddress = "proxy.citepulse.test:443"
	s.fingerprint = "BOLT-LANE-7K3P-9Q2F"
	s.policy = policy
	s.running = running
	s.status = status
	return s
}

func headlessPreview(in *bufio.Reader, s deviceState) deviceState {
	fmt.Println("\nRaspberry Pi / headless preview")
	fmt.Println("  boltlane enroll --invite <token> --expect-server BOLT-LANE-7K3P-9Q2F")
	fmt.Println()
	fmt.Println("The expected fingerprint is mandatory in non-interactive mode.")
	fmt.Println("The key would be stored in a service-account-only file because no OS key store was found.")
	fmt.Println("That weaker protection is reported; it is never selected silently.")
	prompt(in, "Press Enter to return")
	return s
}

func simulateTraffic(s deviceState) deviceState {
	if !s.running || s.paused {
		fmt.Println("\nNo traffic carried: sharing is paused or policy approval is incomplete.")
		return s
	}
	s.connections = 1
	s.carriedMB += 84
	s.earningsSats += 3
	fmt.Println("\nCarried 84 MB of permitted web-fetch traffic. No browsing contents were stored.")
	return s
}

func changeLimits(in *bufio.Reader, s deviceState) deviceState {
	fmt.Println("\nWork-computer presets")
	fmt.Println("1  Quiet: 2 Mbps, 1 connection, pause on battery")
	fmt.Println("2  Balanced: 5 Mbps, 2 connections, pause on battery")
	fmt.Println("3  Paused: deny new traffic")
	switch prompt(in, "Preset") {
	case "1":
		s.policy = "Web fetches | 2 Mbps | 1 connection | pause on battery"
		s.running = true
		s.paused = false
		s.status = "Available (quiet limits)"
	case "2":
		s.policy = "Web fetches | 5 Mbps | 2 connections | pause on battery"
		s.running = true
		s.paused = false
		s.status = "Available"
	case "3":
		s.running = false
		s.paused = true
		s.connections = 0
		s.status = "Paused by you"
	default:
		fmt.Println("\nLimits unchanged.")
	}
	return s
}

func updateAgent(in *bufio.Reader, s deviceState) deviceState {
	s.update = "0.2.0 ready; requires a brief restart"
	fmt.Println("\nUpdate 0.2.0 is verified and ready.")
	fmt.Println("Installing now drains active connections, restarts the background service,")
	fmt.Println("then reconnects only if the pinned Server identity still matches.")
	if confirm(in, "Install now? [y/N]") {
		s.connections = 0
		s.update = "Current (prototype 0.2.0)"
		fmt.Println("\nUpdated and reconnected. Your policy and Server pin were preserved.")
	} else {
		fmt.Println("\nUpdate deferred. The tray/status view will keep showing it as ready.")
	}
	return s
}

func identityMismatch(in *bufio.Reader, s deviceState) deviceState {
	s.running = false
	s.paused = true
	s.securityLock = true
	s.connections = 0
	s.status = "Stopped: Server identity changed"
	fmt.Println("\nSAFETY STOP")
	fmt.Println("The Server at proxy.citepulse.test presented a different identity.")
	fmt.Println("Boltlane will not reconnect automatically or let a certificate override your pin.")
	fmt.Println("Ask the Operator to verify the change. Re-enrollment requires a new invitation.")
	prompt(in, "Press Enter to acknowledge")
	return s
}

func uninstall(in *bufio.Reader, s deviceState) deviceState {
	fmt.Println("\nUninstall preview")
	fmt.Println("This will stop traffic, ask the Server to revoke this Device, and remove")
	fmt.Println("the Server pin, Device key, credential, and reconnect state.")
	fmt.Println("Reusable policy profiles and exported receipts may be kept.")
	if !confirm(in, "Forget the Server and uninstall? [y/N]") {
		fmt.Println("\nUninstall cancelled.")
		return s
	}

	fmt.Println("\nRemote revocation confirmed. Local credentials removed.")
	fmt.Println("The package manager may now remove the binary and background service.")
	return initialState()
}

func prompt(in *bufio.Reader, label string) string {
	fmt.Printf("%s: ", label)
	value, _ := in.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(value))
}

func confirm(in *bufio.Reader, label string) bool {
	answer := prompt(in, label)
	return answer == "y" || answer == "yes"
}
