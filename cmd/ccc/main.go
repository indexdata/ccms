package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/chzyer/readline"
	"github.com/essentialkaos/ek/v13/pager"
	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/internal/eout"
	"github.com/indexdata/ccms/internal/global"
	"github.com/spf13/cobra"
)

var colorMode string
var devMode bool

var colorInitialized bool

var option struct {
	Host          string
	Port          string
	NoTLS         bool
	TLSSkipVerify bool
	Version       bool
	Timing        bool
}

func main() {
	colorMode = os.Getenv("CCC_COLOR")
	cccMain()
}

func cccMain() {
	eout.Init(global.ClientProgram)
	run()
}

func errorExit(err error) {
	if !colorInitialized {
		eout.NeverColor()
	}
	eout.Error("%s", err)
	os.Exit(1)
}

func run() {
	if len(os.Args) > 1 {
		if os.Args[1] == "help" {
			printHelp()
		}
		if os.Args[1][0] != '-' {
			fmt.Fprintf(os.Stderr, "%s: unknown argument: %s\n", global.ClientProgram, os.Args[1])
			os.Exit(1)
		}
	}
	var rootCmd = &cobra.Command{
		Use:                global.ClientProgram,
		SilenceErrors:      true,
		SilenceUsage:       true,
		DisableSuggestions: true,
		Run: func(cmd *cobra.Command, args []string) {
			if err := runClient(); err != nil {
				errorExit(err)
			}
		},
	}
	rootCmd.SetHelpFunc(help)
	// redefine help without -h, so we can use it for --port
	var helpFlag bool
	rootCmd.PersistentFlags().BoolVarP(&helpFlag, "help", "", false, "Help for ccc")
	_ = hostFlag(rootCmd, &option.Host)
	_ = portFlag(rootCmd, &option.Port)
	_ = noTLSFlag(rootCmd, &option.NoTLS)
	_ = skipVerifyFlag(rootCmd, &option.TLSSkipVerify)
	_ = versionFlag(rootCmd, &option.Version)
	_ = timingFlag(rootCmd, &option.Timing)
	if err := rootCmd.Execute(); err != nil {
		errorExit(err)
	}
}

func runClient() error {
	if option.Version {
		fmt.Printf("%s %s\n", global.ClientProgram, global.Version)
		return nil
	}

	pager.AllowEnv = true
	eout.Interactive()
	fmt.Printf("%s (%s) client for CCMS\n", global.ClientProgram, global.Version)
	if option.NoTLS && option.Host != "127.0.0.1" {
		eout.Warning("disabling TLS (insecure)")
	}
	fmt.Printf("Type \"help\" for help.\n")

	home := os.Getenv("HOME")
	rl, err := readline.NewEx(&readline.Config{
		Prompt:       "=> ",
		HistoryFile:  filepath.Join(home, ".ccc_history"),
		AutoComplete: completer,
	})
	if err != nil {
		return err
	}
	defer rl.Close()

	client := &ccms.Client{
		Host:          option.Host,
		Port:          option.Port,
		User:          "nemo",
		Password:      "testpass",
		NoTLS:         option.NoTLS,
		TLSSkipVerify: option.TLSSkipVerify,
	}
	//if _, err = client.Send("ping"); err != nil {
	//        errorExit(err)
	//}
	for {
		rline, err := rl.Readline()
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			continue
		}
		line := strings.TrimSpace(rline)
		if line == "" {
			continue
		}
		if line[0] == '\\' {
			switch line[0:2] {
			case "\\h":
			case "\\q":
			default:
				eout.Error("unknown command: %s", line)
				continue
			}
		}
		if line == "help" {
			fmt.Printf("" +
				"Type:  \\h for help with SQL commands\n" +
				"       \\q to quit\n")
			continue
		}
		if strings.HasPrefix(line, "\\h") {
			if line == "\\h" {
				line = "info;"
			} else {
				line = "info '" + helpCommand(line) + "';"
			}
		}
		if line == "\\q" {
			break
		}
		l := strings.Join(strings.Fields(line), "")
		if l == "quit" || l == "quit;" || l == "exit" || l == "exit;" {
			break
		}
		startTime := time.Now()
		resp, err := client.Send(line)
		if err != nil {
			eout.Error("%v", err)
			continue
		}
		elapsedTime := time.Since(startTime).Seconds()
		elapsedTimeStr := fmt.Sprintf("[%.4f s]", elapsedTime)

		if err = pager.Setup(); err != nil {
			return err
		}
		i := 0
		for result := range resp.Results() {
			if i > 0 {
				fmt.Printf("\n")
			}
			if result.Status() == "error" {
				eout.Error("error: %s", result.Message())
				continue
			}
			header := true
			if result.Status() == "info" {
				header = false
			}
			if result.Status() == "ping" {
				continue
			}

			switch result.Status() {
			case "info":
				fallthrough
			case "show":
				fallthrough
			case "select":
				w := tabwriter.NewWriter(os.Stdout, 1, 1, 2, ' ', 0)
				if header {
					fields := result.Fields()
					for j := range fields {
						if j != 0 {
							fmt.Fprint(w, "\t")
						}
						fmt.Fprint(w, fields[j].Name())
					}
					fmt.Fprint(w, "\n")
				}
				for data := range result.Data() {
					values := data.Values()
					for j := range values {
						if j != 0 {
							fmt.Fprint(w, "\t")
						}
						fmt.Fprint(w, values[j])
					}
					fmt.Fprint(w, "\n")
				}
				_ = w.Flush()
				if line == "info;" {
					fmt.Printf("Type \"\\h <command>\" for more information.\n")
				}
			default:
				fmt.Println(result.Status())
			}
			i++
		}
		if i == 0 {
			continue
		}
		if i > 1 {
			fmt.Println()
		}
		if option.Timing {
			fmt.Println(elapsedTimeStr)
		}
		pager.Complete()
	}

	return nil
}

func help(cmd *cobra.Command, commandLine []string) {
	printHelp()
}

func printHelp() {
	fmt.Print("" +
		global.ClientProgram + " is the CCMS client\n" +
		"\n" +
		"Usage:  " + global.ClientProgram + " [options]\n" +
		"\n" +
		"Options:\n" +
		hostFlag(nil, nil) +
		portFlag(nil, nil) +
		noTLSFlag(nil, nil) +
		skipVerifyFlag(nil, nil) +
		versionFlag(nil, nil) +
		timingFlag(nil, nil) +
		"")
	os.Exit(0)
}

func versionFlag(cmd *cobra.Command, version *bool) string {
	if cmd != nil {
		cmd.Flags().BoolVar(version, "version", false, "")
	}
	return "" +
		"      --version               print ccc version\n"
}

func verboseFlag(cmd *cobra.Command, verbose *bool) string {
	if cmd != nil {
		cmd.Flags().BoolVarP(verbose, "verbose", "v", false, "")
	}
	return "" +
		"  -v, --verbose               enable verbose output\n"
}

func timingFlag(cmd *cobra.Command, timing *bool) string {
	if cmd != nil {
		cmd.Flags().BoolVarP(timing, "timing", "t", false, "")
	}
	return "" +
		"  -t, --timing                enable timing of commands\n"
}

func hostFlag(cmd *cobra.Command, host *string) string {
	if cmd != nil {
		cmd.Flags().StringVarP(host, "host", "h", "127.0.0.1", "")
	}
	return "" +
		"  -h, --host <h>              server host (default: 127.0.0.1)\n"
}

func portFlag(cmd *cobra.Command, port *string) string {
	if cmd != nil {
		cmd.Flags().StringVarP(port, "port", "p", global.DefaultPort, "")
	}
	return "" +
		"  -p, --port <p>              server port (default: " + global.DefaultPort + ")\n"
}

func noTLSFlag(cmd *cobra.Command, noTLS *bool) string {
	if cmd != nil {
		cmd.Flags().BoolVar(noTLS, "notls", false, "")
	}
	return "" +
		"      --notls                 disable TLS in connection to server (insecure)\n"
}

func skipVerifyFlag(cmd *cobra.Command, skipVerify *bool) string {
	if cmd != nil {
		cmd.Flags().BoolVar(skipVerify, "skipverify", false, "")
	}
	return "" +
		"      --skipverify            do not verify server certificate chain and host\n" +
		"                              name (insecure)\n"
}

func initColor() error {
	switch colorMode {
	case "always":
		eout.AlwaysColor()
	case "auto":
		eout.AutoColor()
	default:
		eout.NeverColor()
	}
	colorInitialized = true
	return nil
}

func ValueFromFile(filename string) (string, error) {
	var err error
	var f *os.File
	if f, err = os.Open(filename); err != nil {
		return "", err
	}
	var scanner = bufio.NewScanner(f)
	scanner.Split(bufio.ScanWords)
	var ok bool
	if ok = scanner.Scan(); !ok {
		if scanner.Err() != nil {
			return "", err
		}
	}
	return scanner.Text(), nil
}

func helpCommand(line string) string {
	return strings.Join(strings.Fields(line[2:]), " ")
}

var completer = readline.NewPrefixCompleter(
	readline.PcItem("create set"),
	readline.PcItem("delete from"),
	readline.PcItem("drop set"),
	readline.PcItem("insert into"),
	readline.PcItem("select * from"),
	readline.PcItem("show sets ;"),
	//readline.PcItem("show",
	//        readline.PcItem("sets",
	//                readline.PcItem(";"),
	//        ),
	//),
	readline.PcItem("\\h",
		readline.PcItem("create set"),
		readline.PcItem("delete"),
		readline.PcItem("drop set"),
		readline.PcItem("insert"),
		readline.PcItem("select"),
		readline.PcItem("show"),
	),
)
