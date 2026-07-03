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
	"github.com/indexdata/ccms/internal/crypto"
	"github.com/indexdata/ccms/internal/eout"
	"github.com/indexdata/ccms/internal/global"
	"github.com/spf13/cobra"
	"gopkg.in/ini.v1"
)

var colorMode string
var devMode bool

var colorInitialized bool

var option struct {
	Host          string
	Port          string
	User          string
	NoTLS         bool
	TLSSkipVerify bool
	Version       bool
	Timing        bool
}

type config struct {
	user     string
	password string
}

func newConfig() (*config, error) {
	configFile := filepath.Join(os.Getenv("HOME"), ".ccc_config")
	exists, err := fileExists(configFile)
	if err != nil {
		return nil, err
	}
	if !exists {
		return &config{}, nil
	}

	c, err := ini.Load(configFile)
	if err != nil {
		return nil, err
	}

	s := c.Section("default")
	return &config{
		user:     s.Key("user").String(),
		password: s.Key("password").String(),
	}, nil
}

func fileExists(file string) (bool, error) {
	_, err := os.Stat(file)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

const errorPrefix = "ERROR:"

func main() {
	colorMode = os.Getenv("CCC_COLOR")
	cccMain()
}

func cccMain() {
	eout.Init(os.Args[0])
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
	_ = userFlag(rootCmd, &option.User)
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

	conf, err := newConfig()
	if err != nil {
		return err
	}

	user := option.User
	password := ""
	if strings.TrimSpace(user) == "" {
		user = conf.user
		password = conf.password
	}
	if strings.TrimSpace(user) == "" {
		return fmt.Errorf("user name must be specified")
	}
	if strings.TrimSpace(password) == "" {
		password, err = crypto.InputPassword("Password for \""+user+"\": ", false)
		if err != nil {
			return err
		}
		if strings.TrimSpace(password) == "" {
			return fmt.Errorf("password must be specified")
		}
	}

	client := &ccms.Client{
		Host:          option.Host,
		Port:          option.Port,
		User:          user,
		Password:      password,
		NoTLS:         option.NoTLS,
		TLSSkipVerify: option.TLSSkipVerify,
	}

	//resp, err := client.Send("ping;")
	//if err != nil {
	//        errorExit(err)
	//}
	//for result := range resp.Results() {
	//        if result.Status() == "error" {
	//                //eout.Error("error: %s", result.Message())
	//                errorExit(fmt.Errorf("%s", result.Message()))
	//        }
	//        break
	//}

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
		fields := strings.Fields(line)
		if line[0] == '\\' {
			switch fields[0] {
			case "\\h":
			case "\\q":
			case "\\createuser":
			default:
				eout.Error(errorPrefix + " unknown command \"" + fields[0] + "\"")
				continue
			}
		}
		if line == "help" {
			fmt.Printf("" +
				"Type:  \\h for help with SQL commands\n" +
				"       \\q to quit\n" +
				"       \\createuser <username>\n")
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
		if strings.HasPrefix(line, "\\createuser") {
			line, err = createUser(client, fields)
			if err != nil {
				eout.Error(errorPrefix + " " + err.Error())
				continue
			}
			fields = strings.Fields(line)
		}
		l := strings.Join(fields, "")
		if l == "quit" || l == "quit;" || l == "exit" || l == "exit;" {
			break
		}
		startTime := time.Now()
		resp, err := client.Send(line)
		if err != nil {
			eout.Error(errorPrefix + " " + err.Error())
			continue
		}
		elapsedTime := time.Since(startTime).Seconds()
		elapsedTimeStr := fmt.Sprintf("[%.4f s]", elapsedTime)

		if err = pager.Setup(); err != nil {
			return err
		}
		defer pager.Complete()
		defer func() {
			if r := recover(); r != nil {
				pager.Complete()
				panic(r)
			}
		}()

		i := 0
		for result := range resp.Results() {
			if i > 0 {
				fmt.Printf("\n")
			}
			if result.Status() == "error" {
				// eout.Error(errorPrefix + " " + result.Message())
				fmt.Println(errorPrefix + " " + result.Message())
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
					// print field names
					fields := result.Fields()
					for j := range fields {
						if j != 0 {
							fmt.Fprint(w, "\t")
						}
						fmt.Fprint(w, fields[j].Name())
					}
					fmt.Fprint(w, "\n")
					// print dashes under the field names
					for j := range fields {
						if j != 0 {
							fmt.Fprint(w, "\t")
						}
						printDashes(w, len(fields[j].Name()))
					}
					fmt.Fprint(w, "\n")
				}
				// print the data
				j := 0
				for data := range result.Data() {
					values := data.Values()
					for k := range values {
						if k != 0 {
							fmt.Fprint(w, "\t")
						}
						fmt.Fprint(w, values[k])
					}
					fmt.Fprint(w, "\n")
					j++
				}
				if j == 1 {
					fmt.Fprint(w, "(1 row)\n")
				} else {
					_, _ = fmt.Fprintf(w, "(%d rows)\n", j)
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
		if i > 0 {
			if i > 1 {
				fmt.Println()
			}
			if option.Timing {
				fmt.Println(elapsedTimeStr)
			}
		}
		pager.Complete()
	}

	return nil
}

const dashes = "-------------------------------------------------------------------------------"

func printDashes(w *tabwriter.Writer, count int) {
	fmt.Fprint(w, dashes[0:min(count, len(dashes))])
}

func createUser(client *ccms.Client, fields []string) (string, error) {
	if len(fields) == 1 {
		return "", fmt.Errorf("user name not specified")
	}
	userName := fields[1]
	pw, err := crypto.InputPassword("Password for \""+userName+"\": ", true)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(pw) == "" {
		return "", fmt.Errorf("password is required")
	}
	return "create user " + userName + " with encrypted password '" + client.HashPassword(pw) + "';", nil
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
		userFlag(nil, nil) +
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
		"  -t, --timing                enable timing of requests\n"
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

func userFlag(cmd *cobra.Command, user *string) string {
	if cmd != nil {
		cmd.Flags().StringVarP(user, "username", "U", "", "")
	}
	return "" +
		"  -U, --username <u>          user name\n"
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
	readline.PcItem("\\createuser"),
	readline.PcItem("\\h",
		readline.PcItem("alter fund"),
		readline.PcItem("alter project"),
		readline.PcItem("create filter"),
		readline.PcItem("create fund"),
		readline.PcItem("create project"),
		readline.PcItem("create set"),
		readline.PcItem("create user"),
		readline.PcItem("delete"),
		readline.PcItem("drop fund"),
		readline.PcItem("drop set"),
		readline.PcItem("insert"),
		readline.PcItem("select"),
		readline.PcItem("show"),
	),
	readline.PcItem("alter fund"),
	readline.PcItem("alter project"),
	readline.PcItem("archive project"),
	readline.PcItem("create filter"),
	readline.PcItem("create fund"),
	readline.PcItem("create project"),
	readline.PcItem("create set"),
	readline.PcItem("delete from"),
	readline.PcItem("drop fund"),
	// readline.PcItem("drop project"),
	readline.PcItem("drop set"),
	readline.PcItem("insert into"),
	readline.PcItem("select",
		readline.PcItem("*"),
		readline.PcItem("count(*)"),
		readline.PcItem("version()"),
	),
	readline.PcItem("show",
		readline.PcItem("fund"),
		readline.PcItem("funds"),
		readline.PcItem("project"),
		readline.PcItem("projects",
			readline.PcItem("archived"),
		),
		readline.PcItem("sets"),
		readline.PcItem("users"),
	),
	readline.PcItem("update"),
)
