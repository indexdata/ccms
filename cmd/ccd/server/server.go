package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/indexdata/ccms"
	"github.com/indexdata/ccms/cmd/ccd/ast"
	"github.com/indexdata/ccms/cmd/ccd/catalog"
	"github.com/indexdata/ccms/cmd/ccd/config"
	"github.com/indexdata/ccms/cmd/ccd/harvest"
	"github.com/indexdata/ccms/cmd/ccd/log"
	"github.com/indexdata/ccms/cmd/ccd/option"
	"github.com/indexdata/ccms/cmd/ccd/osutil"
	"github.com/indexdata/ccms/cmd/ccd/parser"
	"github.com/indexdata/ccms/cmd/ccd/process"
	"github.com/indexdata/ccms/internal/eout"
	"github.com/indexdata/ccms/internal/global"
	"github.com/indexdata/ccms/internal/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type svr struct {
	cat  *catalog.Catalog
	dp   *pgxpool.Pool
	conf *config.Config
	opt  *option.Server
}

func Start(opt *option.Server) error {
	var err error
	// Require datadir specified
	if opt.Datadir == "" {
		return fmt.Errorf("data directory not specified")
	}
	// Require datadir exists
	var exists bool
	if exists, err = osutil.FileExists(opt.Datadir); err != nil {
		return err
	}
	if !exists {
		return fmt.Errorf("data directory not found: %s", opt.Datadir)
	}

	// Check if server is already running.
	running, pid, err := process.IsServerRunning(opt.Datadir)
	if err != nil {
		return err
	}
	if running {
		eout.Error("lock file %q already exists and server (PID %d) appears to be running", osutil.SystemPIDFileName(opt.Datadir), pid)
		return fmt.Errorf("could not start server")
	}
	// Write lock file for new server instance.
	if err = process.WritePIDFile(opt.Datadir); err != nil {
		return err
	}
	defer process.RemovePIDFile(opt.Datadir)

	if err = databaseServer(opt); err != nil {
		return fmt.Errorf("server stopped: %s", err)
	}
	return nil
}

func databaseServer(opt *option.Server) error {
	conf, err := config.New(opt.Datadir)
	if err != nil {
		return fmt.Errorf("reading configuration file: %v", err)
	}

	dp, err := newPool(context.TODO(), conf.DB.ConnString())
	if err != nil {
		return fmt.Errorf("creating database connection pool: %v", err)
	}
	defer dp.Close()

	// ensure database is initialized and compatible
	cat, err := catalog.Initialize(dp)
	if err != nil {
		return err
	}

	s := &svr{cat: cat, dp: dp, conf: conf, opt: opt}

	if err = startServer(s); err != nil {
		return fmt.Errorf("server stopped: %s", err)
	}
	return nil
}

func startServer(s *svr) error {
	var sigc = make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGTERM)
	go func() {
		<-sigc
		process.SetStop()
	}()

	go serve(s)
	if !s.opt.NoHarvest {
		go harvest.Harvest(s.dp)
	}

	for {
		if process.Stop() {
			break
		}
		time.Sleep(10 * time.Second)
	}
	log.Info("server stopped")
	return nil
}

var counter atomic.Int64

func serve(s *svr) {
	var listen string
	if s.opt.Listen == "" {
		listen = "127.0.0.1"
	} else {
		listen = s.opt.Listen
	}
	addr := net.JoinHostPort(listen, s.opt.Port)
	httpsvr := http.Server{
		Addr:    addr,
		Handler: setupHandlers(s),
	}
	log.Info("CCMS %s, listening on %s", global.Version, addr)
	if s.opt.NoTLS && s.opt.Listen != "" {
		log.Warning("disabled TLS (insecure)")
	}
	if s.opt.NoHarvest {
		log.Warning("disabled harvesting")
	}
	catalog.Init()
	var err error
	if s.opt.Listen == "" || s.opt.NoTLS {
		err = httpsvr.ListenAndServe()
	} else {
		err = httpsvr.ListenAndServeTLS(s.opt.TLSCert, s.opt.TLSKey)
	}
	if err != nil {
		m := fmt.Sprintf("error starting server: %v", err)
		log.Fatal("%s", m)
		eout.Error("%s", m)
		os.Exit(1)
	}
}

func setupHandlers(s *svr) http.Handler {
	//counter.Load(-1)
	mux := http.NewServeMux()
	mux.HandleFunc("/cmd", s.handleCommand)
	return mux
}

func (s *svr) handleCommand(w http.ResponseWriter, r *http.Request) {
	rqid := counter.Add(1)
	if r.Method == "POST" {
		// log.Info("request: %s", requestString(r))
		s.handleCommandPost(w, r, rqid)
		return
	}
	// var m = unsupportedMethod("/config", r)
	// log.Info(m)
	// http.Error(w, m, http.StatusMethodNotAllowed)
}

func (s *svr) handleCommandPost(w http.ResponseWriter, r *http.Request, rqid int64) {
	addr, _, _ := net.SplitHostPort(r.RemoteAddr)

	var req protocol.Request
	if err := ReadRequest(w, r, &req); err != nil {
		log.Info("[%d] %s - error: %v", rqid, addr, err)
		resp := ccms.NewResponse()
		resp.AddResult(cmderr(err.Error()))
		if err1 := sendResponse(w, resp); err1 != nil {
			log.Info("[%d] internal error: %v", rqid, err1)
		}
		return
	}
	log.Info("[%d] %s - %s", rqid, addr, req.Commands)

	var node ast.Node
	var cmds []ast.Node
	var err error

	node, err = parser.Parse(req.Commands)
	//fmt.Printf("### %#v --- %v\n", node, err)
	if err != nil {
		log.Info("[%d] error: %s", rqid, strings.Split(err.Error(), "\n")[0])
		returnError(w, err.Error(), http.StatusOK /* http.StatusBadRequest */)
		return
	}
	//if node == nil {
	//        returnError(w, errors.New("syntax error"), http.StatusBadRequest)
	//        return
	//}
	//log.Info("parsed: %#v", node)
	resp := ccms.NewResponse()
	var result *ccms.Result
	cmds = node.(*ast.ParseTree).Commands
	for i := range cmds {
		switch cmd := cmds[i].(type) {
		case *ast.CreateSetStmt:
			result = createSetStmt(s, rqid, cmd)
		case *ast.DeleteStmt:
			result = deleteStmt(s, rqid, cmd)
		case *ast.DropSetStmt:
			result = dropSetStmt(s, rqid, cmd)
		case *ast.InfoStmt:
			result = infoStmt(s, cmd)
		case *ast.InsertStmt:
			result = insertStmt(s, rqid, cmd)
		case *ast.PingStmt:
			result = ccms.NewResult("ping")
		case *ast.SelectStmt:
			result = selectStmt(s, rqid, cmd)
		case *ast.ShowStmt:
			result = showStmt(s, cmd)
		case nil:
			continue
		default:
			firstField := strings.Fields(req.Commands)[0]
			var b strings.Builder
			parser.WriteCarets(&b, 0, len(firstField))
			result = ccms.NewResult("error")
			result.AddMessage(fmt.Sprintf("syntax error near %s\n%s\n%s",
				parser.Near(firstField), req.Commands, b.String()))
		}
		resp.AddResult(result)
		if result.Status() == "error" {
			log.Info("[%d] error: %s", rqid, result.Message())
			break
		}
	}
	if err := sendResponse(w, resp); err != nil {
		log.Info("[%d] internal error: %v", rqid, err)
	}
}

func sendResponse(w http.ResponseWriter, resp *ccms.Response) error {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := resp.Encode(w); err != nil {
		return err
	}
	return nil
}

func cmderr(message string) *ccms.Result {
	result := ccms.NewResult("error")
	result.AddMessage(message)
	return result
}

func returnError(w http.ResponseWriter, errString string, statusCode int) {
	HTTPError(w, errString, statusCode)
}

func ReadRequest(w http.ResponseWriter, r *http.Request, requestStruct any) error {
	user, err := HandleBasicAuth(w, r)
	if err != nil {
		return err
	}
	_ = user // TODO retain user in server state

	var body []byte
	if body, err = ioutil.ReadAll(r.Body); err != nil {
		HandleError(w, err, http.StatusBadRequest)
		return err
	}
	if err = json.Unmarshal(body, requestStruct); err != nil {
		HandleError(w, err, http.StatusBadRequest)
		return err
	}
	log.Trace("request %s %v\n", r.RemoteAddr, requestStruct)
	return nil
}

func HandleBasicAuth(w http.ResponseWriter, r *http.Request) (string, error) {
	//host := osutil.AddrHost(r.RemoteAddr)
	var user, password string
	var ok bool
	user, password, ok = r.BasicAuth()
	if !ok {
		return "", fmt.Errorf("authentication failed")
		//returnError(w, e, http.StatusForbidden)
	}
	if user != "nemo" || password != "testpass" {
		return "", fmt.Errorf("authentication failed for user %q", user)
	}
	//var match bool
	//var err error
	//match, err = srv.storage.Authenticate(user, password)
	//if err != nil {
	//        var m = "Unauthorized (user '" + user + "')"
	//        log.Println(m + ": " + err.Error())
	//        //w.Header().Set("WWW-Authenticate", "Basic")
	//        http.Error(w, m, http.StatusForbidden)
	//        return user, false
	//}
	/*	if !match {
			var m = "Unauthorized (user '" + user + "'): " + "Unable to authenticate username/password"
			log.Info(m)
			//w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, m, http.StatusForbidden)
			return user, false
		}
	*/
	return user, nil
}

/*
func ReadRequest(w http.ResponseWriter, r *http.Request, requestStruct interface{}) bool {
	var body []byte
	var err error
	if body, err = ioutil.ReadAll(r.Body); err != nil {
		HandleError(w, err, http.StatusBadRequest)
		return false
	}
	//log.Info("received: %s\n", body)
	if err = json.Unmarshal(body, requestStruct); err != nil {
		HandleError(w, err, http.StatusBadRequest)
		return false
	}
	log.Trace("request %s %v\n", r.RemoteAddr, requestStruct)
	return true
}
*/

func HandleError(w http.ResponseWriter, err error, statusCode int) {
	log.Error("%s", err)
	HTTPError(w, err.Error(), statusCode)
}

func HTTPError(w http.ResponseWriter, errString string, code int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	m := ccms.NewResponse()
	result := ccms.NewResult("error")
	result.AddMessage(errString)
	m.AddResult(result)
	if err := m.Encode(w); err != nil {
		// TODO error handling
		panic(err)
	}
}

func requestString(r *http.Request) string {
	var remoteHost, remotePort string
	remoteHost, remotePort, _ = net.SplitHostPort(r.RemoteAddr)
	return fmt.Sprintf("host=%s port=%s method=%s uri=%s", remoteHost, remotePort, r.Method, r.URL)
}

func newPool(ctx context.Context, connString string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(connString)
	if err != nil {
		return nil, err
	}
	config.AfterConnect = setDatabaseParameters
	config.MaxConns = 64
	dp, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return dp, nil
}

func setDatabaseParameters(ctx context.Context, dc *pgx.Conn) error {
	q := "SET search_path = ''"
	if _, err := dc.Exec(ctx, q); err != nil {
		return err
	}
	q = "SET idle_in_transaction_session_timeout=0"
	if _, err := dc.Exec(ctx, q); err != nil {
		return err
	}
	q = "SET idle_session_timeout=0"
	_, _ = dc.Exec(ctx, q) // Temporarily allow for PostgreSQL versions < 14
	q = "SET statement_timeout=0"
	if _, err := dc.Exec(ctx, q); err != nil {
		return err
	}
	q = "SET timezone='UTC'"
	if _, err := dc.Exec(ctx, q); err != nil {
		return err
	}
	return nil
}
