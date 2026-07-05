package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	"github.com/indexdata/ccms/cmd/ccd/cat"
	"github.com/indexdata/ccms/cmd/ccd/config"
	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/cmd/ccd/harvest"
	"github.com/indexdata/ccms/cmd/ccd/log"
	"github.com/indexdata/ccms/cmd/ccd/option"
	"github.com/indexdata/ccms/cmd/ccd/osutil"
	"github.com/indexdata/ccms/cmd/ccd/parser"
	"github.com/indexdata/ccms/cmd/ccd/process"
	"github.com/indexdata/ccms/internal/eout"
	"github.com/indexdata/ccms/internal/global"
	"github.com/indexdata/ccms/internal/protocol"
)

type svr struct {
	// cat *cat.Catalog
	conf *config.Config
	opt  *option.Server
}

const internalError = "internal error: "

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

	// ensure database is initialized and compatible
	err = cat.Initialize(opt.Program, conf.DB.ConnString(), conf.Security)
	if err != nil {
		return err
	}

	s := &svr{conf: conf, opt: opt}

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
		go harvest.Harvest(s.conf.DB.ConnString())
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
	// cat.Init()
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

	ctx := context.TODO()
	conn, err := dbx.Connect(ctx, s.conf.DB.ConnString())
	if err != nil {
		sendError(w, rqid, err.Error())
		return
	}
	defer conn.Close(context.TODO())

	var req protocol.Request
	user, err := s.ReadRequest(&dbx.DB{Ctx: ctx, Queryable: conn}, w, r, &req)
	if err != nil {
		log.Info("[%d] %s - error: %v", rqid, addr, err)
		resp := ccms.NewResponse()
		resp.AddResult(cmderr(err.Error()))
		sendResponse(w, rqid, resp)
		return
	}

	log.Info("[%d] %s (%s) - %q", rqid, addr, user, req.Commands)

	defer func() {
		if r := recover(); r != nil {
			sendError(w, rqid, fmt.Sprintf("internal server error: %v", r))
			return
		}
	}()

	//fmt.Printf("### %#v --- %v\n", node, err)
	var node ast.Node
	node, err = parser.Parse(req.Commands)
	if err != nil {
		sendError(w, rqid, strings.Split(err.Error(), "\n")[0])
		return
	}
	//if node == nil {
	//        returnError(w, errors.New("syntax error"), http.StatusBadRequest)
	//        return
	//}
	//log.Info("parsed: %#v", node)

	// var noLog bool
	// if len(cmds) == 1 {
	// 	_, ok := cmds[0].(*ast.PingStmt)
	// 	if ok {
	// 		noLog = true
	// 	}
	// }
	// if !noLog {
	// 	log.Info("[%d] %s (%s) - %q", rqid, addr, user, req.Commands)
	// }

	tx, err := conn.Begin(ctx)
	if err != nil {
		sendError(w, rqid, "start transaction: "+err.Error())
		return
	}
	defer tx.Rollback(ctx)

	dbtx := &dbx.DB{Ctx: ctx, Queryable: tx}
	errorState := false
	resp := ccms.NewResponse()
	cmds := node.(*ast.ParseTree).Commands
	for i := range cmds {
		var result *ccms.Result
		switch cmd := cmds[i].(type) {
		case *ast.AlterFundStmt:
			result = alterFundStmt(s, dbtx, rqid, cmd)
		case *ast.AlterProjectStmt:
			result = alterProjectStmt(s, dbtx, rqid, cmd)
		case *ast.ArchiveProjectStmt:
			result = cmderr("\"archive project\" is no longer supported; use \"drop project\"")

		case *ast.CreateFilterStmt:
			result = createFilterStmt(s, dbtx, rqid, cmd)
		case *ast.CreateFundStmt:
			result = createFundStmt(s, dbtx, rqid, cmd)
		case *ast.CreateProjectStmt:
			result = createProjectStmt(s, dbtx, rqid, cmd)
		case *ast.CreateSetStmt:
			result = createSetStmt(s, dbtx, rqid, cmd)
		case *ast.CreateUserStmt:
			result = createUserStmt(s, dbtx, rqid, cmd)
		case *ast.DeleteStmt:
			result = deleteStmt(s, dbtx, rqid, cmd)
		case *ast.DropFundStmt:
			result = dropFundStmt(s, dbtx, rqid, cmd)
		case *ast.DropProjectStmt:
			result = dropProjectStmt(s, dbtx, rqid, cmd)
		case *ast.DropSetStmt:
			result = dropSetStmt(s, dbtx, rqid, cmd)
		case *ast.InfoStmt:
			result = infoStmt(s, dbtx, cmd)
		case *ast.InsertStmt:
			result = insertStmt(s, dbtx, rqid, cmd)
		case *ast.PingStmt:
			result = ccms.NewResult("ping")
		case *ast.SelectStmt:
			result = selectStmt(s, dbtx, rqid, cmd)
		case *ast.SelectVersionStmt:
			result = selectVersionStmt(s, dbtx, rqid, cmd)
		case *ast.ShowStmt:
			result = showStmt(s, dbtx, cmd)
		case *ast.UpdateStmt:
			result = updateStmt(s, dbtx, rqid, cmd)
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
			errorState = true
			resp.SetError(i)
			log.Info("[%d] error: %s", rqid, strings.Split(result.Message(), "\n")[0])
			break
		}
	}

	if errorState {
		if err = tx.Rollback(ctx); err != nil {
			sendError(w, rqid, "rollback: "+err.Error())
			return
		}
	} else {
		if err = tx.Commit(ctx); err != nil {
			sendError(w, rqid, "commit: "+err.Error())
			return
		}
	}

	sendResponse(w, rqid, resp)
}

func sendError(w http.ResponseWriter, rqid int64, message string) {
	log.Info("[%d] error: %s", rqid, message)
	resp := ccms.NewResponse()
	resp.AddResult(cmderr(message))
	sendResponse(w, rqid, resp)
}

func sendResponse(w http.ResponseWriter, rqid int64, resp *ccms.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := resp.Encode(w); err != nil {
		log.Info("[%d] internal error: encoding response: %v", rqid, err)
	}
}

// func cmderrint(message string, err error) *ccms.Result {
// 	return cmderr(internalError + message + ": " + err.Error())
// }

func cmderr(message string) *ccms.Result {
	result := ccms.NewResult("error")
	result.AddMessage(message)
	return result
}

// func returnError(w http.ResponseWriter, errString string, statusCode int) {
// 	HTTPError(w, errString, statusCode)
// }

func (s *svr) ReadRequest(db *dbx.DB, w http.ResponseWriter, r *http.Request, requestStruct any) (string, error) {
	user, err := s.HandleBasicAuth(db, w, r)
	if err != nil {
		return "", err
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		// HandleError(w, err, http.StatusBadRequest)
		return "", err
	}
	if err = json.Unmarshal(body, requestStruct); err != nil {
		// HandleError(w, err, http.StatusBadRequest)
		return "", err
	}
	log.Trace("request %s %v\n", r.RemoteAddr, requestStruct)
	return user, nil
}

func (s *svr) HandleBasicAuth(db *dbx.DB, w http.ResponseWriter, r *http.Request) (string, error) {
	user, password, ok := r.BasicAuth()
	if !ok {
		return "", fmt.Errorf("authentication failed")
	}
	auth, err := cat.Authenticate(s.conf.Security.SecretKey, db, user, password)
	if err != nil {
		return "", err
	}
	if !auth {
		return "", fmt.Errorf("authentication failed for user %q", user)
	}
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

// func HandleError(w http.ResponseWriter, err error, statusCode int) {
// 	log.Error("%s", err)
// 	HTTPError(w, err.Error(), statusCode)
// }

// func HTTPError(w http.ResponseWriter, errString string, code int) {
// 	w.Header().Set("Content-Type", "application/json; charset=utf-8")
// 	w.Header().Set("X-Content-Type-Options", "nosniff")
// 	w.WriteHeader(code)
// 	m := ccms.NewResponse()
// 	result := ccms.NewResult("error")
// 	result.AddMessage(errString)
// 	m.AddResult(result)
// 	if err := m.Encode(w); err != nil {
// 		// TODO error handling
// 		panic(err)
// 	}
// }

func requestString(r *http.Request) string {
	var remoteHost, remotePort string
	remoteHost, remotePort, _ = net.SplitHostPort(r.RemoteAddr)
	return fmt.Sprintf("host=%s port=%s method=%s uri=%s", remoteHost, remotePort, r.Method, r.URL)
}
