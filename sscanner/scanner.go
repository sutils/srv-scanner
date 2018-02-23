package sscanner

import (
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Centny/gwf/routing"

	"github.com/Centny/gwf/log"

	"github.com/Centny/gwf/util"
)

//Warner is the interface of callback.
type Warner interface {
	//
	OnWarning(task *Task, err error) (back interface{})
}

//Task is the scan task by host/protocol
type Task struct {
	Host      string
	Protocol  string
	Ranges    [2]int
	Wait      *sync.WaitGroup
	Whitelist map[int]string
	New       map[int]string
	Missing   map[int]string
	nmap      *NMAP
}

//Scanner is tool for scanning hosts and alert when port is not in whitelist.
type Scanner struct {
	tcpTasks chan *Task
	udpTasks chan *Task
	running  bool
	lck      sync.RWMutex

	TCP    bool
	UDP    bool
	Warner Warner

	//
	recorder    util.Map
	recorderLck sync.RWMutex
}

//NewScanner is the creator of Scanner.
func NewScanner(tcp, udp bool) *Scanner {
	return &Scanner{
		tcpTasks:    make(chan *Task, 1000),
		udpTasks:    make(chan *Task, 1000),
		lck:         sync.RWMutex{},
		TCP:         tcp,
		UDP:         udp,
		Warner:      &NoneWarner{},
		recorder:    util.Map{},
		recorderLck: sync.RWMutex{},
	}
}

//Scan will send the scan task to runner pool by configure.
func (s *Scanner) Scan(cfg *util.Fcfg) {
	s.lck.Lock()
	defer s.lck.Unlock()
	hosts := strings.Split(cfg.Val2("hosts", ""), ",")
	var err error
	for _, host := range hosts {
		wlConf := cfg.Val2(host, "")
		wlLines := strings.Split(wlConf, "\n")
		tcpWL := map[int]string{}
		udpWL := map[int]string{}
		ranges := [2]int{0, 65535}
		for _, wlLine := range wlLines {
			if strings.HasPrefix(wlLine, "ranges=") {
				wlLine = strings.TrimPrefix(strings.TrimSpace(strings.Split(wlLine, "#")[0]), "ranges=")
				parts := strings.SplitN(wlLine, "-", 2)
				ranges[0], err = strconv.Atoi(parts[0])
				if err != nil {
					log.E("Scanner read ranges line on %v fail with %v, the line is:%v", host, err, wlLine)
					continue
				}
				ranges[1], err = strconv.Atoi(parts[1])
				if err != nil {
					log.E("Scanner read ranges line on %v fail with %v, the line is:%v", host, err, wlLine)
					continue
				}
				continue
			}
			parts := regexp.MustCompile("[/\\s#]+").Split(wlLine, -1)
			if len(parts) < 3 {
				log.E("Scanner read whitelist on %v and one invalid line is found:%v", host, wlLine)
				continue
			}
			port, err := strconv.Atoi(parts[0])
			if err != nil {
				log.E("Scanner read whitelist on %v and one invalid line is found:%v", host, wlLine)
				continue
			}
			if parts[1] == "tcp" {
				tcpWL[port] = parts[2]
			} else {
				udpWL[port] = parts[2]
			}
		}
		if s.TCP {
			task := &Task{
				Host:      host,
				Protocol:  "tcp",
				Ranges:    ranges,
				Whitelist: tcpWL,
				New:       map[int]string{},
				Missing:   map[int]string{},
			}
			s.tcpTasks <- task
		}
		if s.UDP {
			task := &Task{
				Host:      host,
				Protocol:  "udp",
				Ranges:    ranges,
				Whitelist: udpWL,
				New:       map[int]string{},
				Missing:   map[int]string{},
			}
			s.udpTasks <- task
		}
	}
}

func (s *Scanner) runner(name string, runid int, tasks chan *Task) {
	log.D("Scanner(%v/%v) is started", name, runid)
	for s.running {
		task := <-tasks
		last := util.Map{}
		task.nmap = NewNMAP(task.Host, task.Protocol)
		task.nmap.Ranges = task.Ranges
		ports, err := task.nmap.Scan()
		if err != nil {
			log.E("Scanner(%v) scan %v/%v fail with %v", runid, task.Host, task.Protocol, err)
			last["error"] = err.Error()
			last["warn"] = s.Warner.OnWarning(task, err)
			last["last"] = util.Now()
			s.recorderLck.Lock()
			s.recorder[fmt.Sprintf("%v/%v", task.Host, task.Protocol)] = last
			s.recorderLck.Unlock()
			continue
		}
		for port, status := range ports {
			if task.Whitelist[port] != status {
				task.New[port] = status
			}
		}
		for port, status := range task.Whitelist {
			if _, ok := ports[port]; !ok {
				task.Missing[port] = status
			}
		}
		log.D("Scanner(%v) scan %v/%v done with \n new:%v\n missing:%v", runid,
			task.Host, task.Protocol, util.S2Json(task.New), util.S2Json(task.Missing))
		var warn interface{} = "NONE"
		if len(task.New) != 0 || len(task.Missing) != 0 {
			warn = s.Warner.OnWarning(task, nil)
		}
		//
		newRecord := util.Map{}
		for port, status := range task.New {
			newRecord[fmt.Sprintf("%v", port)] = status
		}
		missingRecord := util.Map{}
		for port, status := range task.Missing {
			missingRecord[fmt.Sprintf("%v", port)] = status
		}
		last["error"] = nil
		last["warn"] = warn
		last["new"] = newRecord
		last["missing"] = missingRecord
		last["last"] = util.Now()
		s.recorderLck.Lock()
		s.recorder[fmt.Sprintf("%v/%v", task.Host, task.Protocol)] = last
		s.recorderLck.Unlock()

	}
	log.D("Scanner(%v/%v) is stopped", name, runid)
}

//Start will start the scan task runner.
func (s *Scanner) Start(tcp, udp int) {
	s.running = true
	runid := 0
	for i := 0; i < tcp; i++ {
		go s.runner("tcp", runid, s.tcpTasks)
		runid++
	}
	for i := 0; i < udp; i++ {
		go s.runner("udp", runid, s.udpTasks)
		runid++
	}
}

//StatusH is the web handler to show the current status.
func (s *Scanner) StatusH(hs *routing.HTTPSession) routing.HResult {
	s.recorderLck.RLock()
	defer s.recorderLck.RUnlock()
	return hs.JRes(s.recorder)
}

//NoneWarner is default warner to do nothing.
type NoneWarner struct {
}

//OnWarning is the callback on one taks is completed.
func (n *NoneWarner) OnWarning(task *Task, err error) (back interface{}) {
	return
}

//CmdWarner is the warner by sending task result to command
type CmdWarner struct {
	Cmds string //the command string
}

//NewCmdWarner is the creator of CmdWarner by command string.
func NewCmdWarner(cmds string) *CmdWarner {
	return &CmdWarner{
		Cmds: cmds,
	}
}

//OnWarning is the callback on one taks is completed.
func (c CmdWarner) OnWarning(task *Task, err error) (back interface{}) {
	cmd := exec.Command("bash", "-c", c.Cmds)
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_ERROR=%v", err))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_HOST=%v", task.Host))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_PROTO=%v", task.Protocol))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_NEW=%v", util.S2Json(task.New)))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_NEW_SIZE=%v", len(task.New)))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_MISSING=%v", util.S2Json(task.Missing)))
	cmd.Env = append(cmd.Env, fmt.Sprintf("SS_MISSING_SIZE=%v", len(task.Missing)))
	bys, xerr := cmd.CombinedOutput()
	if xerr != nil {
		log.E("CmdWarnner run fail with %v:%v", xerr, string(bys))
	} else {
		log.D("CmdWarnner run warning message done with %v", string(bys))
	}
	back = xerr
	return
}
