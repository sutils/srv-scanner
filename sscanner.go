package main

import (
	"fmt"
	"os"
	"time"

	"github.com/Centny/gwf/log"
	"github.com/Centny/gwf/routing"
	"github.com/Centny/gwf/tools/timer"
	"github.com/Centny/gwf/util"
	"github.com/sutils/srv-scanner/sscanner"
)

func main() {
	//load configure
	cfgfile = "conf/sscanner.conf"
	if len(os.Args) > 1 {
		cfgfile = os.Args[1]
	}
	conf := loadConf()
	conf.Print()
	//
	//initial scanner.
	sharedScanner = sscanner.NewScanner()
	sharedScanner.Warner = sscanner.NewCmdWarner(conf.Val2("warner", ""))
	sharedScanner.Start(conf.IntValV("tcp_runner", util.CPU()), conf.IntValV("udp_runner", util.CPU()))
	//
	//initial schedule
	timer.Register5(conf.Int64ValV("delay", 300000), onScanTime, false, true)
	timer.Register5(conf.Int64ValV("detect_delay", 86400000), onDetectTime, false, true)
	//
	//start web server.
	routing.HFunc("^/adm/status(\\?.*)?$", sharedScanner.StatusH)
	log.I("listen web server on %v", conf.Val2("listen", ""))
	fmt.Println(routing.ListenAndServe(conf.Val2("listen", "")))
}

var cfgfile = "conf/sscanner.conf"
var sharedScanner *sscanner.Scanner

func onScanTime(i uint64) error {
	gid := fmt.Sprintf("%v-%03d", time.Now().Format("2006-01-02"), i)
	log.I("Scanner start %v scan", gid)
	sharedScanner.Scan(gid, loadConf())
	return nil
}

func onDetectTime(i uint64) error {
	gid := fmt.Sprintf("%v-%03d", time.Now().Format("2006-01-02"), i)
	log.I("Scanner start %v detect", gid)
	sharedScanner.Detect(gid, loadConf())
	return nil
}

func loadConf() *util.Fcfg {
	conf := util.NewFcfg3()
	conf.InitWithUri(cfgfile)
	conf.InitWithData(conf.Val2("conf", ""))
	conf.SetVal("conf", "")
	return conf
}
