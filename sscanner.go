package main

import (
	"fmt"
	"os"

	"github.com/Centny/gwf/log"
	"github.com/Centny/gwf/routing"
	"github.com/Centny/gwf/tools/timer"
	"github.com/Centny/gwf/util"
	"github.com/sutils/srv-scanner/sscanner"
)

func main() {
	//load configure
	cfgfile := "conf/sscanner.conf"
	if len(os.Args) > 1 {
		cfgfile = os.Args[1]
	}
	sharedConf.InitWithUri(cfgfile)
	sharedConf.InitWithData(sharedConf.Val2("conf", ""))
	sharedConf.SetVal("conf", "")
	sharedConf.Print()
	//
	//initial scanner.
	sharedScanner = sscanner.NewScanner(sharedConf.IntValV("enable_tcp", 0) > 0, sharedConf.IntValV("enable_udp", 0) > 0)
	sharedScanner.Warner = sscanner.NewCmdWarner(sharedConf.Val2("warner", ""))
	sharedScanner.Start(util.CPU(), util.CPU())
	//
	//initial schedule
	timer.Register5(sharedConf.Int64ValV("delay", 300000), onTime, false, true)
	//
	//start web server.
	routing.HFunc("^/adm/status(\\?.*)?$", sharedScanner.StatusH)
	log.I("listen web server on %v", sharedConf.Val2("listen", ""))
	fmt.Println(routing.ListenAndServe(sharedConf.Val2("listen", "")))
}

var sharedConf = util.NewFcfg3()
var sharedScanner *sscanner.Scanner

func onTime(i uint64) error {
	log.I("Scanner start %v scan", i)
	sharedScanner.Scan(sharedConf)
	return nil
}
