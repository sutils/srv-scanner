package sscanner

import (
	"fmt"
	"testing"

	"github.com/Centny/gwf/util"
)

func TestScanner(t *testing.T) {
	cfg := util.NewFcfg3()
	cfg.InitWithUri2("whitelist.conf", false)
	scanner := NewScanner()
	scanner.Warner = NewCmdWarner(cfg.Val2("warner", ""))
	scanner.Start(5, 0)
	scanner.Scan("testing", cfg)
	scanner.Detect("testing", cfg)
	fmt.Println("--->")
	scanner.Stop()
	fmt.Printf("--->\n%v\n\n", util.S2Json(scanner.recorder))
}
